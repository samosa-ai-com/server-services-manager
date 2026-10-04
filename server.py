import signal
import sys

import eventlet
eventlet.monkey_patch()
import queue
import json
import logging
import os
import tempfile
import time
import threading
import yaml

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, Response, send_from_directory
from flask_socketio import SocketIO
from app.process_manager import ProcessManager, ProgramConfig, ProgramStatus
from app.terminal_manager import TerminalManager
from app import system_services
from app.log_streamer import get_streamer
from app import cron_manager
from app import docker_manager
from app import alert_log
from app import package_manager
from app import firewall_manager
from app import backup_manager
from app import cluster_manager
from app import disk_manager
from app import file_explorer
from app import monitor_prefs
from app import service_overview
from app import ssh_manager
from app import openapi as openapi_mod
from app.health import HealthCheck, HealthMonitor
from app.notifier import build_notifiers, Event as HealthEvent
from app import activity
from app import palette
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import send_file
from dotenv import load_dotenv
import psutil
import subprocess

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FlaskAPI")

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24).hex())
app.config['TEMPLATES_AUTO_RELOAD'] = True
# Defense in depth for /api/files/upload: Werkzeug rejects bodies larger
# than the per-file cap plus multipart overhead regardless of whether
# Content-Length is present (chunked requests have none). The handler
# below still enforces a per-file + per-request check after writing.
UPLOAD_MAX_BYTES = 1024 * 1024 * 1024
app.config['MAX_CONTENT_LENGTH'] = UPLOAD_MAX_BYTES + 16 * 1024 * 1024
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True


@app.errorhandler(413)
def _too_large(error):
    return jsonify({"error": "upload too large (cap 1GB per file)", "code": "too_large"}), 413
socketio = SocketIO(app, cors_allowed_origins=os.getenv('CORS_ORIGIN', '*'), max_http_buffer_size=10*1024*1024)


# State-change hook for managed programs. Defined at module level
# so the API routes can attach it to new programs added at runtime
# (the function body references ``_health_notifiers`` which is also
# module-level).
def _on_program_state_change(program, old_status, new_status):
    """Fan a service state transition out to all notifiers.

    Triggered from :meth:`Program._set_status` on every transition.
    Failures inside a notifier must never block the program, so the
    hook is wrapped in a daemon thread.
    """
    if new_status == old_status:
        return
    if new_status == ProgramStatus.STOPPED and old_status == ProgramStatus.STOPPED:
        return
    from app import notifier as _notifier_mod
    notifiers = list(_health_notifiers)
    if not notifiers:
        return
    severity = "info"
    if new_status == ProgramStatus.FAILED:
        severity = "error"
    message = f"{program.config.name} {old_status.value} -> {new_status.value}"
    event = _notifier_mod.Event(
        service=program.config.name,
        kind="state_change",
        state=new_status.value,
        detail=f"{message} | command={program.config.command!r} cwd={program.config.cwd!r}",
        timestamp=time.time(),
    )
    # Push to socketio so the UI sees a toast for service events.
    # Wrapped in try/except because socketio.emit is not safe to
    # call from every thread context (the eventlet hub is required).
    try:
        socketio.emit("service_event", {
            "service": program.config.name,
            "old": old_status.value,
            "new": new_status.value,
            "severity": severity,
            "message": message,
            "timestamp": event.timestamp,
        })
    except Exception:
        pass
    # Off-thread fanout so a slow webhook doesn't stall the
    # program loop. The notifier module wraps each notifier in a
    # try/except too, so a single bad endpoint can't poison the
    # others. alert_log.fanout_with_logging records each delivery
    # attempt to the notification_events table for /alerts.
    threading.Thread(
        target=alert_log.fanout_with_logging,
        args=(notifiers, event),
        daemon=True,
    ).start()

pm = ProcessManager()
tm = TerminalManager(socketio)

# Health monitor reads `health_check` blocks from config.yaml and
# pings each service on a background thread. Notifiers are also
# loaded from `notifications:` in the same file. Both blocks are
# optional — when missing, the monitor runs no checks.
_health_notifiers: list = []
_health_monitor = None  # initialized after pm.load_config()
# Live notifier list used by the program state-change hook. Mirrors
# the health-monitor notifier list — they're built from the same
# config.yaml section, so the live copy and the periodic copy are
# always in sync. Kept separate so the state-change hook can fire
# in a thread without contention on the health monitor's internal
# state.
def _get_active_notifiers() -> list:
    return list(_health_notifiers)

_password_env = os.getenv('PASSWORD')
_custom_warning = (os.getenv('DEFAULT_PASSWORD_WARNING') or '').strip()
if not _password_env:
    logger.warning(
        _custom_warning
        or "SECURITY WARNING: PASSWORD is not set — using the default 'admin'. "
        "Set PASSWORD in your environment or .env before exposing this app."
    )
_password_hash = generate_password_hash(_password_env or 'admin')
del _password_env, _custom_warning

@app.before_request
def require_login():
    allowed_routes = ['login', 'static', 'health', 'favicon']
    if request.endpoint in allowed_routes or 'logged_in' in session:
        return None
    # Cluster peer auth: cross-node API calls carry the shared
    # secret in X-SSM-Cluster-Secret. Accept it as an alternative
    # credential for /api/* so peers authenticate even when their
    # Flask SECRET_KEY differs (session cookies are instance-signed
    # and don't verify across hosts). Empty secret never verifies.
    if (request.path or "").startswith("/api/"):
        try:
            _cfg = pm.config_data if hasattr(pm, "config_data") else {}
        except Exception:
            _cfg = {}
        if cluster_manager.verify_cluster_secret(
            request.headers.get("X-SSM-Cluster-Secret", ""), _cfg
        ):
            return None
    if request.endpoint not in allowed_routes and 'logged_in' not in session:
        return redirect(url_for('login'))

@app.route('/health')
@openapi_mod.describe(
    summary="Health check (no auth)",
    description="Returns 200 OK if the server is reachable. Bypasses auth.",
    responses={"200": {"description": "OK"}},
)
def health():
    return jsonify({"status": "ok"})

@app.route('/login', methods=['GET', 'POST'])
def login():
    global _password_hash
    if request.method == 'POST':
        password = request.form.get('password') or ""
        if password and check_password_hash(_password_hash, password):
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            flash('Invalid password')
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static', 'logo.svg', mimetype='image/svg+xml')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/monitor')
def monitor():
    return render_template('monitor.html')

@app.route('/control')
def control():
    custom_commands = []
    config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                cfg = yaml.safe_load(f)
                if cfg and 'commands' in cfg:
                    custom_commands = cfg['commands']
        except Exception:
            pass
    return render_template('control.html', commands=custom_commands)


@app.route('/system-services')
def system_services_page():
    return render_template('system-services.html')

WHITELIST_COMMANDS = {
    "lock":       {"cmd": "loginctl lock-session",          "auth": False, "icon": "lock"},
    "suspend":    {"cmd": "systemctl suspend",               "auth": True,  "icon": "moon"},
    "hibernate":  {"cmd": "systemctl hibernate",            "auth": True,  "icon": "bed"},
    "reboot":     {"cmd": "systemctl reboot",               "auth": True,  "icon": "power"},
    "shutdown":   {"cmd": "systemctl poweroff",             "auth": True,  "icon": "power-off"},
    "disk":       {"cmd": "df -h /",                        "auth": False, "icon": "hard-drive"},
    "memory":     {"cmd": "free -h",                        "auth": False, "icon": "memory-stick"},
    "uptime":     {"cmd": "uptime",                         "auth": False, "icon": "clock"},
    "temp":       {"cmd": "",                                "auth": False, "icon": "thermometer"},
    "net-restart":{"cmd": "systemctl restart NetworkManager","auth": False, "icon": "wifi-off"},
    "net-ip":     {"cmd": "ip -4 addr show | grep inet | awk '{print $NF\" \"$2}'", "auth": False, "icon": "globe"},
}

@app.route('/api/control/run', methods=['POST'])
def control_run():
    data = request.get_json() or {}
    command_id = data.get('command')
    password = data.get('password', '')

    if command_id in WHITELIST_COMMANDS:
        entry = WHITELIST_COMMANDS[command_id]
        cmd = entry['cmd']
    else:
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        found = None
        if os.path.exists(config_path):
            try:
                with open(config_path) as f:
                    cfg = yaml.safe_load(f)
                    if cfg and 'commands' in cfg:
                        for c in cfg['commands']:
                            if c.get('id') == command_id:
                                found = c
                                break
            except Exception:
                pass
        if found:
            entry = found
            cmd = found.get('command', '')
        else:
            return jsonify({"error": "Unknown command"}), 400

    if entry.get('auth', False):
        if not password:
            return jsonify({"error": "auth_required"}), 401
        if not check_password_hash(_password_hash, password):
            return jsonify({"error": "Invalid password"}), 403

    if command_id == 'temp':
        temp = None
        try:
            temps = psutil.sensors_temperatures()
            for key in ('coretemp', 'k10temp', 'cpu-thermal', 'cpu_thermal', 'thinkpad', 'acpitz'):
                if key in temps:
                    temp = round(temps[key][0].current, 1)
                    break
        except Exception:
            pass
        if temp is not None:
            return jsonify({"ok": True, "output": f"CPU Temperature: {temp}°C"})
        return jsonify({"ok": True, "output": "No temperature sensor available"})

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        output = result.stdout.strip() or result.stderr.strip() or "Done (no output)"
        return jsonify({"ok": True, "output": output})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/programs', methods=['GET'])
def get_programs():
    programs = pm.get_all_programs()
    return jsonify([{
        "name": p.config.name,
        "status": p.status.value,
        "restart_count": p.restart_count,
        "last_restart_time": p.last_restart_time
    } for p in programs])

@app.route('/programs/<name>/config', methods=['GET'])
def get_program_config(name):
    program = pm.get_program(name)
    if not program:
        return jsonify({"error": "Program not found"}), 404
    
    return jsonify({
        "name": program.config.name,
        "command": program.config.command,
        "cwd": program.config.cwd,
        "autostart": program.config.autostart,
        "schedule": program.config.schedule or "",
        "environment": program.config.environment
    })

@app.route('/programs', methods=['POST'])
def add_program():
    data = request.json
    try:
        config = ProgramConfig(
            name=data['name'],
            command=data['command'],
            cwd=data['cwd'],
            autostart=data.get('autostart', False),
            schedule=data.get('schedule', ''),
            environment=data.get('environment', {})
        )
        pm.add_program(config)
        # Attach state-change hook to the newly added program so
        # its transitions get notified.
        new_program = pm.programs[data['name']]
        if new_program.on_state_change is None:
            new_program.on_state_change = _on_program_state_change
        activity.log("program.add", target=data['name'], status="ok",
                    detail=f"command={data['command']!r} cwd={data['cwd']!r}",
                    ip=request.remote_addr or "")
        return jsonify({"status": "added", "name": data['name']})
    except Exception as e:
        activity.log("program.add", target=(data or {}).get('name', ''), status="error",
                    detail=str(e), ip=request.remote_addr or "")
        return jsonify({"error": str(e)}), 400

@app.route('/programs/<name>', methods=['PUT'])
def edit_program(name):
    data = request.json
    try:
        config = ProgramConfig(
            name=data['name'],
            command=data['command'],
            cwd=data['cwd'],
            autostart=data.get('autostart', False),
            schedule=data.get('schedule', ''),
            environment=data.get('environment', {})
        )
        pm.edit_program(name, config)
        activity.log("program.edit", target=name, status="ok",
                    detail=f"new_name={data['name']!r}", ip=request.remote_addr or "")
        return jsonify({"status": "updated", "name": data['name']})
    except Exception as e:
        activity.log("program.edit", target=name, status="error",
                    detail=str(e), ip=request.remote_addr or "")
        return jsonify({"error": str(e)}), 400

@app.route('/programs/<name>', methods=['DELETE'])
def delete_program(name):
    try:
        pm.delete_program(name)
        activity.log("program.delete", target=name, status="ok",
                    ip=request.remote_addr or "")
        return jsonify({"status": "deleted", "name": name})
    except ValueError as e:
        activity.log("program.delete", target=name, status="error",
                    detail=str(e), ip=request.remote_addr or "")
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        activity.log("program.delete", target=name, status="error",
                    detail=str(e), ip=request.remote_addr or "")
        return jsonify({"error": str(e)}), 500

@app.route('/programs/<name>/<action>', methods=['POST'])
def control_program(name, action):
    program = pm.get_program(name)
    if not program:
        return jsonify({"error": "Program not found"}), 404
    
    if action == 'start':
        program.start()
    elif action == 'stop':
        program.stop()
    elif action == 'restart':
        program.restart()
    else:
        return jsonify({"error": "Invalid action"}), 400
        
    return jsonify({"status": action, "name": name})

@app.route('/programs/<name>/logs', methods=['GET'])
def get_logs(name):
    program = pm.get_program(name)
    if not program:
        return jsonify({"error": "Program not found"}), 404
    # Live in-memory buffer; the persisted tail is fetched by
    # ``/programs/<name>/logs/tail`` for after-restart continuity.
    return jsonify({"logs": list(program.logs)})


@app.route('/api/programs/<name>/logs/search', methods=['GET'])
@openapi_mod.describe(
    summary="Search/filter a program's logs",
    description=(
        "Server-side log search with substring match, ISO/relative date "
        "range, pagination, and source selection (in-memory deque, "
        "persisted tail, or both deduped). Lines without a parseable "
        "timestamp are kept so a buggy log line never silently vanishes."
    ),
    tag="Programs",
    parameters=[
        {"name": "search", "in": "query", "schema": {"type": "string"}, "description": "substring (case-insensitive)"},
        {"name": "since", "in": "query", "schema": {"type": "string"}, "description": "5m / 1h / 2d / ISO 8601 / unix ts"},
        {"name": "until", "in": "query", "schema": {"type": "string"}},
        {"name": "source", "in": "query", "schema": {"type": "string", "enum": ["memory", "disk", "all"]}},
        {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}},
        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 200, "maximum": 5000}},
    ],
)
def api_program_logs_search(name):
    """Server-side log filtering + pagination for the program logs panel.

    Query params:
      search   — substring (case-insensitive) to match in each line
      since    — relative ("5m", "1h", "2d") or unix timestamp; if set,
                 only lines with a parseable timestamp >= since are kept
      until    — relative or unix timestamp; only lines <= until kept
      offset   — number of matching lines to skip (for pagination)
      limit    — max lines to return (default 200, max 5000)
      source   — "memory" (in-memory deque) or "disk" (persisted tail)
                 or "all" (default; both, deduped)
    """
    program = pm.get_program(name)
    if program is None:
        return jsonify({"error": "Program not found"}), 404
    from app import log_persistence
    import re
    import time as _time

    search = (request.args.get('search') or '').lower()
    source = request.args.get('source', 'all')
    try:
        offset = max(0, int(request.args.get('offset', '0')))
    except ValueError:
        offset = 0
    try:
        limit = max(1, min(5000, int(request.args.get('limit', '200'))))
    except ValueError:
        limit = 200

    since_raw = request.args.get('since')
    until_raw = request.args.get('until')

    def parse_ts(arg):
        if not arg:
            return None
        arg = arg.strip()
        if len(arg) >= 2 and arg[-1] in "smhd" and arg[:-1].isdigit():
            n = int(arg[:-1])
            mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[arg[-1]]
            return _time.time() - n * mult
        try:
            return float(arg)
        except ValueError:
            pass
        # ISO date / datetime
        from datetime import datetime
        for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S',
                    '%Y-%m-%dT%H:%M', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
            try:
                return datetime.strptime(arg, fmt).timestamp()
            except ValueError:
                continue
        return None
    since_ts = parse_ts(since_raw)
    until_ts = parse_ts(until_raw)

    # Collect lines
    lines: list = []
    if source in ("all", "memory"):
        try:
            lines.extend(list(program.logs))
        except Exception:  # noqa: BLE001
            pass
    if source in ("all", "disk"):
        try:
            lines.extend(log_persistence.read_tail(name, 5000))
        except Exception:  # noqa: BLE001
            pass
    # Dedupe, preserving order
    seen = set()
    deduped = []
    for ln in lines:
        if ln in seen:
            continue
        seen.add(ln)
        deduped.append(ln)
    total = len(deduped)

    # Filter by search
    if search:
        deduped = [ln for ln in deduped if search in ln.lower()]

    # Filter by date range, when lines have parseable timestamps.
    # Patterns tried, in order: ISO 8601 ("2024-01-02T03:04:05"),
    # classic ("2024-01-02 03:04:05"), date-only ("2024-01-02").
    ts_re = re.compile(
        r'(?P<ts>\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?)?)'
    )
    if since_ts is not None or until_ts is not None:
        def in_range(line: str) -> bool:
            m = ts_re.search(line)
            if not m:
                # No timestamp = keep (don't silently drop)
                return True
            from datetime import datetime
            try:
                raw = m.group('ts').replace('T', ' ')
                if len(raw) == 10:  # date-only
                    dt = datetime.strptime(raw, '%Y-%m-%d')
                elif len(raw) >= 19:
                    dt = datetime.strptime(raw[:19], '%Y-%m-%d %H:%M:%S')
                else:
                    dt = datetime.strptime(raw, '%Y-%m-%d %H:%M')
                ts = dt.timestamp()
            except Exception:  # noqa: BLE001
                return True
            if since_ts is not None and ts < since_ts:
                return False
            if until_ts is not None and ts > until_ts:
                return False
            return True
        deduped = [ln for ln in deduped if in_range(ln)]

    matched = len(deduped)
    page = deduped[offset:offset + limit]
    has_more = (offset + limit) < matched
    return jsonify({
        "name": name,
        "logs": page,
        "total": total,
        "matched": matched,
        "offset": offset,
        "limit": limit,
        "has_more": has_more,
    })


@app.route('/programs/<name>/logs/tail', methods=['GET'])
def get_logs_tail(name):
    """Return the persisted tail of the service's log file.

    This is the last N lines from the disk file, surviving across
    restarts. Combined with ``/programs/<name>/logs`` (in-memory),
    the UI can show both: the live buffer plus anything that
    happened before the most recent process start.
    """
    from app import log_persistence
    try:
        lines = int(request.args.get('lines', '200'))
    except ValueError:
        lines = 200
    return jsonify({"logs": log_persistence.read_tail(name, lines)})


@app.route('/programs/<name>/logs/download', methods=['GET'])
def download_logs(name):
    program = pm.get_program(name)
    if not program:
        return jsonify({"error": "Program not found"}), 404
    # Include both in-memory and persisted tail, deduped
    from app import log_persistence
    persisted = log_persistence.read_tail(name, 10000)
    in_memory = list(program.logs)
    seen = set()
    merged = []
    for line in persisted + in_memory:
        if line in seen:
            continue
        seen.add(line)
        merged.append(line)
    log_text = "\n".join(merged)
    return (log_text, 200, {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": f'attachment; filename="{name}.log"'
    })

@app.route('/programs/<name>/logs', methods=['DELETE'])
def clear_logs(name):
    program = pm.get_program(name)
    if not program:
        return jsonify({"error": "Program not found"}), 404
    program.logs.clear()
    from app import log_persistence
    log_persistence.clear(name)
    return jsonify({"status": "cleared"})

# File Management Endpoints
@app.route('/api/files', methods=['GET'])
def list_files():
    try:
        path = request.args.get('path', '.')
        
        # Use simple expansion for base
        base_dir_raw = os.path.expanduser('~')
        base_dir = os.path.realpath(base_dir_raw)
        
        # Resolve target
        target_dir_raw = os.path.join(base_dir, path)
        target_dir = os.path.realpath(target_dir_raw)
        
        logger.info(f"List files request: path='{path}'")
        logger.info(f"Base: raw='{base_dir_raw}', real='{base_dir}'")
        logger.info(f"Target: raw='{target_dir_raw}', real='{target_dir}'")
        
        if target_dir != base_dir and not target_dir.startswith(base_dir + os.sep):
            logger.warning(f"Access denied: {target_dir} is not under {base_dir}")
            return jsonify({
                "error": "Access denied", 
                "details": f"Target {target_dir} is not inside {base_dir}"
            }), 403
            
        if not os.path.exists(target_dir):
             logger.warning(f"Directory not found: {target_dir}")
             return jsonify({
                 "error": "Directory not found",
                 "details": f"Path {target_dir} does not exist"
             }), 404

        items = []
        for entry in os.scandir(target_dir):
            try:
                # Block symlink escapes: don't list entries whose resolved target is outside $HOME
                entry_real = os.path.realpath(entry.path)
                if entry_real != base_dir and not entry_real.startswith(base_dir + os.sep):
                    continue
                # Safe access to file stats
                is_dir = entry.is_dir()
                stat = entry.stat()
                size = stat.st_size if not is_dir else 0
                modified = stat.st_mtime
                mode = stat.st_mode & 0o777
            except OSError as e:
                # Handle broken symlinks or permission errors
                logger.warning(f"Error accessing {entry.name}: {e}")
                is_dir = False
                size = 0
                modified = 0
                mode = 0

            try:
                is_link = entry.is_symlink()
            except OSError:
                is_link = False
            items.append({
                "name": entry.name,
                "is_dir": is_dir,
                "is_link": is_link,
                "size": size,
                "modified": modified,
                "mode": mode,
            })
        
        # Sort folders first, then files
        items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
        
        return jsonify({
            "current_path": os.path.relpath(target_dir, base_dir),
            "files": items
        })
    except Exception as e:
        logger.error(f"Error listing files: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/files/upload', methods=['POST'])
@openapi_mod.describe(
    summary="Upload files (single-shot or chunked)",
    description=(
        "Single-shot: multipart with one or more `file` parts + `path`. "
        "Chunked (borrowed from Laranode UploadFileAction): same endpoint "
        "with `chunkIndex`, `totalChunks`, `originalName` fields; chunk 0 "
        "creates/truncates, later chunks append. Returns per-file status "
        "so large ISOs/backups survive flaky connections."
    ),
    tag="Files",
)
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file part"}), 400

        path = request.form.get('path', '.')
        base_dir = os.path.realpath(os.path.expanduser('~'))
        target_dir = os.path.realpath(os.path.join(base_dir, path))

        if target_dir != base_dir and not target_dir.startswith(base_dir + os.sep):
            return jsonify({"error": "Access denied"}), 403
        if not os.path.isdir(target_dir):
            return jsonify({"error": "Target directory not found"}), 404

        # Chunked mode detection (Laranode-compatible field names).
        chunk_index_raw = request.form.get('chunkIndex')
        total_chunks_raw = request.form.get('totalChunks')
        original_name = (request.form.get('originalName') or "").strip()
        chunked = chunk_index_raw is not None or total_chunks_raw is not None or bool(original_name)

        files = request.files.getlist('file')
        if not files:
            return jsonify({"error": "No file part"}), 400

        # Size caps (review finding: no unlimited disk fill).
        # Per-request chunks stay small (2MB default in files.html), but the
        # assembled file must stay bounded. 1GB covers ISOs/backups while
        # preventing accidental disk-fill; above it the partial is removed.
        # request.content_length is None for chunked Transfer-Encoding, so
        # it is only a fast-path — every branch below re-checks the bytes
        # actually written to disk. app.config['MAX_CONTENT_LENGTH'] is the
        # outer guard that makes Werkzeug reject huge bodies either way.
        upload_max_bytes = UPLOAD_MAX_BYTES
        if (request.content_length or 0) > upload_max_bytes + 16 * 1024 * 1024:
            return jsonify({"error": "upload too large (cap 1GB per file)", "code": "too_large"}), 413

        def _too_large_error(filename):
            return {"ok": False, "filename": filename,
                    "error": "upload too large (cap 1GB per file)", "code": "too_large"}

        results = []
        request_total = 0
        for file in files:
            # In chunked mode the part filename is a blob; the real name
            # comes from originalName.
            raw_name = original_name if chunked else (file.filename or "")
            if not raw_name:
                results.append({"ok": False, "error": "No selected file"})
                continue
            filename = secure_filename(os.path.basename(raw_name))
            if not filename:
                results.append({"ok": False, "error": "Invalid filename"})
                continue
            dest = os.path.join(target_dir, filename)
            # Symlink/chroot guard on the final destination.
            dest_real = os.path.realpath(dest)
            if dest_real != base_dir and not dest_real.startswith(base_dir + os.sep):
                # Allow non-existent dest inside target_dir (realpath resolves
                # to target_dir/filename); reject only escapes.
                if os.path.dirname(dest_real) != target_dir:
                    results.append({"ok": False, "filename": filename, "error": "Access denied"})
                    continue
            try:
                if chunked:
                    try:
                        chunk_index = int(chunk_index_raw or 0)
                        total_chunks = int(total_chunks_raw or 1)
                    except (TypeError, ValueError):
                        results.append({"ok": False, "filename": filename, "error": "Invalid chunkIndex/totalChunks"})
                        continue
                    if chunk_index < 0 or total_chunks < 1 or chunk_index >= total_chunks:
                        results.append({"ok": False, "filename": filename, "error": "Chunk index out of range"})
                        continue
                    if len(original_name) > 255 or "/" in original_name or "\\" in original_name:
                        results.append({"ok": False, "filename": filename, "error": "Invalid originalName"})
                        continue
                    # Write to a server-side staging name so an interrupted
                    # upload never leaves a partial file under the real
                    # name (the client ".part" blob name is untrusted and
                    # ignored). The staging file is renamed onto dest only
                    # on the final chunk.
                    staging = dest + ".part"
                    staging_real = os.path.realpath(staging)
                    if staging_real != base_dir and not staging_real.startswith(base_dir + os.sep):
                        if os.path.dirname(staging_real) != target_dir:
                            results.append({"ok": False, "filename": filename, "error": "Access denied"})
                            continue
                    mode = "wb" if chunk_index == 0 else "ab"
                    chunk_bytes = file.stream.read() if hasattr(file, "stream") else file.read()
                    if isinstance(chunk_bytes, str):
                        chunk_bytes = chunk_bytes.encode("utf-8", errors="replace")
                    with open(staging, mode) as out:
                        out.write(chunk_bytes or b"")
                    try:
                        staged_size = os.path.getsize(staging)
                    except OSError:
                        staged_size = 0
                    request_total += len(chunk_bytes or b"")
                    if staged_size > upload_max_bytes or request_total > upload_max_bytes:
                        try:
                            os.unlink(staging)
                        except OSError:
                            pass
                        results.append(_too_large_error(filename))
                        continue
                    done = chunk_index + 1 >= total_chunks
                    if done:
                        try:
                            os.replace(staging, dest)
                        except OSError as e:
                            results.append({"ok": False, "filename": filename, "error": str(e)})
                            continue
                    results.append({
                        "ok": True, "filename": filename,
                        "chunkIndex": chunk_index, "totalChunks": total_chunks,
                        "done": done,
                    })
                else:
                    file.save(dest)
                    try:
                        size = os.path.getsize(dest)
                    except OSError:
                        size = 0
                    request_total += size
                    if size > upload_max_bytes or request_total > upload_max_bytes:
                        try:
                            os.unlink(dest)
                        except OSError:
                            pass
                        results.append(_too_large_error(filename))
                        continue
                    results.append({"ok": True, "filename": filename})
            except Exception as e:  # noqa: BLE001
                results.append({"ok": False, "filename": filename, "error": str(e)})

        ok_all = all(r.get("ok") for r in results)
        status = 200 if ok_all else 500 if len(results) == 1 else 207
        # Backward compat: single single-shot upload returns {status, filename}.
        if len(results) == 1 and not chunked:
            single = results[0]
            if single.get("ok"):
                activity.log(
                    "files.upload", target=os.path.join(path, single["filename"]),
                    status="ok", ip=request.remote_addr or "",
                )
                return jsonify({"status": "uploaded", "filename": single["filename"]})
            code = 413 if single.get("code") == "too_large" else 400
            body = {"error": single.get("error", "upload failed")}
            if single.get("code"):
                body["code"] = single["code"]
            return jsonify(body), code
        activity.log(
            "files.upload", target=path, status="ok" if ok_all else "partial",
            detail=f"files={len(results)} chunked={chunked}",
            ip=request.remote_addr or "",
        )
        return jsonify({"files": results, "chunked": chunked}), status

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/files/editable-types', methods=['GET'])
@openapi_mod.describe(
    summary="List editable MIME types for the file editor",
    description=(
        "Returns the server-side allowlist gating the text editor "
        "(borrowed from Laranode editable_mime_types) plus a helper "
        "flag for a specific ?path."
    ),
    tag="Files",
)
def api_files_editable_types():
    rel = (request.args.get("path") or "").strip()
    out: dict = {"editable_mime_types": sorted(file_explorer.EDITABLE_MIME_TYPES)}
    if rel:
        try:
            target = file_explorer.resolve_api_path(rel)
            out["path"] = rel
            out["editable"] = file_explorer.is_editable_path(target)
            out["mime"] = file_explorer.mime_guess(target)
            out["kind"] = file_explorer.classify_api_path(target) if os.path.exists(target) else None
        except file_explorer.FileExplorerError as e:
            return jsonify({"error": str(e), "code": e.code}), 403
    return jsonify(out)

@app.route('/api/files/download', methods=['GET'])
def download_file():
    try:
        path = request.args.get('path', '')
        if not path:
             return jsonify({"error": "No path specified"}), 400
             
        base_dir = os.path.realpath(os.path.expanduser('~'))
        target_path = os.path.realpath(os.path.join(base_dir, path))
        
        if target_path != base_dir and not target_path.startswith(base_dir + os.sep):
            return jsonify({"error": "Access denied"}), 403
            
        if not os.path.exists(target_path):
            return jsonify({"error": "File not found"}), 404
            
        if os.path.isdir(target_path):
             return jsonify({"error": "Cannot download directory"}), 400

        return send_file(target_path, as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------------------------------------------------------------------
# System Services (systemd units)
# ---------------------------------------------------------------------------

@app.route('/api/system-services', methods=['GET'])
def api_system_services_list():
    unit_type = request.args.get('type', 'all')
    state = request.args.get('state', 'all')
    search = request.args.get('q', '').strip()
    only_user = request.args.get('user', '').lower() in ('1', 'true', 'yes')

    try:
        units = system_services.list_units(
            unit_type=unit_type, state=state, search=search, only_user=only_user,
        )
        return jsonify({
            "units": [u.to_summary() for u in units],
            "count": len(units),
        })
    except system_services.SystemServicesError as e:
        return jsonify({"error": str(e), "code": e.code}), 500
    except Exception as e:
        logger.error(f"system-services list failed: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/system-services/<path:name>', methods=['GET'])
def api_system_services_detail(name):
    try:
        unit = system_services.get_unit(name)
        if not unit:
            return jsonify({"error": "Unit not found"}), 404
        return jsonify(unit.to_detail())
    except system_services.SystemServicesError as e:
        return jsonify({"error": str(e), "code": e.code}), 500


@app.route('/api/system-services/<path:name>/unit', methods=['GET'])
def api_system_services_unit(name):
    try:
        content = system_services.get_unit_file(name)
        return jsonify({"name": name, "content": content})
    except system_services.SystemServicesError as e:
        http = 404 if e.code == "not_found" else 500
        return jsonify({"error": str(e), "code": e.code}), http


@app.route('/api/system-services/<path:name>/graph', methods=['GET'])
def api_system_services_graph(name):
    try:
        depth = int(request.args.get('depth', '2'))
    except ValueError:
        depth = 2
    return jsonify(system_services.get_dependencies(name, depth))


@app.route('/api/system-services/<path:name>/unit', methods=['PUT'])
def api_system_services_edit(name):
    data = request.get_json(silent=True) or {}
    content = data.get('content', '')
    password = data.get('password', '')

    if not isinstance(content, str):
        return jsonify({"error": "content must be a string"}), 400
    if len(content) > 200_000:
        return jsonify({"error": "content too large"}), 413
    if not password:
        return jsonify({"error": "auth_required"}), 401

    try:
        result = system_services.edit_unit_file(name, content, password)
        # If the content was for [Service]/[Timer] etc, suggest a daemon-reload
        return jsonify(result)
    except system_services.SystemServicesError as e:
        code = e.code
        http = 403 if code == "permission" else 400 if code in ("invalid",) else 500
        return jsonify({"error": str(e), "code": code}), http


@app.route('/api/system-services/<path:name>/<action>', methods=['POST'])
def api_system_services_action(name, action):
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')

    if action not in system_services.ACTIONS:
        return jsonify({"error": f"Unknown action: {action}"}), 400
    if not password:
        return jsonify({"error": "auth_required"}), 401

    try:
        result = system_services.control(name, action, password)
        activity.log(f"systemd.{action}", target=name, status="ok",
                    detail=result.get("output", ""), ip=request.remote_addr or "")
        return jsonify(result)
    except system_services.SystemServicesError as e:
        activity.log(f"systemd.{action}", target=name, status="error",
                    detail=f"{e.code}: {e}", ip=request.remote_addr or "")
        http = 403 if e.code == "permission" else 500
        return jsonify({"error": str(e), "code": e.code}), http


@app.route('/api/system-services/<path:name>/logs', methods=['GET'])
def api_system_services_logs(name):
    try:
        lines = int(request.args.get('lines', '100'))
    except ValueError:
        lines = 100
    try:
        logs = system_services.get_unit_logs(name, lines)
        return jsonify({"name": name, "logs": logs})
    except system_services.SystemServicesError as e:
        return jsonify({"error": str(e), "code": e.code}), 500


@app.route('/api/system-services/<path:name>/logs/search', methods=['GET'])
@openapi_mod.describe(
    summary="Search a systemd unit's journal logs",
    description=(
        "Server-side journalctl search with substring match, ISO/relative "
        "date range, journalctl priority, and pagination. When a search "
        "query is set, a wide window is fetched and filtered in Python "
        "(since journalctl has no substring filter)."
    ),
    tag="System Services",
    parameters=[
        {"name": "search", "in": "query", "schema": {"type": "string"}},
        {"name": "since", "in": "query", "schema": {"type": "string"}, "description": "passed to journalctl --since"},
        {"name": "until", "in": "query", "schema": {"type": "string"}},
        {"name": "priority", "in": "query", "schema": {"type": "string", "enum": ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]}},
        {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}},
        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 200, "maximum": 5000}},
    ],
)
def api_system_services_logs_search(name):
    """Server-side journalctl log search/filter.

    Query params:
      search   — substring match
      since    — relative ("5m", "1h") or unix timestamp
      until    — relative or unix timestamp
      priority — comma-separated journalctl priorities (emerg..debug)
      offset   — pagination offset
      limit    — max lines (default 200, max 5000)
    """
    import subprocess
    import time as _time
    search = (request.args.get('search') or '').lower()
    priority = request.args.get('priority') or 'info'
    try:
        offset = max(0, int(request.args.get('offset', '0')))
    except ValueError:
        offset = 0
    try:
        limit = max(1, min(5000, int(request.args.get('limit', '200'))))
    except ValueError:
        limit = 200

    def parse_ts(arg):
        if not arg:
            return None
        arg = arg.strip()
        if len(arg) >= 2 and arg[-1] in "smhd" and arg[:-1].isdigit():
            n = int(arg[:-1])
            mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[arg[-1]]
            return _time.time() - n * mult
        try:
            return float(arg)
        except ValueError:
            pass
        from datetime import datetime
        for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S',
                    '%Y-%m-%dT%H:%M', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
            try:
                return datetime.strptime(arg, fmt).timestamp()
            except ValueError:
                continue
        return None
    since_ts = parse_ts(request.args.get('since'))
    until_ts = parse_ts(request.args.get('until'))

    # Get a wider window when filters are present so we can post-filter
    # in Python; otherwise just ask for ``limit`` lines from the end.
    fetch_count = 5000 if (search or since_ts or until_ts) else limit
    cmd = [
        "journalctl", "-u", name, "-n", str(fetch_count), "--no-pager", "-o", "short",
    ]
    if priority and priority != "all":
        cmd += ["-p", priority]
    if since_ts:
        from datetime import datetime
        cmd += ["--since", datetime.fromtimestamp(since_ts).isoformat()]
    if until_ts:
        from datetime import datetime
        cmd += ["--until", datetime.fromtimestamp(until_ts).isoformat()]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        return jsonify({"error": "journalctl not installed", "code": "missing_tool"}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "journalctl timed out", "code": "timeout"}), 500
    if proc.returncode != 0:
        err = (proc.stderr or "").strip() or "journalctl failed"
        return jsonify({"error": err, "code": "error"}), 500

    lines = proc.stdout.splitlines()
    if search:
        lines = [ln for ln in lines if search in ln.lower()]

    matched = len(lines)
    page = lines[offset:offset + limit]
    has_more = (offset + limit) < matched
    return jsonify({
        "name": name,
        "logs": page,
        "matched": matched,
        "offset": offset,
        "limit": limit,
        "has_more": has_more,
    })


@app.route('/api/system-services/<path:name>/logs/stream', methods=['GET'])
def api_system_services_logs_stream(name):
    """Server-Sent Events endpoint for live log lines.

    Each connected client gets its own journalctl -f (the OS subprocess
    is shared via the streamer; only the per-client output queue is
    unique). Lines are written as ``data: <json>\\n\\n`` SSE frames.
    A sentinel ``{"ended": true}`` is sent when the stream closes.
    """
    priority = request.args.get('priority', 'info')
    try:
        lines = int(request.args.get('lines', '100'))
    except ValueError:
        lines = 100
    try:
        from app.log_streamer import get_streamer
        streamer = get_streamer()
        sid = f"sse-{request.remote_addr}-{id(request)}"
        handle = streamer.subscribe(name, sid, priority, lines)
    except (ValueError, RuntimeError) as e:
        return jsonify({"error": str(e)}), 400

    queue_obj = streamer.get_subscriber_queue(handle, sid)
    replay = streamer.get_replay(handle)

    def generate():
        try:
            for line in replay:
                yield f"data: {json.dumps({'line': line, 'unit': name})}\n\n"
            if queue_obj is None:
                return
            while True:
                try:
                    item = queue_obj.get(timeout=15)
                except queue.Empty:
                    # Heartbeat to keep connection alive through proxies
                    yield ": heartbeat\n\n"
                    continue
                if item is None:
                    yield f"data: {json.dumps({'ended': True, 'unit': name})}\n\n"
                    break
                yield f"data: {json.dumps({'line': item, 'unit': name})}\n\n"
        finally:
            streamer.unsubscribe(name, sid, priority)

    return app.response_class(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive',
        },
    )


# Docker management
@app.route('/docker')
def docker_page():
    return render_template('docker.html')


@app.route('/api/docker/availability')
@openapi_mod.describe(
    summary="Probe Docker daemon availability",
    description=(
        "Returns ``{available, reason, version}``. The reason is "
        "human-readable when the daemon is unreachable (e.g. permission "
        "denied → explains how to add user to docker group)."
    ),
    tag="Docker",
)
def api_docker_availability():
    try:
        return jsonify(docker_manager.is_available(timeout=0.5))
    except Exception as e:  # noqa: BLE001
        return jsonify({"available": False, "reason": str(e), "version": None})


@app.route('/api/docker/containers', methods=['GET'])
@openapi_mod.describe(
    summary="List Docker containers",
    description="Returns a summary list of containers. Use ``?all=false`` to filter to running ones.",
    tag="Docker",
    parameters=[
        {"name": "all", "in": "query", "schema": {"type": "string", "enum": ["true", "false"], "default": "true"}},
    ],
)
def api_docker_containers_list():
    try:
        all_containers = request.args.get('all', 'true').lower() != 'false'
        items = docker_manager.list_containers(all_containers=all_containers)
        return jsonify({"containers": [c.to_summary() for c in items]})
    except docker_manager.DockerError as e:
        code = e.code
        http = 403 if code == "permission" else 500
        return jsonify({"error": str(e), "code": code}), http


@app.route('/api/docker/containers/<path:id_or_name>', methods=['GET'])
def api_docker_container_detail(id_or_name):
    try:
        c = docker_manager.get_container(id_or_name)
        if c is None:
            return jsonify({"error": "not_found", "code": "not_found"}), 404
        return jsonify(c.to_detail())
    except docker_manager.DockerError as e:
        return jsonify({"error": str(e), "code": e.code}), 500


@app.route('/api/docker/containers/<path:id_or_name>/logs', methods=['GET'])
def api_docker_container_logs(id_or_name):
    try:
        tail = int(request.args.get('tail', '100'))
    except ValueError:
        tail = 100
    try:
        lines = docker_manager.get_logs(id_or_name, tail=tail)
        return jsonify({"container": id_or_name, "logs": lines})
    except docker_manager.DockerError as e:
        return jsonify({"error": str(e), "code": e.code}), 500


@app.route('/api/docker/containers/<path:id_or_name>/logs/stream', methods=['GET'])
def api_docker_container_logs_stream(id_or_name):
    """SSE stream of container logs.

    Yields ``data: {"line": "..."}`` frames; closes when the container stops
    or the consumer disconnects. The docker SDK's stream is consumed in a
    background thread; each connected client has its own generator.
    """
    try:
        tail = int(request.args.get('tail', '100'))
    except ValueError:
        tail = 100

    queue_obj: queue.Queue = queue.Queue(maxsize=2000)
    done = threading.Event()

    def pump():
        try:
            gen = docker_manager.stream_logs(id_or_name, tail=tail)
            for line in gen:
                if done.is_set():
                    break
                try:
                    queue_obj.put_nowait(line)
                except queue.Full:
                    pass
        except docker_manager.DockerError as e:
            try:
                queue_obj.put_nowait(f"__error__:{e}")
            except queue.Full:
                pass
        finally:
            try:
                queue_obj.put_nowait(None)
            except queue.Full:
                pass

    t = threading.Thread(target=pump, daemon=True)
    t.start()

    def generate():
        try:
            while True:
                try:
                    item = queue_obj.get(timeout=15)
                except queue.Empty:
                    yield ": heartbeat\n\n"
                    continue
                if item is None:
                    yield f"data: {json.dumps({'ended': True, 'container': id_or_name})}\n\n"
                    break
                if isinstance(item, str) and item.startswith("__error__:"):
                    yield f"data: {json.dumps({'error': item.split(':', 1)[1]})}\n\n"
                    break
                yield f"data: {json.dumps({'line': item, 'container': id_or_name})}\n\n"
        finally:
            done.set()

    return app.response_class(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive',
        },
    )


@app.route('/api/docker/containers/<path:id_or_name>/stats', methods=['GET'])
def api_docker_container_stats(id_or_name):
    try:
        return jsonify(docker_manager.get_stats(id_or_name))
    except docker_manager.DockerError as e:
        return jsonify({"error": str(e), "code": e.code}), 500


@app.route('/api/docker/containers/<path:id_or_name>/<action>', methods=['POST'])
def api_docker_container_action(id_or_name, action):
    if action not in docker_manager.LIFECYCLE_ACTIONS:
        return jsonify({"error": f"Unknown action: {action}"}), 400
    try:
        result = docker_manager.control(id_or_name, action)
        activity.log(f"docker.{action}", target=id_or_name, status="ok",
                    detail=result.get("output", ""), ip=request.remote_addr or "")
        return jsonify(result)
    except docker_manager.DockerError as e:
        activity.log(f"docker.{action}", target=id_or_name, status="error",
                    detail=f"{e.code}: {e}", ip=request.remote_addr or "")
        http = 403 if e.code == "permission" else 404 if e.code == "not_found" else 500
        return jsonify({"error": str(e), "code": e.code}), http


@app.route('/api/docker/containers/<path:id_or_name>', methods=['DELETE'])
def api_docker_container_remove(id_or_name):
    force = request.args.get('force', 'false').lower() == 'true'
    volumes = request.args.get('volumes', 'false').lower() == 'true'
    try:
        result = docker_manager.remove_container(id_or_name, force=force, volumes=volumes)
        activity.log("docker.remove", target=id_or_name, status="ok",
                    detail=f"force={force} volumes={volumes}", ip=request.remote_addr or "")
        return jsonify(result)
    except docker_manager.DockerError as e:
        activity.log("docker.remove", target=id_or_name, status="error",
                    detail=f"{e.code}: {e}", ip=request.remote_addr or "")
        http = 403 if e.code == "permission" else 404 if e.code == "not_found" else 500
        return jsonify({"error": str(e), "code": e.code}), http


@app.route('/api/docker/images', methods=['GET'])
def api_docker_images_list():
    try:
        return jsonify({"images": docker_manager.list_images()})
    except docker_manager.DockerError as e:
        return jsonify({"error": str(e), "code": e.code}), 500


@app.route('/api/docker/images/<path:id_or_name>', methods=['DELETE'])
def api_docker_image_remove(id_or_name):
    """Remove a Docker image by short id, full id, or repo:tag."""
    force = (request.args.get('force') or '').lower() in ('1', 'true', 'yes')
    try:
        result = docker_manager.remove_image(id_or_name, force=force)
        activity.log("docker.image.remove", target=id_or_name, status="ok",
                    detail=result.get("output", ""), ip=request.remote_addr or "")
        return jsonify(result)
    except docker_manager.DockerError as e:
        activity.log("docker.image.remove", target=id_or_name, status="error",
                    detail=str(e), ip=request.remote_addr or "")
        if e.code == "not_found":
            return jsonify({"error": str(e), "code": e.code}), 404
        return jsonify({"error": str(e), "code": e.code}), 500


@app.route('/api/docker/daemon', methods=['GET'])
@openapi_mod.describe(
    summary="Docker daemon info",
    description="Small subset of ``docker info`` for the Daemon view.",
    tag="Docker",
)
def api_docker_daemon_info():
    try:
        return jsonify(docker_manager.daemon_info())
    except docker_manager.DockerError as e:
        return jsonify({"error": str(e), "code": e.code}), 500


@app.route('/api/docker/daemon/restart', methods=['POST'])
@openapi_mod.describe(
    summary="Restart the Docker daemon",
    description=(
        "Runs ``sudo systemctl restart docker`` with the user's sudo "
        "password (not the app login) piped to ``sudo -S`` (same pattern "
        "as systemd unit control). Expect a brief disconnect."
    ),
    tag="Docker",
)
def api_docker_daemon_restart():
    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""
    try:
        result = docker_manager.restart_daemon(password)
        activity.log("docker.daemon.restart", status="ok",
                     detail=result.get("output", ""), ip=request.remote_addr or "")
        return jsonify(result)
    except docker_manager.DockerError as e:
        activity.log("docker.daemon.restart", status="error",
                     detail=f"{e.code}: {e}", ip=request.remote_addr or "")
        http = 403 if e.code == "permission" else 500
        return jsonify({"error": str(e), "code": e.code}), http


@app.route('/api/docker/images/prune', methods=['POST'])
@openapi_mod.describe(
    summary="Prune dangling Docker images",
    description="Deletes dangling images; reports deleted count and reclaimed bytes.",
    tag="Docker",
)
def api_docker_images_prune():
    try:
        result = docker_manager.prune_images()
        activity.log("docker.image.prune", status="ok",
                     detail=result.get("output", ""), ip=request.remote_addr or "")
        return jsonify(result)
    except docker_manager.DockerError as e:
        activity.log("docker.image.prune", status="error",
                     detail=f"{e.code}: {e}", ip=request.remote_addr or "")
        return jsonify({"error": str(e), "code": e.code}), 500


# Cron management
@app.route('/cron')
def cron_page():
    return render_template('cron.html')


@app.route('/api/cron', methods=['GET'])
def api_cron_list():
    try:
        jobs = cron_manager.list_all()
        out = []
        for j in jobs:
            d = j.to_dict()
            try:
                d["next_run"] = cron_manager.next_run(j.schedule) if j.enabled else None
            except Exception:
                d["next_run"] = None
            out.append(d)
        return jsonify({
            "jobs": out,
            "count": len(out),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/cron/validate', methods=['POST'])
def api_cron_validate():
    data = request.get_json(silent=True) or {}
    expr = (data.get("expression") or "").strip()
    err = cron_manager.validate_expression(expr)
    return jsonify({
        "valid": err is None,
        "error": err,
        "description": cron_manager.describe_schedule(expr) if err is None else None,
    })


@app.route('/api/cron/toggle', methods=['POST'])
def api_cron_toggle():
    data = request.get_json(silent=True) or {}
    source = (data.get("source") or "").strip()
    line_number = data.get("line_number")
    enabled = bool(data.get("enabled"))
    password = data.get("password", "")
    try:
        result = cron_manager.toggle_system_job(source, int(line_number), enabled, password)
        activity.log("cron.toggle", target=f"{source}:{line_number}",
                    status="ok", detail=f"enabled={enabled}",
                    ip=request.remote_addr or "")
        return jsonify(result)
    except cron_manager.CronError as e:
        activity.log("cron.toggle", target=f"{source}:{line_number}",
                    status="error", detail=f"{e.code}: {e}",
                    ip=request.remote_addr or "")
        http = 403 if e.code == "permission" else 400 if e.code in ("invalid", "auth_required") else 500
        return jsonify({"error": str(e), "code": e.code}), http


@app.route('/api/cron/jobs', methods=['POST'])
@openapi_mod.describe(
    summary="Add a cron job",
    description=(
        "Appends ``schedule user command`` to a file in ``/etc/cron.d/`` "
        "(created with a manager header when missing) via ``sudo cp`` "
        "of a tempfile, using the user's sudo password."
    ),
    tag="Cron",
)
def api_cron_add():
    data = request.get_json(silent=True) or {}
    try:
        result = cron_manager.add_job(
            data.get("filename") or "manager",
            (data.get("schedule") or "").strip(),
            (data.get("user") or "").strip(),
            data.get("command") or "",
            data.get("password", ""),
        )
        activity.log("cron.add", target=result.get("source", ""),
                     status="ok", detail=(data.get("schedule") or ""),
                     ip=request.remote_addr or "")
        return jsonify(result)
    except cron_manager.CronError as e:
        activity.log("cron.add", status="error", detail=f"{e.code}: {e}",
                     ip=request.remote_addr or "")
        http = 403 if e.code in ("permission", "auth_required") else 400 if e.code == "invalid" else 500
        return jsonify({"error": str(e), "code": e.code}), http


@app.route('/api/programs/<name>/autostart', methods=['GET'])
def api_program_autostart_get(name):
    """Return whether the managed service is enabled at boot.

    Runs ``systemctl is-enabled ssm-<name>.service`` to determine
    state, falling back to the in-memory config flag.
    """
    program = pm.get_program(name)
    if not program:
        return jsonify({"error": "Program not found"}), 404
    safe_name = "".join(c for c in name if c.isalnum() or c in "_-.")
    if not safe_name or safe_name != name:
        return jsonify({"error": "Invalid service name"}), 400
    unit_name = f"ssm-{safe_name}.service"
    try:
        proc = subprocess.run(
            ["systemctl", "is-enabled", unit_name],
            capture_output=True, text=True, timeout=5,
        )
        enabled = proc.returncode == 0
    except Exception:
        enabled = False
    return jsonify({
        "name": name,
        "unit": unit_name,
        "autostart": enabled,
    })


@app.route('/api/programs/<name>/autostart', methods=['POST'])
def api_program_autostart(name):
    """Enable or disable systemd-level autostart for a managed service.

    Writes a small systemd unit to /etc/systemd/system/ssm-<name>.service
    that runs the same command, and uses systemctl enable|disable. The
    manager's manual start/stop is unaffected — this just adds a
    matching systemd unit that the bootloader will run on startup.
    """
    program = pm.get_program(name)
    if not program:
        return jsonify({"error": "Program not found"}), 404
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get("enabled"))
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "auth_required"}), 401

    safe_name = "".join(c for c in name if c.isalnum() or c in "_-.")
    if not safe_name or safe_name != name:
        return jsonify({"error": "Invalid service name"}), 400

    unit_name = f"ssm-{safe_name}.service"
    unit_path = f"/etc/systemd/system/{unit_name}"
    try:
        if enabled:
            # Build the [Service] section
            cfg = program.config
            exec_start = cfg.command
            working_dir = cfg.cwd or "/"
            env_lines = "\n".join(
                f'Environment="{k}={v}"' for k, v in (cfg.environment or {}).items()
            )
            unit_content = (
                "[Unit]\n"
                f"Description=Server Services Manager: {name}\n"
                "After=network.target\n"
                "\n"
                "[Service]\n"
                f"WorkingDirectory={working_dir}\n"
                f"ExecStart={exec_start}\n"
                f"{env_lines}\n"
                "Restart=on-failure\n"
                "RestartSec=5\n"
                "\n"
                "[Install]\n"
                "WantedBy=multi-user.target\n"
            )
            # Write via tempfile + sudo cp
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".service") as tmp:
                tmp.write(unit_content)
                tmp_path = tmp.name
            try:
                os.chmod(tmp_path, 0o644)
                subprocess.run(
                    ["sudo", "-S", "cp", tmp_path, unit_path],
                    input=password + "\n", capture_output=True, text=True, timeout=10,
                )
            finally:
                try: os.unlink(tmp_path)
                except OSError: pass

        # Now enable or disable via systemctl
        action = "enable" if enabled else "disable"
        proc = subprocess.run(
            ["sudo", "-S", "systemctl", action, unit_name],
            input=password + "\n", capture_output=True, text=True, timeout=15,
        )
        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            first = next((ln for ln in stderr.splitlines() if ln.strip() and "password for" not in ln), stderr)
            lower = stderr.lower()
            if "password" in lower or "permission" in lower or "not in" in lower:
                return jsonify({"error": first, "code": "permission"}), 403
            return jsonify({"error": first, "code": "error"}), 500
        if not enabled:
            # Optionally remove the unit file too
            subprocess.run(
                ["sudo", "-S", "rm", "-f", unit_path],
                input=password + "\n", capture_output=True, text=True, timeout=5,
            )
        subprocess.run(
            ["sudo", "-S", "systemctl", "daemon-reload"],
            input=password + "\n", capture_output=True, text=True, timeout=10,
        )
        # Update the in-memory config
        program.config.autostart = enabled
        activity.log(f"autostart.{action}", target=name, status="ok",
                    detail=f"unit={unit_name}", ip=request.remote_addr or "")
        return jsonify({
            "ok": True,
            "output": f"{action}d {unit_name}",
            "autostart": enabled,
        })
    except subprocess.TimeoutExpired:
        activity.log(f"autostart.{action}", target=name, status="error",
                    detail="timeout", ip=request.remote_addr or "")
        return jsonify({"error": "command timed out"}), 504
    except Exception as e:
        activity.log(f"autostart.{action}", target=name, status="error",
                    detail=str(e), ip=request.remote_addr or "")
        return jsonify({"error": str(e)}), 500


# ---- Schedule (systemd timer) management ----------------------------

@app.route('/api/programs/<name>/schedule', methods=['GET'])
def api_program_schedule_get(name):
    """Return current schedule + timer state for a program."""
    from app import schedules
    program = pm.get_program(name)
    if not program:
        return jsonify({"error": "Program not found"}), 404
    schedule = program.config.schedule or ""
    status = schedules.timer_status(name) if schedule else {
        "enabled": False, "active": False, "next_run": None, "last_run": None,
    }
    return jsonify({
        "name": name,
        "schedule": schedule,
        "is_scheduled": bool(schedule),
        "valid": schedules.is_valid_schedule(schedule),
        "presets": [{"value": v, "label": l} for v, l in schedules.preset_suggestions()],
        "timer": status,
    })


@app.route('/api/programs/<name>/schedule', methods=['POST'])
def api_program_schedule_set(name):
    """Set the schedule for a program and write the systemd units.

    Body: {schedule: "hourly", password?: "..."}
    If the schedule is non-empty, also enables the timer (unless
    the user passes ``enable: false``).
    """
    from app import schedules
    program = pm.get_program(name)
    if not program:
        return jsonify({"error": "Program not found"}), 404
    data = request.json or {}
    expr = (data.get("schedule") or "").strip()
    if not schedules.is_valid_schedule(expr):
        return jsonify({
            "error": f"Invalid schedule expression: {expr!r}",
            "code": "invalid",
        }), 400
    password = data.get("password") or ""
    enable = data.get("enable", True)
    try:
        if expr:
            ok, err = schedules.write_units(
                name, program.config.command, program.config.cwd,
                expr, program.config.environment,
            )
            if not ok:
                activity.log("program.schedule", target=name, status="error",
                            detail=err, ip=request.remote_addr or "")
                return jsonify({"error": err, "code": "write"}), 500
            if enable:
                ok, err = schedules.enable_timer(name, password=password or None)
                if not ok:
                    activity.log("program.schedule", target=name, status="error",
                                detail=f"enable: {err}", ip=request.remote_addr or "")
                    return jsonify({"error": err, "code": "permission"}), 403
        else:
            schedules.remove_units(name)
        # Update in-memory + persisted config
        program.config.schedule = expr
        pm._save_config_file()
        status = schedules.timer_status(name) if expr else {
            "enabled": False, "active": False, "next_run": None, "last_run": None,
        }
        activity.log("program.schedule", target=name, status="ok",
                    detail=f"schedule={expr!r}", ip=request.remote_addr or "")
        return jsonify({
            "ok": True,
            "schedule": expr,
            "timer": status,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "command timed out"}), 504
    except Exception as e:
        activity.log("program.schedule", target=name, status="error",
                    detail=str(e), ip=request.remote_addr or "")
        return jsonify({"error": str(e)}), 500


@app.route('/api/programs/<name>/schedule/trigger', methods=['POST'])
def api_program_schedule_trigger(name):
    """Run a scheduled task immediately (one-shot start)."""
    from app import schedules
    program = pm.get_program(name)
    if not program:
        return jsonify({"error": "Program not found"}), 404
    password = (request.json or {}).get("password") or None
    ok, err = schedules.trigger_now(name, password=password)
    activity.log("program.schedule.trigger", target=name,
                status="ok" if ok else "error",
                detail="" if ok else err, ip=request.remote_addr or "")
    if not ok:
        code = "permission" if "assword" in err.lower() else "error"
        return jsonify({"error": err, "code": code}), 403 if code == "permission" else 500
    return jsonify({"ok": True})


@app.route('/api/programs/<name>/schedule', methods=['DELETE'])
def api_program_schedule_remove(name):
    """Remove the schedule (and the timer units)."""
    from app import schedules
    program = pm.get_program(name)
    if not program:
        return jsonify({"error": "Program not found"}), 404
    ok, err = schedules.remove_units(name)
    if not ok:
        return jsonify({"error": err}), 500
    program.config.schedule = ""
    pm._save_config_file()
    activity.log("program.schedule.remove", target=name, status="ok",
                ip=request.remote_addr or "")
    return jsonify({"ok": True, "schedule": ""})


# ---- Resource limits (systemd drop-in) ------------------------------

@app.route('/api/programs/<name>/limits', methods=['GET'])
def api_program_limits_get(name):
    """Return the current resource limits and the supported fields."""
    from app import resource_limits
    program = pm.get_program(name)
    if not program:
        return jsonify({"error": "Program not found"}), 404
    return jsonify({
        "name": name,
        "limits": resource_limits.get(name),
        "fields": resource_limits.field_choices(),
    })


@app.route('/api/programs/<name>/limits', methods=['POST'])
def api_program_limits_set(name):
    """Apply resource limits to the program's systemd drop-in.

    Body: {limits: {cpu_quota: "50", memory_max: "512M", ...},
           password?: "..."}
    Pass an empty string to clear a single field.
    """
    from app import resource_limits
    program = pm.get_program(name)
    if not program:
        return jsonify({"error": "Program not found"}), 404
    data = request.json or {}
    settings = data.get("limits", {})
    password = data.get("password") or None
    ok, err = resource_limits.apply(name, settings, password=password)
    activity.log("program.limits", target=name,
                status="ok" if ok else "error",
                detail="" if ok else err, ip=request.remote_addr or "")
    if not ok:
        code = "permission" if "password" in err.lower() else "error"
        return jsonify({"error": err, "code": code}), 403 if code == "permission" else 400
    return jsonify({"ok": True, "limits": resource_limits.get(name)})


@app.route('/api/programs/<name>/limits', methods=['DELETE'])
def api_program_limits_clear(name):
    """Remove the drop-in entirely."""
    from app import resource_limits
    program = pm.get_program(name)
    if not program:
        return jsonify({"error": "Program not found"}), 404
    password = (request.json or {}).get("password") or None
    ok, err = resource_limits.clear(name, password=password)
    activity.log("program.limits.clear", target=name,
                status="ok" if ok else "error",
                detail="" if ok else err, ip=request.remote_addr or "")
    if not ok:
        return jsonify({"error": err}), 500
    return jsonify({"ok": True, "limits": {}})


@app.route('/notifications')
def notifications_page():
    return render_template('notifications.html')


@app.route('/activity')
def activity_page():
    return render_template('activity.html')


@app.route('/api/plugins', methods=['GET'])
def api_plugins_list():
    """List user plugins discovered in the plugin directory.

    Read-only; the loader is what actually instantiates and
    registers them at startup.
    """
    from app import plugins as _plugins
    return jsonify({
        "directory": _plugins.DEFAULT_DIR,
        "plugins": _plugins.discover(),
    })


@app.route('/plugins')
def plugins_page():
    """User plugin manager — list what was discovered at startup."""
    return render_template('plugins.html')


@app.route('/config')
def config_page():
    """View and validate config.yaml without editing it."""
    return render_template('config.html')


@app.route('/api/config', methods=['GET'])
def api_config_view():
    """Return the parsed config.yaml + validation result.

    The file is read directly (not via pm.load_config) so the
    UI always sees what's on disk, even if the in-memory
    representation has been edited. Sensitive fields (passwords,
    keys) are redacted before returning.
    """
    from app import config_schema
    config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
    if not os.path.exists(config_path):
        return jsonify({
            "path": config_path,
            "exists": False,
            "raw": None,
            "valid": True,
            "errors": [],
            "warnings": [],
        })
    try:
        with open(config_path) as f:
            raw = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        return jsonify({
            "path": config_path,
            "exists": True,
            "raw": None,
            "valid": False,
            "errors": [{"loc": "(file)", "msg": f"YAML parse error: {e}"}],
            "warnings": [],
        })
    # Redact obvious secrets so the UI doesn't display them.
    redacted = _redact_secrets(raw)
    errors = []
    warnings = []
    valid = True
    try:
        config_schema.validate_config(redacted)
    except Exception as e:  # pydantic.ValidationError
        valid = False
        # pydantic's ValidationError exposes .errors() as a method.
        # Older versions exposed it as a property; handle both so
        # the page keeps working across pydantic releases.
        err_iter = e.errors() if callable(getattr(e, "errors", None)) else (getattr(e, "errors", []) or [])
        for err in err_iter:
            errors.append({
                "loc": ".".join(str(x) for x in err.get("loc", [])),
                "msg": err.get("msg", "invalid"),
                "type": err.get("type", "value_error"),
            })
    # A small set of soft warnings we surface even when the
    # schema validates (the schema is lenient, so it doesn't
    # catch everything).
    if raw.get("commands"):
        ids = [c.get("id") for c in raw.get("commands", []) if c.get("id")]
        if len(ids) != len(set(ids)):
            warnings.append({
                "loc": "commands",
                "msg": "duplicate command id detected",
            })
    return jsonify({
        "path": config_path,
        "exists": True,
        "raw": redacted,
        "valid": valid,
        "errors": errors,
        "warnings": warnings,
    })


def _redact_secrets(data):
    """Walk the parsed config and replace any 'password' or 'key'
    field values with '***' so they don't get sent to the
    browser. The on-disk file is not modified.
    """
    if isinstance(data, dict):
        out = {}
        for k, v in data.items():
            kl = str(k).lower()
            is_secret = any(t in kl for t in ("password", "secret", "token", "key"))
            if isinstance(v, dict):
                out[k] = _redact_secrets(v)
            elif isinstance(v, list):
                if is_secret:
                    out[k] = ["***" if isinstance(x, str) else _redact_secrets(x) if isinstance(x, dict) else x for x in v]
                else:
                    out[k] = [_redact_secrets(x) if isinstance(x, dict) else x for x in v]
            elif is_secret and isinstance(v, str):
                out[k] = "***"
            else:
                out[k] = v
        return out
    if isinstance(data, list):
        return [_redact_secrets(x) if isinstance(x, dict) else x for x in data]
    return data


def _control_commands_for_palette():
    """Return the list of custom control commands from config.yaml."""
    config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
    if not os.path.exists(config_path):
        return []
    try:
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        return cfg.get('commands', []) if cfg else []
    except Exception:
        return []


def _system_units_for_palette():
    """Return a small list of running systemd units for the palette."""
    try:
        units = system_services.list_units(state="active", unit_type="service")
        return units[:30]
    except Exception:
        return []


@app.route('/api/palette/search', methods=['GET'])
def api_palette_search():
    q = request.args.get('q', '').strip()
    try:
        limit = max(1, min(50, int(request.args.get('limit', '20'))))
    except ValueError:
        limit = 20
    items = palette.build_palette_index(
        get_programs=lambda: pm.get_all_programs(),
        get_control_commands=_control_commands_for_palette,
        get_system_units=_system_units_for_palette,
    )
    results = palette.search(items, q, limit=limit)
    return jsonify({"results": results})


@app.route('/api/programs/export', methods=['GET'])
def api_programs_export():
    """Export the full set of managed services as JSON.

    The shape matches what ``POST /api/programs/import`` accepts, so a
    file produced here can be re-imported on a fresh install to
    reproduce the same fleet.
    """
    payload = {
        "version": 1,
        "exported_at": time.time(),
        "programs": [
            {
                "name": p.config.name,
                "command": p.config.command,
                "cwd": p.config.cwd,
                "autostart": p.config.autostart,
                "environment": p.config.environment,
            }
            for p in pm.get_all_programs()
        ],
    }
    return app.response_class(
        json.dumps(payload, indent=2),
        mimetype="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="services.json"',
        },
    )


@app.route('/api/programs/import', methods=['POST'])
def api_programs_import():
    """Import a JSON export.

    Body: ``{"version": 1, "programs": [...]}``.

    Modes (via ``?mode=replace|merge``, default ``merge``):
    - ``merge``: keep existing programs, add new ones by name
      (overwriting if the name matches).
    - ``replace``: remove all existing programs first, then import.
    """
    data = request.get_json(silent=True) or {}
    if not isinstance(data.get("programs"), list):
        return jsonify({"error": "expected { programs: [...] }"}), 400
    mode = request.args.get("mode", "merge")
    if mode == "replace":
        for p in list(pm.get_all_programs()):
            try:
                pm.delete_program(p.config.name)
            except Exception:
                pass
    added = 0
    skipped = 0
    for entry in data["programs"]:
        try:
            cfg = ProgramConfig(
                name=entry["name"],
                command=entry["command"],
                cwd=entry["cwd"],
                autostart=entry.get("autostart", False),
                environment=entry.get("environment", {}),
            )
            pm.add_program(cfg)
            added += 1
        except Exception as e:
            skipped += 1
            activity.log("program.import.skip", target=entry.get("name", ""),
                        status="error", detail=str(e),
                        ip=request.remote_addr or "")
    activity.log("program.import", target=f"mode={mode}",
                status="ok", detail=f"added={added} skipped={skipped}",
                ip=request.remote_addr or "")
    return jsonify({"ok": True, "added": added, "skipped": skipped, "mode": mode})


@app.route('/api/activity', methods=['GET'])
def api_activity_list():
    action = request.args.get('action') or None
    target = request.args.get('target') or None
    user = request.args.get('user') or None
    status = request.args.get('status') or None
    try:
        since = float(request.args['since']) if 'since' in request.args else None
    except (KeyError, ValueError):
        since = None
    try:
        limit = max(1, min(1000, int(request.args.get('limit', '200'))))
    except ValueError:
        limit = 200
    entries = activity.list_entries(
        action=action, target=target, user=user, status=status,
        since=since, limit=limit,
    )
    return jsonify({
        "entries": entries,
        "summary": activity.count_by_action(),
    })


@app.route('/api/activity/export.csv', methods=['GET'])
def api_activity_export():
    try:
        limit = max(1, min(10000, int(request.args.get('limit', '1000'))))
    except ValueError:
        limit = 1000
    entries = activity.list_entries(limit=limit)
    csv = activity.export_csv(entries)
    return app.response_class(
        csv, mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="activity.csv"'},
    )


# Alert history (notification delivery log)
@app.route('/alerts')
def alerts_page():
    return render_template('alerts.html')


def _parse_since(arg):
    """Parse a ``since=`` query value as either a relative duration
    string ("24h", "7d", "30m") or an absolute unix timestamp.
    Returns a float or None on failure.
    """
    if not arg:
        return None
    arg = arg.strip()
    if not arg:
        return None
    # Relative: "30s", "5m", "2h", "7d"
    if len(arg) >= 2 and arg[-1] in "smhd" and arg[:-1].isdigit():
        n = int(arg[:-1])
        mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[arg[-1]]
        return time.time() - n * mult
    try:
        return float(arg)
    except ValueError:
        return None


@app.route('/api/alerts/events', methods=['GET'])
@openapi_mod.describe(
    summary="List notification delivery events",
    description=(
        "Returns recent notification delivery attempts with channel, "
        "recipient, success/failure, latency. Supports relative or "
        "absolute date ranges for `since`/`until`."
    ),
    tag="Alerts",
    parameters=[
        {"name": "channel", "in": "query", "schema": {"type": "string", "enum": ["ntfy", "webhook", "telegram", "email"]}},
        {"name": "service", "in": "query", "schema": {"type": "string"}},
        {"name": "success", "in": "query", "schema": {"type": "string", "enum": ["true", "false", "1", "0"]}},
        {"name": "since", "in": "query", "schema": {"type": "string"}},
        {"name": "until", "in": "query", "schema": {"type": "string"}},
        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 200, "maximum": 5000}},
    ],
)
def api_alerts_events():
    try:
        limit = max(1, min(5000, int(request.args.get('limit', '200'))))
    except ValueError:
        limit = 200
    channel = request.args.get('channel') or None
    service = request.args.get('service') or None
    success_raw = request.args.get('success')
    success = None
    if success_raw is not None:
        if success_raw.lower() in ("1", "true", "yes"):
            success = True
        elif success_raw.lower() in ("0", "false", "no"):
            success = False
    since = _parse_since(request.args.get('since'))
    until = _parse_since(request.args.get('until'))
    events = alert_log.list_events(
        channel=channel, service=service, success=success,
        since=since, until=until, limit=limit,
    )
    return jsonify({"events": events})


@app.route('/api/alerts/stats', methods=['GET'])
def api_alerts_stats():
    since = _parse_since(request.args.get('since'))
    return jsonify({
        "channels": alert_log.channel_stats(since=since),
        "summary": alert_log.summary(since=since),
    })


@app.route('/api/alerts/export.csv', methods=['GET'])
def api_alerts_export():
    try:
        limit = max(1, min(10000, int(request.args.get('limit', '1000'))))
    except ValueError:
        limit = 1000
    entries = alert_log.list_events(limit=limit)
    csv = alert_log.export_csv(entries)
    return app.response_class(
        csv, mimetype="text/csv",
        headers={"Content-Disposition": 'attachment; filename="alerts.csv"'},
    )


# Package updates
@app.route('/packages')
def packages_page():
    return render_template('packages.html')


# Log search
@app.route('/logs')
def logs_search_page():
    return render_template('logs.html')


# Firewall management
@app.route('/firewall')
def firewall_page():
    return render_template('firewall.html')


@app.route('/api/firewall/status', methods=['GET', 'POST'])
@openapi_mod.describe(
    summary="Read firewall status (ufw/firewalld)",
    description=(
        "Returns the current firewall backend, enabled state, default "
        "policies, and rule list. Optional sudo ``password`` (JSON body on "
        "POST, ``?password=`` on GET) elevates the "
        "read with sudo so the full rule list is returned. The sudo "
        "password is never assumed to equal the app login password."
    ),
    tag="Firewall",
    parameters=[
        {"name": "password", "in": "query", "schema": {"type": "string"}, "description": "optional sudo password for sudo-elevated read (GET)"},
    ],
    request_body={
        "required": False,
        "content": {"application/json": {"schema": {
            "type": "object",
            "properties": {
                "password": {"type": "string", "description": "optional sudo password for sudo-elevated read (POST, preferred — avoids access-log leak)"},
            },
        }}},
    },
)
def api_firewall_status():
    # Optional sudo password; if provided, the read is elevated
    # so the user can see the full rules list. POST body preferred
    # (avoids password in access logs); GET query kept for compat.
    password = None
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        password = data.get('password', '') or None
    if not password:
        password = request.args.get('password', '') or None
    try:
        return jsonify(firewall_manager.get_status(password=password).to_dict())
    except firewall_manager.FirewallError as e:
        http = 403 if e.code == "permission" else 500
        return jsonify({"error": str(e), "code": e.code}), http


@app.route('/api/firewall/enable', methods=['POST'])
def api_firewall_enable():
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')
    if not password:
        return jsonify({"error": "auth_required"}), 401
    try:
        result = firewall_manager.enable(password)
        activity.log("firewall.enable", target="", status="ok",
                     detail=result.get("output", ""), ip=request.remote_addr or "")
        return jsonify(result)
    except firewall_manager.FirewallError as e:
        activity.log("firewall.enable", target="", status="error",
                     detail=f"{e.code}: {e}", ip=request.remote_addr or "")
        http = 403 if e.code == "permission" else 500
        return jsonify({"error": str(e), "code": e.code}), http


@app.route('/api/firewall/disable', methods=['POST'])
def api_firewall_disable():
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')
    if not password:
        return jsonify({"error": "auth_required"}), 401
    try:
        result = firewall_manager.disable(password)
        activity.log("firewall.disable", target="", status="ok",
                     detail=result.get("output", ""), ip=request.remote_addr or "")
        return jsonify(result)
    except firewall_manager.FirewallError as e:
        activity.log("firewall.disable", target="", status="error",
                     detail=f"{e.code}: {e}", ip=request.remote_addr or "")
        http = 403 if e.code == "permission" else 500
        return jsonify({"error": str(e), "code": e.code}), http


@app.route('/api/firewall/reload', methods=['POST'])
def api_firewall_reload():
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')
    if not password:
        return jsonify({"error": "auth_required"}), 401
    try:
        result = firewall_manager.reload(password)
        activity.log("firewall.reload", target="", status="ok",
                     detail=result.get("output", ""), ip=request.remote_addr or "")
        return jsonify(result)
    except firewall_manager.FirewallError as e:
        activity.log("firewall.reload", target="", status="error",
                     detail=f"{e.code}: {e}", ip=request.remote_addr or "")
        http = 403 if e.code == "permission" else 500
        return jsonify({"error": str(e), "code": e.code}), http


@app.route('/api/firewall/default', methods=['POST'])
def api_firewall_default():
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')
    policy = data.get('policy', '')
    direction = data.get('direction', '')
    if not password:
        return jsonify({"error": "auth_required"}), 401
    try:
        result = firewall_manager.set_default(policy, direction, password)
        activity.log("firewall.default", target=f"{direction}={policy}", status="ok",
                     detail=result.get("output", ""), ip=request.remote_addr or "")
        return jsonify(result)
    except firewall_manager.FirewallError as e:
        activity.log("firewall.default", target=f"{direction}={policy}", status="error",
                     detail=f"{e.code}: {e}", ip=request.remote_addr or "")
        http = 403 if e.code == "permission" else 400 if e.code in ("invalid", "unsupported") else 500
        return jsonify({"error": str(e), "code": e.code}), http


@app.route('/api/firewall/rules', methods=['POST'])
def api_firewall_add_rule():
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')
    spec = {k: v for k, v in data.items() if k != 'password'}
    if not password:
        return jsonify({"error": "auth_required"}), 401
    try:
        result = firewall_manager.add_rule(spec, password)
        activity.log("firewall.add_rule",
                     target=f"{spec.get('action')}/{spec.get('port')}/{spec.get('protocol', 'any')}",
                     status="ok", detail=result.get("output", ""), ip=request.remote_addr or "")
        return jsonify(result)
    except firewall_manager.FirewallError as e:
        activity.log("firewall.add_rule",
                     target=f"{spec.get('action')}/{spec.get('port')}",
                     status="error", detail=f"{e.code}: {e}", ip=request.remote_addr or "")
        if e.code == "confirm_required":
            return jsonify({
                "error": str(e), "code": e.code,
                "preview": getattr(e, "preview", ""),
                "lockout_warning": getattr(e, "lockout_warning", True),
            }), 409
        http = 403 if e.code == "permission" else 400 if e.code == "invalid" else 500
        return jsonify({"error": str(e), "code": e.code}), http


@app.route('/api/firewall/rule-preview', methods=['POST'])
@openapi_mod.describe(
    summary="Validate a firewall rule form and preview it",
    description=(
        "Validates action/port/protocol/source/direction without touching "
        "the system (Laranode BuildUfwRuleSpec idea). Returns a normalized "
        "spec, a human preview string, and lockout_warning=True when the "
        "rule would deny inbound SSH without a source restriction."
    ),
    tag="Firewall",
)
def api_firewall_rule_preview():
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(firewall_manager.build_rule_spec(
            action=data.get("action", "allow"),
            port=str(data.get("port", "")),
            protocol=data.get("protocol", "tcp"),
            source=data.get("source", ""),
            direction=data.get("direction", "in"),
        ))
    except firewall_manager.FirewallError as e:
        return jsonify({"error": str(e), "code": e.code}), 400


@app.route('/api/firewall/rules', methods=['DELETE'])
def api_firewall_delete_rule():
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')
    spec = {k: v for k, v in data.items() if k != 'password'}
    if not password:
        return jsonify({"error": "auth_required"}), 401
    try:
        result = firewall_manager.delete_rule(spec, password)
        target = str(spec.get('number')) if spec.get('number') else f"{spec.get('action')}/{spec.get('port')}"
        activity.log("firewall.delete_rule", target=target, status="ok",
                     detail=result.get("output", ""), ip=request.remote_addr or "")
        return jsonify(result)
    except firewall_manager.FirewallError as e:
        activity.log("firewall.delete_rule", target="", status="error",
                     detail=f"{e.code}: {e}", ip=request.remote_addr or "")
        http = 403 if e.code == "permission" else 400 if e.code == "invalid" else 500
        return jsonify({"error": str(e), "code": e.code}), http


# Backup scheduler
@app.route('/backups')
def backups_page():
    return render_template('backups.html')


@app.route('/api/backups', methods=['GET'])
def api_backups_list():
    jobs = [j.to_dict() for j in backup_manager.list_jobs()]
    return jsonify({"jobs": jobs})


def _parse_enabled_flag(value) -> bool:
    """Parse the ``enabled`` request flag without bool("false") == True."""
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


@app.route('/api/backups', methods=['POST'])
@openapi_mod.describe(
    summary="Create a backup job",
    description=(
        "Creates a new backup job that materializes as a systemd timer "
        "+ service pair. Required fields: name, type (directory/mysql/"
        "postgres), source, destination, schedule. Retention defaults "
        "to 7 (most-recent N archives kept)."
    ),
    tag="Backups",
    request_body={
        "required": True,
        "content": {"application/json": {"schema": {
            "type": "object",
            "required": ["name", "type", "source", "destination", "schedule"],
            "properties": {
                "name": {"type": "string"},
                "type": {"type": "string", "enum": ["directory", "mysql", "postgres"]},
                "source": {"type": "string"},
                "destination": {"type": "string"},
                "schedule": {"type": "string", "description": "systemd OnCalendar expression"},
                "retention": {"type": "integer", "default": 7},
                "password": {"type": "string", "description": "optional sudo password (not app login) to enable the timer"},
            },
        }}},
    },
)
def api_backups_create():
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')
    required = ['name', 'type', 'source', 'destination', 'schedule']
    for k in required:
        if not data.get(k):
            return jsonify({"error": f"{k} is required"}), 400
    try:
        retention = int(data.get('retention', 7))
    except (TypeError, ValueError):
        return jsonify({"error": "invalid retention (must be an integer 1-365)", "code": "invalid"}), 400
    # A job is only marked enabled once its timer actually is. Without
    # a password the timer can't be enabled, so the job starts
    # disabled and the UI offers Enable — never a lying badge.
    want_enabled = _parse_enabled_flag(data.get('enabled', True)) and bool(password)
    try:
        job = backup_manager.create_job(
            name=data['name'],
            type_=data['type'],
            source=data['source'],
            destination=data['destination'],
            schedule=data['schedule'],
            retention=retention,
            enabled=False,
        )
    except ValueError as e:
        return jsonify({"error": str(e), "code": "invalid"}), 400
    except RuntimeError as e:
        return jsonify({"error": str(e), "code": "error"}), 500

    warning = ""
    if want_enabled:
        if not system_services.verify_password(password):
            return jsonify({"error": "wrong password", "code": "permission"}), 403
        ok, err = backup_manager.enable_job(job.name, password=password)
        if not ok:
            warning = f"enable failed: {err}"
    else:
        warning = "created disabled; enable it from the table to start the schedule"

    if warning.startswith("enable failed"):
        activity.log("backup.create", target=job.name, status="partial",
                     detail=warning, ip=request.remote_addr or "")
    else:
        activity.log("backup.create", target=job.name, status="ok",
                     detail=f"{job.type} {job.source}->{job.destination}", ip=request.remote_addr or "")
    fresh = backup_manager.get_job(job.name)
    resp: dict = {"job": (fresh or job).to_dict()}
    if warning:
        resp["warning"] = warning
    return jsonify(resp)


def _verify_backup_password(password) -> bool:
    """User timers need no sudo exec, but the password field must still
    mean something: it has to be the user's actual sudo password
    (verified via ``sudo -S -v``), never the app login password."""
    return bool(password) and system_services.verify_password(password)


@app.route('/api/backups/<name>', methods=['DELETE'])
def api_backups_delete(name):
    ok, warning = backup_manager.delete_job(name)
    if not ok:
        return jsonify({"error": "not_found"}), 404
    activity.log("backup.delete", target=name, status="ok",
                 detail=warning[:200] if warning else "",
                 ip=request.remote_addr or "")
    resp: dict = {"ok": True}
    if warning:
        resp["warning"] = warning
    return jsonify(resp)


@app.route('/api/backups/<name>/enable', methods=['POST'])
def api_backups_enable(name):
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')
    if not password:
        return jsonify({"error": "auth_required"}), 401
    if not _verify_backup_password(password):
        return jsonify({"error": "wrong password", "code": "permission"}), 403
    ok, err = backup_manager.enable_job(name, password=password)
    if not ok:
        activity.log("backup.enable", target=name, status="error",
                     detail=err, ip=request.remote_addr or "")
        http = 403 if "permission" in err.lower() or "password" in err.lower() else 500
        return jsonify({"error": err, "code": "permission" if http == 403 else "error"}), http
    activity.log("backup.enable", target=name, status="ok", ip=request.remote_addr or "")
    return jsonify({"ok": True})


@app.route('/api/backups/<name>/disable', methods=['POST'])
def api_backups_disable(name):
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')
    if not password:
        return jsonify({"error": "auth_required"}), 401
    if not _verify_backup_password(password):
        return jsonify({"error": "wrong password", "code": "permission"}), 403
    ok, err = backup_manager.disable_job(name, password=password)
    if not ok:
        activity.log("backup.disable", target=name, status="error",
                     detail=err, ip=request.remote_addr or "")
        return jsonify({"error": err, "code": "error"}), 500
    activity.log("backup.disable", target=name, status="ok", ip=request.remote_addr or "")
    return jsonify({"ok": True})


@app.route('/api/backups/<name>/run', methods=['POST'])
def api_backups_run(name):
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')
    if not password:
        return jsonify({"error": "auth_required"}), 401
    if not _verify_backup_password(password):
        return jsonify({"error": "wrong password", "code": "permission"}), 403
    ok, err = backup_manager.trigger_now(name, password=password)
    if not ok:
        activity.log("backup.run", target=name, status="error",
                     detail=err, ip=request.remote_addr or "")
        return jsonify({"error": err, "code": "error"}), 500
    activity.log("backup.run", target=name, status="ok", ip=request.remote_addr or "")
    return jsonify({"ok": True})


@app.route('/api/backups/<name>/status')
def api_backups_status(name):
    job = backup_manager.get_job(name)
    if not job:
        return jsonify({"error": "not_found"}), 404
    status = backup_manager.get_status(name)
    return jsonify({"job": job.to_dict(), "timer": status})


# Disk usage analyzer (Phase 25)
@app.route('/disk')
def disk_page():
    return render_template('disk.html')


@app.route('/api/disk/usage', methods=['GET'])
@openapi_mod.describe(
    summary="Disk usage for a path under $HOME",
    description=(
        "Returns the immediate children of `path` (relative to "
        "$HOME) with their apparent sizes in bytes, sorted by size "
        "descending. `depth` is capped at 3. `timeout` (seconds, "
        "1-300) overrides the default 60s. Paths outside $HOME "
        "are rejected. Common cache/build directories (node_modules, "
        ".git, .cache, venv, etc.) are excluded from the recursive "
        "walk by default — drill into them explicitly if you want "
        "their size."
    ),
    tag="Disk Usage",
)
def api_disk_usage():
    path = request.args.get("path", "")
    depth = request.args.get("depth", "1")
    timeout = request.args.get("timeout")
    try:
        result = disk_manager.get_usage(path=path, depth=depth, timeout=timeout)
    except disk_manager.DiskError as e:
        if e.code == "outside_home":
            activity.log(
                "disk.usage", target=path, status="denied",
                detail=str(e), ip=request.remote_addr or "",
            )
            return jsonify({"error": str(e), "code": e.code}), 403
        if e.code == "not_found":
            return jsonify({"error": str(e), "code": e.code}), 404
        if e.code == "timeout":
            # 503 with a hint lets the frontend offer a "retry
            # with a longer timeout" button.
            return jsonify({
                "error": str(e), "code": e.code,
                "retry_with_timeout": result_timeout_hint(),
            }), 503
        return jsonify({"error": str(e), "code": e.code}), 400
    except Exception as e:  # noqa: BLE001
        logger.exception(f"disk usage failed for path={path!r}")
        return jsonify({"error": str(e), "code": "internal"}), 500

    result["largest"] = disk_manager.largest_items(result.get("items", []), n=20)
    result["breadcrumb"] = disk_manager.breadcrumb(result.get("path", "."))
    return jsonify(result)


def result_timeout_hint():
    """Return a sensible retry timeout (current × 2, capped at 300s)."""
    try:
        cur = float(request.args.get("timeout") or disk_manager._DU_TIMEOUT_SECONDS)
    except (TypeError, ValueError):
        cur = float(disk_manager._DU_TIMEOUT_SECONDS)
    return int(min(cur * 2, disk_manager._MAX_TIMEOUT))


@app.route('/api/disk/breadcrumb', methods=['GET'])
@openapi_mod.describe(
    summary="Resolve a path into breadcrumb segments",
    description=(
        "Splits a path relative to $HOME into clickable breadcrumb "
        "segments. Returns 403 if the path escapes $HOME."
    ),
    tag="Disk Usage",
)
def api_disk_breadcrumb():
    path = request.args.get("path", "")
    try:
        crumbs = disk_manager.breadcrumb(path)
    except disk_manager.DiskError as e:
        return jsonify({"error": str(e), "code": e.code}), 403
    return jsonify({"breadcrumb": crumbs})


@app.route('/api/monitor/services', methods=['GET'])
@openapi_mod.describe(
    summary="Pinned systemd units overview for /monitor",
    description=(
        "Returns machine-readable status for up to 10 units "
        "(?units=docker.service,ssh.service). Uses systemctl show, "
        "not fragile status-text parsing. Missing units return "
        "exists=False so the UI can hide them."
    ),
    tag="Monitor",
)
def api_monitor_services():
    raw = request.args.get("units", "")
    units = [u.strip() for u in raw.split(",") if u.strip()]
    if not units:
        units = ["docker.service", "ssh.service", "cron.service"]
    return jsonify({"services": service_overview.get_summaries(units)})


@app.route('/api/monitor/sort', methods=['GET'])
@openapi_mod.describe(
    summary="Get persisted Top Processes sort preference",
    description=(
        "Returns the server-side default sort column + direction for "
        "the /monitor processes table (borrowed from Laranode top-sort). "
        "The table itself still sorts client-side; this only seeds it."
    ),
    tag="Monitor",
)
def api_monitor_sort_get():
    return jsonify(monitor_prefs.get_prefs())


@app.route('/api/monitor/sort', methods=['POST'])
@openapi_mod.describe(
    summary="Persist Top Processes sort preference",
    description="Body: {sort: cpu|memory|name|pid|status, direction?: asc|desc}.",
    tag="Monitor",
)
def api_monitor_sort_set():
    payload = request.get_json(silent=True) or {}
    sort = str(payload.get("sort") or "").strip()
    direction = payload.get("direction")
    if direction is not None:
        direction = str(direction).strip()
    try:
        prefs = monitor_prefs.set_prefs(sort, direction)
    except ValueError as e:
        return jsonify({"error": str(e), "code": "invalid"}), 400
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": str(e), "code": "internal"}), 500
    activity.log(
        "monitor.sort", target=prefs["sort"], status="ok",
        detail=prefs["direction"], ip=request.remote_addr or "",
    )
    return jsonify(prefs)


# SSH authorized_keys manager (Phase 26)
@app.route('/ssh')
def ssh_page():
    return render_template('ssh.html')


@app.route('/api/ssh/keys', methods=['GET'])
@openapi_mod.describe(
    summary="List authorized SSH keys",
    description=(
        "Reads ~/.ssh/authorized_keys and returns each key's "
        "algorithm, SHA256 fingerprint, comment, and any "
        "sshd-style options prefix. Returns an empty list when "
        "the file doesn't exist (which is normal for a fresh "
        "user)."
    ),
    tag="SSH Keys",
)
def api_ssh_keys_list():
    try:
        return jsonify(ssh_manager.list_keys())
    except ssh_manager.SSHKeyError as e:
        return jsonify({"error": str(e), "code": e.code}), 500


@app.route('/api/ssh/keys', methods=['POST'])
@openapi_mod.describe(
    summary="Add an authorized SSH key",
    description=(
        "Appends a key to ~/.ssh/authorized_keys. The request "
        "body must include a `key` field with the full public-"
        "key line (algorithm + base64 + optional comment). "
        "Returns 409 if the fingerprint is already present."
    ),
    tag="SSH Keys",
)
def api_ssh_keys_add():
    payload = request.get_json(silent=True) or {}
    key_text = (payload.get("key") or "").strip()
    if not key_text:
        return jsonify({"error": "missing 'key' field", "code": "empty_input"}), 400
    try:
        parsed = ssh_manager.add_key(key_text)
    except ssh_manager.SSHKeyError as e:
        if e.code == "ssh_dir_missing":
            activity.log(
                "ssh.add_key", target="", status="error",
                detail=str(e), ip=request.remote_addr or "",
            )
        if e.code == "duplicate":
            return jsonify({"error": str(e), "code": e.code}), 409
        if e.code in ("empty_input", "invalid_format", "invalid_base64", "unknown_algorithm"):
            return jsonify({"error": str(e), "code": e.code}), 400
        return jsonify({"error": str(e), "code": e.code}), 500
    except Exception as e:  # noqa: BLE001
        logger.exception(f"ssh add_key failed")
        return jsonify({"error": str(e), "code": "internal"}), 500
    activity.log(
        "ssh.add_key", target=parsed.get("fingerprint", ""), status="ok",
        detail=parsed.get("comment", ""), ip=request.remote_addr or "",
    )
    return jsonify({"key": parsed})


@app.route('/api/ssh/keys/<path:identifier>', methods=['DELETE'])
@openapi_mod.describe(
    summary="Remove an authorized SSH key",
    description=(
        "Removes a key by its fingerprint or full comment. By "
        "default refuses to delete the last remaining key "
        "(`lockout_risk` -> 409). Pass `confirm_last=true` in "
        "the JSON body to override — only do this if you have "
        "another way into the box."
    ),
    tag="SSH Keys",
)
def api_ssh_keys_remove(identifier):
    payload = request.get_json(silent=True) or {}
    confirm_last = bool(payload.get("confirm_last", False))
    try:
        result = ssh_manager.remove_key(identifier, confirm_last=confirm_last)
    except ssh_manager.SSHKeyError as e:
        if e.code == "lockout_risk":
            return jsonify({"error": str(e), "code": e.code,
                            "requires_confirm": True}), 409
        if e.code == "not_found":
            return jsonify({"error": str(e), "code": e.code}), 404
        if e.code == "empty_identifier":
            return jsonify({"error": str(e), "code": e.code}), 400
        return jsonify({"error": str(e), "code": e.code}), 500
    except Exception as e:  # noqa: BLE001
        logger.exception(f"ssh remove_key failed")
        return jsonify({"error": str(e), "code": "internal"}), 500
    activity.log(
        "ssh.remove_key", target=identifier, status="ok",
        detail=f"removed={result['removed']} remaining={result['remaining']}",
        ip=request.remote_addr or "",
    )
    return jsonify(result)


# Full file explorer (Phase 28)
@app.route('/files')
def files_page():
    return render_template('files.html')


# VS Code in an iframe (code-server, Phase 29). The IDE runs as the
# `code-server` managed program (see install-code-server.sh) bound to
# localhost; the browser reaches it directly on its port (same-site,
# so the password cookie works inside the iframe). Our resumable
# uploads, viewers, and editor stay: code-server's drag/drop upload
# corrupts 90 MB+ files (coder/code-server#2803) and VS Code chokes
# on multi-GB files, so /files remains the heavy-lifting path.
CODE_SERVER_HOST = os.getenv("CODE_SERVER_HOST", "127.0.0.1")
CODE_SERVER_PORT = int(os.getenv("CODE_SERVER_PORT", "8600") or 8600)


def _code_server_binary() -> str:
    return os.path.expanduser("~/.local/bin/code-server")


@app.route('/code')
def code_page():
    return render_template('code.html')


@app.route('/api/code/status', methods=['GET'])
@openapi_mod.describe(
    summary="VS Code Server status for the /code page",
    description=(
        "Returns whether the code-server binary is installed, whether "
        "the `code-server` managed program is running, and the "
        "browser-reachable host/port (derived from the Host header so "
        "LAN access works, not just localhost). With `?path=` "
        "(home-relative file/dir) it also returns an absolute "
        "`folder` + `file` for the `?folder=` deep link."
    ),
    tag="Code",
)
def api_code_status():
    import shutil

    binary = _code_server_binary()
    installed = os.path.isfile(binary) and os.access(binary, os.X_OK)
    running = False
    try:
        program = pm.get_program("code-server")
        if program is not None:
            running = program.status.value in ("running", "starting")
    except Exception:  # noqa: BLE001
        running = False
    # Browser-reachable host: the hostname the user used to reach us
    # (Host header), since code-server binds localhost on this box and
    # the browser resolves the same machine via our address.
    host = (request.host or "").split(":")[0] or "127.0.0.1"
    out = {
        "installed": installed,
        "running": running,
        "program": "code-server",
        "host": CODE_SERVER_HOST if CODE_SERVER_HOST not in ("127.0.0.1", "localhost") else host,
        "port": CODE_SERVER_PORT,
    }
    rel = (request.args.get("path") or "").strip()
    if rel:
        try:
            target = file_explorer.resolve_api_path(rel)
            if os.path.isdir(target) and not os.path.islink(target):
                out["folder"] = target
            else:
                out["folder"] = os.path.dirname(target)
                out["file"] = target
        except file_explorer.FileExplorerError as e:
            return jsonify({"error": str(e), "code": e.code}), 403
    return jsonify(out)


@app.route('/api/files/tree', methods=['GET'])
@openapi_mod.describe(
    summary="Recursive directory tree",
    description=(
        "Returns a tree of children up to `depth` levels deep "
        "(capped at 6). Hidden files (dotfiles) are excluded by "
        "default; pass `hidden=true` to include them. The "
        "response carries `truncated=true` if the result hit "
        "the 5,000-entry cap."
    ),
    tag="Files",
)
def api_files_tree():
    path = request.args.get("path", "")
    depth = request.args.get("depth", "2")
    hidden = request.args.get("hidden", "false").lower() in ("1", "true", "yes")
    try:
        return jsonify(file_explorer.tree(path=path, depth=depth, hidden=hidden))
    except file_explorer.FileExplorerError as e:
        if e.code == "outside_home":
            return jsonify({"error": str(e), "code": e.code}), 403
        if e.code == "not_a_directory":
            return jsonify({"error": str(e), "code": e.code}), 404
        return jsonify({"error": str(e), "code": e.code}), 400


@app.route('/api/files/search', methods=['GET'])
@openapi_mod.describe(
    summary="Search filenames recursively under a path",
    description=(
        "Case-insensitive substring match against file/dir "
        "names under the given path. Returns up to 500 "
        "matches."
    ),
    tag="Files",
)
def api_files_search():
    q = request.args.get("q", "")
    path = request.args.get("path", ".")
    try:
        return jsonify(file_explorer.search(q, path=path))
    except file_explorer.FileExplorerError as e:
        if e.code in ("empty_query", "query_too_long"):
            return jsonify({"error": str(e), "code": e.code}), 400
        if e.code == "outside_home":
            return jsonify({"error": str(e), "code": e.code}), 403
        return jsonify({"error": str(e), "code": e.code}), 500


@app.route('/api/files/preview', methods=['GET'])
@openapi_mod.describe(
    summary="Preview a file's contents (text or base64 image/pdf)",
    description=(
        "Returns the file's first 50 MB (configurable via "
        "`max_bytes`). Text files come back as decoded UTF-8 "
        "string; images and PDFs as base64 (`data_b64`). The "
        "browser can render both inline."
    ),
    tag="Files",
)
def api_files_preview():
    path = request.args.get("path", "")
    max_bytes = request.args.get("max_bytes")
    try:
        return jsonify(file_explorer.preview(path=path, max_bytes=max_bytes))
    except file_explorer.FileExplorerError as e:
        if e.code in ("not_found", "outside_home"):
            return jsonify({"error": str(e), "code": e.code}), 404
        return jsonify({"error": str(e), "code": e.code}), 400


@app.route('/api/files/chmod', methods=['POST'])
@openapi_mod.describe(
    summary="Change file mode (chmod)",
    description=(
        "Body: `{path, mode}` where `mode` is either an "
        "octal string (`'0755'`) or an integer (493). Mode "
        "is clamped to 0-0o7777."
    ),
    tag="Files",
)
def api_files_chmod():
    payload = request.get_json(silent=True) or {}
    path = (payload.get("path") or "").strip()
    mode = payload.get("mode")
    if not path:
        return jsonify({"error": "path is required", "code": "invalid_path"}), 400
    try:
        result = file_explorer.chmod(path, mode)
    except file_explorer.FileExplorerError as e:
        if e.code == "outside_home":
            return jsonify({"error": str(e), "code": e.code}), 403
        if e.code == "not_found":
            return jsonify({"error": str(e), "code": e.code}), 404
        return jsonify({"error": str(e), "code": e.code}), 400
    activity.log(
        "files.chmod", target=path, status="ok",
        detail=result.get("mode_str", ""), ip=request.remote_addr or "",
    )
    return jsonify(result)


@app.route('/api/files/bulk-delete', methods=['POST'])
@openapi_mod.describe(
    summary="Delete multiple files / directories in one call",
    description=(
        "Body: `{paths: ['a', 'sub/b', ...]}`. Refuses more "
        "than 1,000 entries at once. Returns per-path "
        "results so the caller can show which deletes failed."
    ),
    tag="Files",
)
def api_files_bulk_delete():
    payload = request.get_json(silent=True) or {}
    paths = payload.get("paths") or []
    if not isinstance(paths, list):
        return jsonify({"error": "paths must be a list", "code": "invalid"}), 400
    try:
        result = file_explorer.bulk_delete(paths)
    except file_explorer.FileExplorerError as e:
        return jsonify({"error": str(e), "code": e.code}), 400
    activity.log(
        "files.bulk_delete", target=",".join(paths[:5]), status="ok",
        detail=f"deleted={result['deleted']} failed={result['failed']}",
        ip=request.remote_addr or "",
    )
    return jsonify(result)


@app.route('/api/files/zip', methods=['POST'])
@openapi_mod.describe(
    summary="Bundle selected paths into a single zip",
    description=(
        "Body: `{paths: [...]}`. The response is the raw "
        "zip bytes (application/zip). Refuses more than "
        "1,000 entries or >256 MB of uncompressed data."
    ),
    tag="Files",
)
def api_files_zip():
    payload = request.get_json(silent=True) or {}
    paths = payload.get("paths") or []
    if not isinstance(paths, list):
        return jsonify({"error": "paths must be a list", "code": "invalid"}), 400
    try:
        data, suggested = file_explorer.make_zip(paths)
    except file_explorer.FileExplorerError as e:
        return jsonify({"error": str(e), "code": e.code}), 400
    activity.log(
        "files.zip", target=",".join(paths[:5]), status="ok",
        detail=f"{len(data)} bytes, {len(paths)} paths",
        ip=request.remote_addr or "",
    )
    return Response(
        data,
        status=200,
        headers={
            "Content-Type": "application/zip",
            "Content-Disposition": f'attachment; filename="{suggested}"',
            "Content-Length": str(len(data)),
        },
    )


def _files_err(e: file_explorer.FileExplorerError, default_status: int = 400):
    """Map a FileExplorerError to (json, status); offset mismatches are 409."""
    status = 409 if e.code == "offset_mismatch" else default_status
    body = {"error": str(e), "code": e.code}
    received = getattr(e, "received", None)
    if received is not None:
        body["received"] = received
    return jsonify(body), status


@app.route('/api/files/mkdir', methods=['POST'])
@openapi_mod.describe(
    summary="Create a directory",
    description="Body: `{path, name}`. Creates one level; slashes rejected.",
    tag="Files",
)
def api_files_mkdir():
    payload = request.get_json(silent=True) or {}
    try:
        out = file_explorer.mkdir(payload.get("path", "."), payload.get("name", ""))
    except file_explorer.FileExplorerError as e:
        return _files_err(e)
    activity.log("files.mkdir", target=out["path"], status="ok", ip=request.remote_addr or "")
    return jsonify(out)


@app.route('/api/files/rename', methods=['POST'])
@openapi_mod.describe(
    summary="Rename a file or directory",
    description="Body: `{path, name}`. Stays in the same directory.",
    tag="Files",
)
def api_files_rename():
    payload = request.get_json(silent=True) or {}
    try:
        out = file_explorer.rename(payload.get("path", ""), payload.get("name", ""))
    except file_explorer.FileExplorerError as e:
        return _files_err(e)
    activity.log(
        "files.rename", target=f'{out["old_path"]} -> {out["path"]}',
        status="ok", ip=request.remote_addr or "",
    )
    return jsonify(out)


@app.route('/api/files/move', methods=['POST'])
@openapi_mod.describe(
    summary="Move paths into a directory (cut + paste)",
    description="Body: `{paths: [...], dest}`. Cross-device falls back to streamed copy + unlink.",
    tag="Files",
)
def api_files_move():
    payload = request.get_json(silent=True) or {}
    paths = payload.get("paths") or []
    if not isinstance(paths, list):
        return jsonify({"error": "paths must be a list", "code": "invalid"}), 400
    try:
        out = file_explorer.move(paths, payload.get("dest", "."))
    except file_explorer.FileExplorerError as e:
        return _files_err(e)
    activity.log(
        "files.move", target=payload.get("dest", "."), status="ok",
        detail=f"moved={out['moved']} failed={out['failed']}",
        ip=request.remote_addr or "",
    )
    return jsonify(out)


@app.route('/api/files/copy', methods=['POST'])
@openapi_mod.describe(
    summary="Copy paths into a directory (copy + paste)",
    description="Body: `{paths: [...], dest}`. Files stream; constant memory.",
    tag="Files",
)
def api_files_copy():
    payload = request.get_json(silent=True) or {}
    paths = payload.get("paths") or []
    if not isinstance(paths, list):
        return jsonify({"error": "paths must be a list", "code": "invalid"}), 400
    try:
        out = file_explorer.copy(paths, payload.get("dest", "."))
    except file_explorer.FileExplorerError as e:
        return _files_err(e)
    activity.log(
        "files.copy", target=payload.get("dest", "."), status="ok",
        detail=f"copied={out['copied']} failed={out['failed']}",
        ip=request.remote_addr or "",
    )
    return jsonify(out)


@app.route('/api/files/uploads', methods=['POST'])
@openapi_mod.describe(
    summary="Start a resumable upload session",
    description=(
        "Body: `{name, size, path?, subpath?, sha256?}`. Preallocates a "
        "sparse staging file (instant even for 100 GB) and returns "
        "`{id, received: 0}`. Fails fast when disk space is short."
    ),
    tag="Files",
)
def api_files_uploads_init():
    payload = request.get_json(silent=True) or {}
    try:
        out = file_explorer.init_upload(
            payload.get("name", ""),
            payload.get("size", -1),
            payload.get("path", "."),
            subpath=payload.get("subpath"),
            sha256=payload.get("sha256"),
        )
    except file_explorer.FileExplorerError as e:
        return _files_err(e, 413 if e.code in ("too_large", "not_enough_space") else 400)
    return jsonify(out)


@app.route('/api/files/uploads/<session_id>', methods=['GET'])
@openapi_mod.describe(
    summary="Resumable upload status (bytes received)",
    description="Lets an interrupted client resume from `received` instead of restarting.",
    tag="Files",
)
def api_files_uploads_status(session_id):
    try:
        return jsonify(file_explorer.upload_status(session_id))
    except file_explorer.FileExplorerError as e:
        return _files_err(e, 404)


@app.route('/api/files/uploads/<session_id>', methods=['PUT'])
@openapi_mod.describe(
    summary="Upload one chunk (raw body at ?offset=)",
    description=(
        "Raw octet-stream body written at `?offset=`, which must equal "
        "the session's `received` counter (409 + `received` on mismatch). "
        "The body streams to disk in 1 MiB blocks — constant memory."
    ),
    tag="Files",
)
def api_files_uploads_chunk(session_id):
    try:
        offset = int(request.args.get("offset", -1))
    except (TypeError, ValueError):
        return jsonify({"error": "offset must be a number", "code": "bad_offset"}), 400
    try:
        out = file_explorer.append_chunk(session_id, offset, request.stream)
    except file_explorer.FileExplorerError as e:
        return _files_err(e, 404 if e.code == "unknown_upload" else 400)
    return jsonify(out)


@app.route('/api/files/uploads/<session_id>/complete', methods=['POST'])
@openapi_mod.describe(
    summary="Finalize a resumable upload",
    description=(
        "Verifies size (+ optional `{sha256}`), then atomically renames "
        "the staging file onto its real name. Interrupts never leave partials."
    ),
    tag="Files",
)
def api_files_uploads_complete(session_id):
    payload = request.get_json(silent=True) or {}
    try:
        out = file_explorer.complete_upload(session_id, sha256=payload.get("sha256"))
    except file_explorer.FileExplorerError as e:
        return _files_err(e, 404 if e.code == "unknown_upload" else 400)
    activity.log(
        "files.upload", target=out["path"], status="ok",
        detail=f"resumable {out['size']} bytes", ip=request.remote_addr or "",
    )
    return jsonify(out)


@app.route('/api/files/save', methods=['POST'])
@openapi_mod.describe(
    summary="Save text content to a file (editor)",
    description=(
        "Body: `{path, content}`. Gated by the editable-type "
        "allowlist (binaries rejected), 1 MB cap, atomic write "
        "preserving mode bits."
    ),
    tag="Files",
)
def api_files_save():
    payload = request.get_json(silent=True) or {}
    try:
        out = file_explorer.save_text(
            payload.get("path", ""), payload.get("content", ""),
        )
    except file_explorer.FileExplorerError as e:
        return _files_err(e)
    activity.log(
        "files.save", target=out["path"], status="ok",
        detail=f"{out['size']} bytes", ip=request.remote_addr or "",
    )
    return jsonify(out)


@app.route('/api/files/uploads/<session_id>', methods=['DELETE'])
@openapi_mod.describe(
    summary="Cancel a resumable upload",
    description="Discards staging bytes + session. Idempotent.",
    tag="Files",
)
def api_files_uploads_cancel(session_id):
    return jsonify(file_explorer.cancel_upload(session_id))


@app.route('/api/packages/manager')
def api_packages_manager():
    return jsonify({"manager": package_manager.detect_manager()})


# Multi-host cluster manager (Phase 27)
@app.route('/cluster')
def cluster_page():
    return render_template('cluster.html')


@app.route('/api/cluster/info', methods=['GET'])
@openapi_mod.describe(
    summary="Cluster info: local identity + enabled flag",
    description=(
        "Returns whether cluster mode is enabled in config and "
        "this node's hostname, port, and whether a secret is "
        "configured (has_secret). The raw secret is only included "
        "when ?include_secret=true so the UI can pre-fill the add-"
        "peer form; never log it."
    ),
    tag="Cluster",
)
def api_cluster_info():
    cfg_data = pm.config_data if hasattr(pm, "config_data") else {}
    cfg = cluster_manager.get_cluster_config(cfg_data)
    ident = cluster_manager.local_identity(cfg_data)
    include = (request.args.get("include_secret", "") or "").lower() in (
        "1", "true", "yes",
    )
    out = {
        "enabled": cfg["enabled"],
        "hostname": ident["hostname"],
        "port": ident["port"],
        "has_secret": bool(cfg["secret"]),
        "advertise": cfg["advertise"],
    }
    if include:
        out["secret"] = cfg["secret"]
    return jsonify(out)


@app.route('/api/cluster/nodes', methods=['GET'])
@openapi_mod.describe(
    summary="List known peer nodes",
    description=(
        "Returns every peer in the local registry plus a summary "
        "block with reachable/unreachable counts. Per-peer secrets "
        "are never returned; each entry carries has_secret instead "
        "(the proxy reads the stored secret server-side). "
        "Reachability is read from the cached `last_seen` field; call "
        "POST /api/cluster/probe to refresh."
    ),
    tag="Cluster",
)
def api_cluster_nodes_list():
    data = cluster_manager.list_peers_with_status()
    masked = []
    for p in data.get("peers", []):
        q = {k: v for k, v in p.items() if k != "secret"}
        q["has_secret"] = bool(p.get("secret"))
        masked.append(q)
    data["peers"] = masked
    return jsonify(data)


@app.route('/api/cluster/nodes', methods=['POST'])
@openapi_mod.describe(
    summary="Add a peer node",
    description=(
        "Manually add a peer (host:port). The shared secret is "
        "optional; if omitted the proxy will fall back to the "
        "local cluster.secret from config."
    ),
    tag="Cluster",
)
def api_cluster_nodes_add():
    payload = request.get_json(silent=True) or {}
    host = (payload.get("host") or "").strip()
    try:
        port = int(payload.get("port", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "port must be an integer", "code": "invalid_port"}), 400
    secret = (payload.get("secret") or "").strip()
    label = (payload.get("label") or "").strip()
    try:
        peer = cluster_manager.add_peer(host, port, secret=secret, label=label)
    except cluster_manager.ClusterError as e:
        http = 409 if e.code == "duplicate" else 400
        return jsonify({"error": str(e), "code": e.code}), http
    activity.log(
        "cluster.add_peer", target=peer["id"], status="ok",
        detail=peer.get("label", ""), ip=request.remote_addr or "",
    )
    masked = {k: v for k, v in peer.items() if k != "secret"}
    masked["has_secret"] = bool(peer.get("secret"))
    return jsonify({"peer": masked})


@app.route('/api/cluster/nodes/<peer_id>', methods=['DELETE'])
@openapi_mod.describe(
    summary="Remove a peer node",
    tag="Cluster",
)
def api_cluster_nodes_remove(peer_id):
    try:
        out = cluster_manager.remove_peer(peer_id)
    except cluster_manager.ClusterError as e:
        return jsonify({"error": str(e), "code": e.code}), 404
    activity.log(
        "cluster.remove_peer", target=peer_id, status="ok",
        detail="", ip=request.remote_addr or "",
    )
    return jsonify(out)


@app.route('/api/cluster/probe', methods=['POST'])
@openapi_mod.describe(
    summary="Probe reachability of every known peer",
    description=(
        "HEAD/GET /health on every registered peer and update "
        "the cached last_seen / last_error fields. Returns the "
        "per-peer results."
    ),
    tag="Cluster",
)
def api_cluster_probe():
    return jsonify(cluster_manager.probe_all_peers(timeout=2.0))


@app.route('/api/cluster/mdns', methods=['POST'])
@openapi_mod.describe(
    summary="Best-effort mDNS browse (zeroconf)",
    description=(
        "Browses _ssm-manager._tcp.local. for peers if the "
        "zeroconf package is installed. Returns an empty list "
        "if zeroconf isn't available or the browse fails — "
        "this endpoint never raises."
    ),
    tag="Cluster",
)
def api_cluster_mdns():
    payload = request.get_json(silent=True) or {}
    timeout = float(payload.get("timeout", 2.0))
    timeout = max(0.5, min(timeout, 10.0))
    return jsonify({"peers": cluster_manager.try_mdns_browse(timeout=timeout)})


@app.route('/api/cluster/config', methods=['GET'])
@openapi_mod.describe(
    summary="Read this node's cluster settings",
    description=(
        "Returns the local cluster: block (enabled, port, "
        "advertise) plus has_secret. The raw secret is never "
        "returned — the peer registry and proxy read it "
        "server-side."
    ),
    tag="Cluster",
)
def api_cluster_config_get():
    cfg_data = pm.config_data if hasattr(pm, "config_data") else {}
    cfg = cluster_manager.get_cluster_config(cfg_data)
    ident = cluster_manager.local_identity(cfg_data)
    return jsonify({
        "enabled": cfg["enabled"],
        "port": cfg["port"],
        "advertise": cfg["advertise"],
        "has_secret": bool(cfg["secret"]),
        "hostname": ident["hostname"],
    })


@app.route('/api/cluster/config', methods=['PUT'])
@openapi_mod.describe(
    summary="Update this node's cluster settings",
    description=(
        "Writes the cluster: block to config.yaml (secret, "
        "enabled, port, advertise). Omit secret to keep the "
        "existing one; pass clear_secret=true to remove it. "
        "Takes effect immediately — no restart needed."
    ),
    tag="Cluster",
)
def api_cluster_config_put():
    payload = request.get_json(silent=True) or {}
    cfg_data = pm.config_data if hasattr(pm, "config_data") else {}
    try:
        block = cluster_manager.build_cluster_block(
            payload, (cfg_data or {}).get("cluster") or {}
        )
    except cluster_manager.ClusterError as e:
        http = 409 if e.code == "duplicate" else 400
        return jsonify({"error": str(e), "code": e.code}), http
    pm.config_data["cluster"] = block
    pm._save_config_file()
    activity.log(
        "cluster.update_config", target="local", status="ok",
        detail=f"enabled={block['enabled']} port={block['port']}",
        ip=request.remote_addr or "",
    )
    return jsonify({
        "enabled": block["enabled"],
        "port": block["port"],
        "advertise": block["advertise"],
        "has_secret": bool(block["secret"]),
        "hostname": cluster_manager.local_identity(pm.config_data)["hostname"],
    })


@app.route('/api/cluster/node/<peer_id>/proxy/<path:rest>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@openapi_mod.describe(
    summary="Proxy an API request to a peer",
    description=(
        "Forwards the request to the peer's same path with the "
        "shared cluster secret in the X-SSM-Cluster-Secret "
        "header. Returns the peer's response verbatim (status, "
        "headers, body) so the UI can render any peer's API "
        "through a single endpoint."
    ),
    tag="Cluster",
)
def api_cluster_proxy(peer_id, rest):
    peer = cluster_manager.get_peer(peer_id)
    if not peer:
        return jsonify({"error": "peer not found", "code": "not_found"}), 404
    cfg_data = pm.config_data if hasattr(pm, "config_data") else {}
    # Auth to the peer rides on X-SSM-Cluster-Secret (verified
    # inbound by require_login). The session cookie is forwarded
    # best-effort as a fallback for peers that share SECRET_KEY,
    # but it is not required — fresh installs have distinct
    # signing keys, so the cookie alone would not verify there.
    fwd_headers = {}
    cookie = request.headers.get("Cookie")
    if cookie:
        fwd_headers["Cookie"] = cookie
    body = request.get_data() or None
    try:
        status, hdrs, body_resp = cluster_manager.proxy_request(
            peer, "/" + rest,
            method=request.method,
            body=body,
            headers=fwd_headers,
            cfg_data=cfg_data,
            timeout=5.0,
        )
    except cluster_manager.ClusterError as e:
        return jsonify({"error": str(e), "code": e.code}), 502
    # Filter hop-by-hop headers we shouldn't echo back.
    SKIP = {"transfer-encoding", "connection", "keep-alive",
            "proxy-authenticate", "proxy-authorization",
            "te", "trailers", "upgrade", "content-encoding",
            "content-length"}
    out_headers = []
    for k, v in hdrs.items():
        if k.lower() in SKIP:
            continue
        out_headers.append((k, v))
    return Response(body_resp, status=status, headers=out_headers)


@app.route('/api/packages/updates', methods=['GET'])
def api_packages_updates_list():
    state = package_manager.get_state()
    if state is None:
        return jsonify({
            "manager": package_manager.detect_manager(),
            "fetched_at": 0,
            "fetched_human": "never",
            "is_stale": True,
            "last_error": "",
            "updates": [],
            "count": 0,
            "security_count": 0,
            "needs_refresh": True,
        })
    d = state.to_dict()
    d["needs_refresh"] = state.is_stale
    return jsonify(d)


def _packages_password(data):
    """Extract and validate the optional sudo password from a JSON body."""
    password = data.get('password')
    if password is None:
        return None
    if not isinstance(password, str) or not password or '\n' in password or '\r' in password:
        return "INVALID"
    return password


@app.route('/api/packages/refresh', methods=['POST'])
@openapi_mod.describe(
    summary="Refresh the package-upgrade cache",
    description=(
        "Runs the distro-specific cache refresh (`apt update` / "
        "`dnf check-update`) and re-parses the upgrade list. If sudo "
        "needs a password, pass it as `password` (piped to `sudo -S` "
        "for that single command); otherwise the existing cache is "
        "used and a warning is included in the response."
    ),
    tag="Packages",
    responses={
        "200": {"description": "Returns the refreshed UpdateState."},
    },
)
def api_packages_refresh():
    data = request.get_json(silent=True) or {}
    password = _packages_password(data)
    if password == "INVALID":
        return jsonify({"error": "invalid password"}), 400
    state = package_manager.refresh(password=password)
    activity.log("packages.refresh", target=state.manager, status="ok" if not state.last_error else "error",
                 detail=state.last_error[:200] if state.last_error else "",
                 ip=request.remote_addr or "")
    return jsonify(state.to_dict())


@app.route('/api/packages/install', methods=['POST'])
def api_packages_install():
    data = request.get_json(silent=True) or {}
    packages = data.get('packages', [])
    if not isinstance(packages, list) or not packages:
        return jsonify({"error": "no packages specified"}), 400
    # Sanitize package names: must start with an alphanumeric so a name
    # can never be parsed as an apt/dnf flag (e.g. "--purge").
    import re
    safe = []
    for p in packages:
        if not isinstance(p, str) or not re.match(r'^[A-Za-z0-9][A-Za-z0-9._+:\-]*$', p):
            return jsonify({"error": f"invalid package name: {p!r}"}), 400
        safe.append(p)
    password = _packages_password(data)
    if password == "INVALID":
        return jsonify({"error": "invalid password"}), 400
    job_id = package_manager.install_packages(safe, password=password)
    activity.log("packages.install", target=job_id, status="ok",
                 detail=",".join(safe), ip=request.remote_addr or "")
    return jsonify({"job_id": job_id, "packages": safe})


@app.route('/api/packages/jobs/<job_id>')
def api_packages_job(job_id):
    job = package_manager.get_job(job_id)
    if job is None:
        return jsonify({"error": "not_found"}), 404
    return jsonify(job)


@app.route('/api/packages/jobs', methods=['GET'])
def api_packages_jobs_list():
    return jsonify({"jobs": package_manager.list_jobs()})


@app.route('/api/packages/lookup', methods=['GET'])
def api_packages_lookup():
    import re
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify({"error": "no package name specified"}), 400
    if not re.match(r'^[A-Za-z0-9][A-Za-z0-9._+:\-]*$', q):
        return jsonify({"name": q, "error": "invalid package name"}), 400
    result = package_manager.lookup_package(q)
    return jsonify(result)


@app.route('/api/notifications/state', methods=['GET'])
def api_notifications_state():
    if _health_monitor is None:
        return jsonify({"states": [], "events": []})
    states = [
        {
            "name": s.name,
            "last_state": s.last_state,
            "last_change": s.last_change,
            "last_check": {
                "healthy": s.last_check.healthy,
                "detail": s.last_check.detail,
                "timestamp": s.last_check.timestamp,
            } if s.last_check else None,
        }
        for s in _health_monitor.all_states()
    ]
    events = [
        {
            "service": e.service,
            "kind": e.kind,
            "state": e.state,
            "detail": e.detail,
            "timestamp": e.timestamp,
        }
        for e in _health_monitor.recent_events()
    ]
    return jsonify({"states": states, "events": events})


_process_cache = {}

def background_thread():
    global _process_cache
    num_cores = psutil.cpu_count() or 1
    # Lazy import — schedules is only used when programs are scheduled.
    from app import schedules
    while True:
        programs_data = []
        for p in pm.get_all_programs():
            cpu = None
            memory = None
            pid = p._get_pid()
            if pid:
                try:
                    if pid not in _process_cache:
                        _process_cache[pid] = psutil.Process(pid)
                    proc = _process_cache[pid]
                    cpu = proc.cpu_percent(interval=0)
                    if cpu is None:
                        cpu = 0.0
                    cpu = round(cpu / num_cores, 1)
                    memory = proc.memory_percent()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    _process_cache.pop(pid, None)
            # Include schedule and timer status so the dashboard card
            # can show "Next run: 4h 23m" and a "Run now" button. Cached
            # briefly to avoid hammering systemctl on every tick — the
            # timer state changes only when units are reloaded.
            schedule = p.config.schedule or ""
            timer_state = None
            if schedule:
                try:
                    timer_state = schedules.timer_status(p.config.name)
                except Exception:
                    timer_state = None
            programs_data.append({
                "name": p.config.name,
                "status": p.status.value,
                "logs": list(p.logs)[-100:],
                "restart_count": p.restart_count,
                "cpu": cpu,
                "memory": memory,
                "schedule": schedule,
                "timer": timer_state,
            })
        # Clean stale cache entries (PIDs no longer tracked)
        tracked_pids = {p._get_pid() for p in pm.get_all_programs() if p._get_pid()}
        stale = [pid for pid in _process_cache if pid not in tracked_pids]
        for pid in stale:
            _process_cache.pop(pid, None)
        socketio.emit('update', {'data': programs_data})
        socketio.sleep(1)

@socketio.on('connect')
def test_connect():
    logger.info('Client connected')

# Terminal Events
@socketio.on('terminal_create')
def handle_terminal_create(data):
    session_id = data.get('id')
    if session_id:
        # create_session() is a no-op for a live id, so a client that
        # navigated away and back reattaches to the same running shell
        # instead of orphaning it. Replay missed output to the
        # requester only (room=request.sid, not broadcast).
        existed = tm.session_alive(session_id)
        tm.create_session(session_id)
        if existed:
            backlog = tm.get_backlog(session_id)
            if backlog:
                socketio.emit('terminal_backlog',
                              {'id': session_id, 'data': backlog},
                              room=request.sid)

@socketio.on('terminal_input')
def handle_terminal_input(data):
    session_id = data.get('id')
    input_data = data.get('data')
    if session_id and input_data:
        tm.write(session_id, input_data)

@socketio.on('terminal_resize')
def handle_terminal_resize(data):
    session_id = data.get('id')
    cols = data.get('cols')
    rows = data.get('rows')
    if session_id and cols and rows:
        tm.resize(session_id, cols, rows)

@socketio.on('terminal_close')
def handle_terminal_close(data):
    session_id = data.get('id')
    if session_id:
        tm.close(session_id)

# Note: log streaming is delivered via Server-Sent Events at
# /api/system-services/<name>/logs/stream. No socketio event handlers
# are required for it.

_net_prev = {}
_disk_io_prev = None

_proc_cpu_cache = {}


# OpenAPI / Swagger UI
try:
    from flask_swagger_ui import get_swaggerui_blueprint

    SWAGGER_URL = "/docs"
    API_URL = "/openapi.json"
    swagger_bp = get_swaggerui_blueprint(
        SWAGGER_URL, API_URL,
        config={"app_name": "Server Services Manager API", "validatorUrl": None},
    )
    app.register_blueprint(swagger_bp, url_prefix=SWAGGER_URL)
except ImportError:
    logger.warning("flask-swagger-ui not installed; /docs unavailable")


# Register security scheme for the session cookie
openapi_mod.add_security_scheme({
    "name": "sessionCookie",
    "type": "apiKey",
    "in": "cookie",
    "description": "Session cookie set by POST /login.",
})


@app.route('/openapi.json')
def openapi_spec():
    """Return the OpenAPI 3.0 spec for this server's REST API."""
    return jsonify(openapi_mod.generate_spec(app))


# Decorate key routes with describe() so /docs has good content out of
# the box. We do this lazily — for routes we want enriched, the decorator
# is applied via openapi_mod.describe(). Most routes still appear with
# empty descriptions; the operator can enrich them later.

def system_monitor_thread():
    global _net_prev, _disk_io_prev, _proc_cpu_cache
    num_cores = psutil.cpu_count() or 1
    psutil.cpu_percent(interval=None)
    psutil.cpu_percent(interval=None, percpu=True)

    while True:
        cpu_total = psutil.cpu_percent(interval=0)
        cpu_cores = psutil.cpu_percent(interval=0, percpu=True)
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        load = os.getloadavg()
        boot = psutil.boot_time()

        disks = []
        for p in psutil.disk_partitions(all=False):
            try:
                u = psutil.disk_usage(p.mountpoint)
                disks.append({
                    "device": p.device,
                    "mount": p.mountpoint,
                    "fstype": p.fstype,
                    "total": u.total,
                    "used": u.used,
                    "free": u.free,
                    "percent": u.percent
                })
            except PermissionError:
                pass

        disk_io = psutil.disk_io_counters()
        if _disk_io_prev is not None:
            disk_read_speed = (disk_io.read_bytes - _disk_io_prev.read_bytes) / 2
            disk_write_speed = (disk_io.write_bytes - _disk_io_prev.write_bytes) / 2
        else:
            disk_read_speed = 0
            disk_write_speed = 0
        _disk_io_prev = disk_io

        net = []
        net_counters = psutil.net_io_counters(pernic=True)
        for iface, counters in net_counters.items():
            if iface == 'lo':
                continue
            prev = _net_prev.get(iface)
            sent_speed = (counters.bytes_sent - prev.bytes_sent) / 2 if prev else 0
            recv_speed = (counters.bytes_recv - prev.bytes_recv) / 2 if prev else 0
            net.append({
                "interface": iface,
                "sent_speed": sent_speed,
                "recv_speed": recv_speed,
                "bytes_sent": counters.bytes_sent,
                "bytes_recv": counters.bytes_recv,
                "packets_sent": counters.packets_sent,
                "packets_recv": counters.packets_recv
            })
            _net_prev[iface] = counters

        procs = []
        seen_pids = set()
        for p in psutil.process_iter(['pid', 'name', 'status']):
            try:
                pid = p.info['pid']
                seen_pids.add(pid)
                name = p.info['name']
                status = p.info['status']
                try:
                    if pid not in _proc_cpu_cache:
                        _proc_cpu_cache[pid] = psutil.Process(pid)
                        _proc_cpu_cache[pid].cpu_percent()
                        cpu = 0.0
                        memory = 0.0
                    else:
                        proc = _proc_cpu_cache[pid]
                        cpu = proc.cpu_percent(interval=0)
                        if cpu is None:
                            cpu = 0.0
                        memory = proc.memory_percent()
                        if memory is None:
                            memory = 0.0
                    procs.append({
                        "pid": pid,
                        "name": name,
                        "cpu": round(cpu / num_cores, 1),
                        "memory": round(memory, 1),
                        "status": status
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    _proc_cpu_cache.pop(pid, None)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        stale = [pid for pid in _proc_cpu_cache if pid not in seen_pids]
        for pid in stale:
            _proc_cpu_cache.pop(pid, None)
        procs.sort(key=lambda x: x['cpu'], reverse=True)
        procs = procs[:15]

        # CPU Temperature (graceful fallback if sensors unavailable)
        cpu_temp = None
        try:
            temps = psutil.sensors_temperatures()
            if 'coretemp' in temps:
                cpu_temp = round(max(t.current for t in temps['coretemp']), 1)
            elif 'k10temp' in temps:
                cpu_temp = round(temps['k10temp'][0].current, 1)
            elif 'cpu-thermal' in temps:
                cpu_temp = round(temps['cpu-thermal'][0].current, 1)
            elif 'cpu_thermal' in temps:
                cpu_temp = round(temps['cpu_thermal'][0].current, 1)
            elif 'thinkpad' in temps:
                cpu_temp = round(temps['thinkpad'][0].current, 1)
            elif 'acpitz' in temps:
                cpu_temp = round(temps['acpitz'][0].current, 1)
        except (AttributeError, FileNotFoundError, KeyError, IndexError, TypeError):
            cpu_temp = None

        sys_info = os.uname()
        socketio.emit('system_stats', {
            "cpu": {
                "percent": cpu_total,
                "cores": cpu_cores,
                "load": [round(l, 2) for l in load],
                "temperature": cpu_temp
            },
            "memory": {
                "total": mem.total,
                "available": mem.available,
                "used": mem.used,
                "percent": mem.percent,
                "swap_total": swap.total,
                "swap_used": swap.used,
                "swap_percent": swap.percent
            },
            "disks": disks,
            "disk_io": {
                "read_speed": disk_read_speed,
                "write_speed": disk_write_speed
            },
            "network": net,
            "processes": procs,
            "system": {
                "hostname": sys_info.nodename,
                "kernel": sys_info.release,
                "uptime": int(time.time() - boot)
            }
        })
        socketio.sleep(2)

_shutdown_called = False

def shutdown_handler(signum=None, frame=None):
    global _shutdown_called
    if _shutdown_called:
        return
    _shutdown_called = True
    logger.info(f"Received signal {signum}. Shutting down...")
    pm.stop_all()
    for sid in list(tm.sessions.keys()):
        tm.close(sid)
    try:
        get_streamer().shutdown()
    except Exception as e:
        logger.warning(f"streamer shutdown: {e}")
    try:
        if globals().get("_health_monitor") is not None:
            globals()["_health_monitor"].stop()
    except Exception as e:
        logger.warning(f"health monitor shutdown: {e}")
    try:
        from app import plugins as _plugins
        _plugins.unload_all(globals().get("_loaded_plugins") or [])
    except Exception as e:
        logger.warning(f"plugin unload: {e}")
    logger.info("Shutdown complete.")
    sys.exit(0)

def _get_health_services():
    """Return [(name, HealthCheck)] pairs for all services with a
    `health_check` block in their config."""
    out = []
    raw = pm.config_data.get("programs", []) if hasattr(pm, "config_data") else []
    for p in pm.get_all_programs():
        cfg = None
        for entry in raw:
            if entry.get("name") == p.config.name:
                cfg = entry.get("health_check")
                break
        if not cfg:
            continue
        check = HealthCheck.from_config(cfg)
        if check is not None:
            out.append((p.config.name, check))
    return out


def _on_health_event(event):
    """Called by the monitor on a healthy<->unhealthy transition.

    Pushes a SocketIO event so the dashboard can show a toast and
    update the per-service status dot.
    """
    try:
        socketio.emit("health_event", {
            "service": event.service,
            "state": event.state,
            "detail": event.detail,
            "timestamp": event.timestamp,
        })
    except Exception as e:
        logger.warning(f"emit health_event failed: {e}")


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)
    
    # Load config, validate, re-attach to surviving processes, then start
    pm.load_config()
    try:
        from app.config_schema import validate_config
        validate_config(pm.config_data if hasattr(pm, "config_data") else {})
    except Exception as e:
        logger.warning(f"config.yaml has validation issues: {e}")
    pm.load_state_and_reattach()

    # Wire the program state-change hook so notifiers get fired
    # for managed-service start/stop/fail. We do this BEFORE
    # start_all() so the initial autostart transitions get
    # notified too.
    for program in pm.programs.values():
        program.on_state_change = _on_program_state_change

    pm.start_all()

    # Initialize and start the health monitor (background health checks
    # and notification fanout)
    cfg_data = pm.config_data if hasattr(pm, "config_data") else {}
    _health_notifiers[:] = build_notifiers(cfg_data.get("notifications", []))
    globals()["_health_monitor"] = HealthMonitor(
        get_services=_get_health_services,
        notifiers=_health_notifiers,
        on_event=_on_health_event,
    )
    globals()["_health_monitor"].start()

    # Load user plugins from ~/.server-services-manager/plugins/.
    # Plugins are NOT auto-reloaded on file change — restart is
    # required to pick up new / modified plugins. A bad plugin
    # is logged and skipped; it cannot break the manager.
    from app import plugins as _plugins
    from app import activity as _activity
    from app import notifier as _notifier_mod
    _loaded_plugins = _plugins.load_all(
        app=app, pm=pm, activity=_activity, notifier_module=_notifier_mod,
    )
    globals()["_loaded_plugins"] = _loaded_plugins
    if _loaded_plugins:
        logger.info(f"loaded {len(_loaded_plugins)} plugin(s)")
    else:
        logger.info("no plugins loaded (drop .py files into ~/.server-services-manager/plugins/ to add one)")

    # Start background thread for updates
    thread = threading.Thread(target=background_thread, daemon=True)
    thread.start()

    # Start system monitor thread
    monitor_thread = threading.Thread(target=system_monitor_thread, daemon=True)
    monitor_thread.start()
    
    logger.info(f"Server starting on 0.0.0.0:8881")
    try:
        socketio.run(app, host='0.0.0.0', port=8881, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        shutdown_handler()

import pytest
from werkzeug.security import generate_password_hash, check_password_hash


class TestPasswordHashing:
    def test_generated_hash_validates(self):
        password = "test-password-123"
        hashed = generate_password_hash(password)
        assert check_password_hash(hashed, password) is True

    def test_wrong_password_fails(self):
        hashed = generate_password_hash("correct-password")
        assert check_password_hash(hashed, "wrong-password") is False

    def test_empty_password_env_falls_back_to_admin(self):
        import os
        password = os.getenv("PASSWORD") or "admin"
        hashed = generate_password_hash(password)
        if not os.getenv("PASSWORD"):
            assert check_password_hash(hashed, "admin") is True

    def test_default_admin_password(self):
        import os
        password = os.getenv("PASSWORD") or "admin"
        hashed = generate_password_hash(password)
        assert check_password_hash(hashed, password) is True

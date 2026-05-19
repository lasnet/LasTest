import tempfile
import unittest
from pathlib import Path

from app.core.settings import Settings
from app.services.auth import AuthStore, has_role, hash_password, verify_password


class AuthStoreTest(unittest.TestCase):
    def test_password_hash_and_verify(self):
        password_hash = hash_password("very-long-password")
        self.assertTrue(verify_password("very-long-password", password_hash))
        self.assertFalse(verify_password("wrong-password", password_hash))

    def test_user_session_and_audit_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(Path(tmp))
            store = AuthStore(settings)
            created = store.create_user("Admin@Example.com", "very-long-password", "admin")
            self.assertEqual(created["username"], "admin@example.com")
            self.assertTrue(has_role(created["role"], "analyst"))

            user = store.authenticate("admin@example.com", "very-long-password")
            self.assertIsNotNone(user)
            session = store.create_session(user, ip_address="127.0.0.1", user_agent="test")
            validated = store.validate_token(session["access_token"])
            self.assertEqual(validated["username"], "admin@example.com")

            store.audit(
                actor=validated,
                action="project.create",
                resource_type="project",
                resource_id="example.com",
                details={"client": "test"},
            )
            events = store.list_audit_events()
            self.assertEqual(events[0]["action"], "project.create")
            self.assertEqual(events[0]["actor_username"], "admin@example.com")

            with self.assertRaises(ValueError):
                store.update_user("admin@example.com", role="viewer")

            store.revoke_session(validated["session_id"])
            with self.assertRaises(ValueError):
                store.validate_token(session["access_token"])

    def test_invalid_bootstrap_password_does_not_break_startup(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(Path(tmp))
            settings = Settings(
                projects_dir=settings.projects_dir,
                data_dir=settings.data_dir,
                logs_dir=settings.logs_dir,
                database_url=settings.database_url,
                auth_jwt_secret=settings.auth_jwt_secret,
                auth_bootstrap_admin_password="short",
            )
            store = AuthStore(settings)
            store.bootstrap_admin_from_env()

            self.assertEqual(store.user_count(), 0)
            self.assertTrue(store.setup_required())
            self.assertEqual(store.list_audit_events()[0]["status"], "failed")

    @staticmethod
    def _settings(root: Path) -> Settings:
        return Settings(
            projects_dir=root / "projects",
            data_dir=root / "data",
            logs_dir=root / "logs",
            database_url=f"sqlite:///{root / 'data' / 'auth.sqlite3'}",
            auth_jwt_secret="test-secret",
        )


if __name__ == "__main__":
    unittest.main()

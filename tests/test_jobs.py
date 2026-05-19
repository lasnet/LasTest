import tempfile
import unittest
from pathlib import Path

from app.core.settings import Settings
from app.services.jobs import JobStore


class JobStoreTest(unittest.TestCase):
    def test_create_acquire_finish_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = Settings(
                projects_dir=root / "projects",
                data_dir=root / "data",
                logs_dir=root / "logs",
                database_url=f"sqlite:///{root / 'data' / 'jobs.sqlite3'}",
            )
            store = JobStore(settings)

            created = store.create_job("client-01", "subfinder", {"domain_mode": "first"})
            self.assertEqual(created["status"], "queued")

            acquired = store.acquire_next_job()
            self.assertIsNotNone(acquired)
            self.assertEqual(acquired["id"], created["id"])
            self.assertEqual(acquired["status"], "running")

            finished = store.finish_job(created["id"], "succeeded", {"found": 3})
            self.assertEqual(finished["status"], "succeeded")
            self.assertEqual(finished["result"]["found"], 3)

            self.assertIsNone(store.acquire_next_job())


if __name__ == "__main__":
    unittest.main()


import json
import tempfile
import unittest
from pathlib import Path

from app.core.settings import Settings
from app.services.dashboard import build_project_dashboard
from app.services.jobs import JobStore
from app.services.projects import create_project, project_path, update_scope
from app.services.tool_registry import available_tasks, validate_task_type


class DashboardTest(unittest.TestCase):
    def test_dashboard_reads_recon_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = self._settings(root)
            create_project("example.com", settings=settings)
            update_scope(
                "example.com",
                domains=["example.com"],
                ips=["203.0.113.10"],
                exclusions=["legacy.example.com"],
                replace=True,
                settings=settings,
            )
            project = project_path("example.com", settings)
            self._write_json(
                project / "recon" / "subdomains" / "subdomains.json",
                {"all": ["www.example.com", "api.example.com"]},
            )
            self._write_json(
                project / "recon" / "dns_records" / "dns_records.json",
                {
                    "hosts": [
                        {"host": "example.com", "records": {"A": ["93.184.216.34"]}},
                        {"host": "www.example.com", "records": {"CNAME": ["example.com"]}},
                    ]
                },
            )
            self._write_json(
                project / "recon" / "httpx" / "alive_hosts.json",
                {
                    "hosts": [
                        {
                            "url": "https://www.example.com",
                            "host": "www.example.com",
                            "port": 443,
                            "status_code": 200,
                            "tech": ["nginx"],
                        }
                    ]
                },
            )
            self._write_json(
                project / "web" / "nuclei" / "findings.json",
                {
                    "findings": [
                        {"name": "TLS issue", "severity": "high", "host": "https://www.example.com"},
                        {"name": "Info leak", "severity": "info", "host": "https://www.example.com"},
                    ]
                },
            )

            store = JobStore(settings)
            job = store.create_job("example.com", "dns-records", {})
            store.finish_job(job["id"], "succeeded", {"records": 2})

            dashboard = build_project_dashboard("example.com", settings, store)

            self.assertEqual(dashboard["metrics"]["domains"], 1)
            self.assertEqual(dashboard["metrics"]["subdomains"], 2)
            self.assertEqual(dashboard["metrics"]["dns_hosts"], 2)
            self.assertEqual(dashboard["metrics"]["alive_hosts"], 1)
            self.assertEqual(dashboard["metrics"]["open_ports"], 1)
            self.assertEqual(dashboard["metrics"]["findings"], 2)
            self.assertEqual(dashboard["severity_counts"]["high"], 1)
            self.assertEqual(dashboard["activity"][0]["task"], "dns-records")

    def test_dns_records_task_is_registered_without_external_binary(self):
        self.assertEqual(validate_task_type("dns-records"), "dns-records")
        specs = {item["task_type"]: item for item in available_tasks()}
        self.assertIn("dns-records", specs)
        self.assertEqual(specs["dns-records"]["required_tools"], [])
        self.assertTrue(specs["dns-records"]["available"])

    @staticmethod
    def _settings(root: Path) -> Settings:
        return Settings(
            projects_dir=root / "projects",
            data_dir=root / "data",
            logs_dir=root / "logs",
            database_url=f"sqlite:///{root / 'data' / 'jobs.sqlite3'}",
        )

    @staticmethod
    def _write_json(path: Path, data: dict):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()

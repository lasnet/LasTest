import unittest

from app.services.validation import (
    normalize_domain,
    normalize_domains,
    normalize_ip,
    normalize_scope_exclusions,
    normalize_severities,
    validate_project_name,
)


class ValidationTest(unittest.TestCase):
    def test_validate_project_name_accepts_safe_names(self):
        self.assertEqual(validate_project_name("client-01"), "client-01")
        self.assertEqual(validate_project_name("ACME_Test.2026"), "ACME_Test.2026")

    def test_validate_project_name_rejects_path_segments(self):
        with self.assertRaises(ValueError):
            validate_project_name("../secret")

    def test_normalize_domain(self):
        self.assertEqual(normalize_domain("Example.COM."), "example.com")
        self.assertEqual(normalize_domains(["B.example.com", "b.example.com"]), ["b.example.com"])

    def test_normalize_ip(self):
        self.assertEqual(normalize_ip("127.0.0.1"), "127.0.0.1")
        with self.assertRaises(ValueError):
            normalize_ip("999.1.1.1")

    def test_normalize_scope_exclusions(self):
        self.assertEqual(
            normalize_scope_exclusions(["Legacy.EXAMPLE.com.", "10.0.0.1", "10.0.0.0/8"]),
            ["10.0.0.0/8", "10.0.0.1", "legacy.example.com"],
        )
        with self.assertRaises(ValueError):
            normalize_scope_exclusions(["not a valid exclusion"])

    def test_normalize_severities(self):
        self.assertEqual(normalize_severities("High, critical, high"), "high,critical")
        with self.assertRaises(ValueError):
            normalize_severities("critical,root")


if __name__ == "__main__":
    unittest.main()

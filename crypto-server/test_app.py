"""Small authorization regression tests for the KMS API.

Run with: python -m unittest discover -s crypto-server -p 'test_*.py'
"""
import os
import tempfile
import unittest
from pathlib import Path

_TEST_DIR = tempfile.TemporaryDirectory(prefix="city-system-kms-test-")
os.environ["DEVICE_API_TOKEN"] = "device-test-token-" + ("d" * 40)
os.environ["ADMIN_API_TOKEN"] = "admin-test-token-" + ("a" * 40)
os.environ["DB_PATH"] = str(Path(_TEST_DIR.name) / "test-keys.db")
os.environ["NETWORK_CONFIG_JSON"] = '{"ELEVATOR_NET":["18","22"]}'

import app as kms  # noqa: E402


class KmsAuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        kms.init_db()
        for network in kms.NETWORK_CONFIG:
            kms.generate_and_store_key(network)

    def test_device_token_can_fetch_authorized_network_key(self):
        result = kms.get_network_key(
            "ELEVATOR_NET",
            "Bearer " + os.environ["DEVICE_API_TOKEN"],
            "CC-Tweaked-Node/18",
        )
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["network"], "ELEVATOR_NET")
        self.assertGreaterEqual(len(result["key"]), 32)

    def test_admin_token_cannot_be_used_for_device_key_endpoint(self):
        with self.assertRaises(kms.HTTPException) as ctx:
            kms.get_network_key(
                "ELEVATOR_NET",
                "Bearer " + os.environ["ADMIN_API_TOKEN"],
                "CC-Tweaked-Node/18",
            )
        self.assertEqual(ctx.exception.status_code, 401)

    def test_device_token_cannot_list_devices(self):
        with self.assertRaises(kms.HTTPException) as ctx:
            kms.list_devices("ELEVATOR_NET", "Bearer " + os.environ["DEVICE_API_TOKEN"])
        self.assertEqual(ctx.exception.status_code, 401)

    def test_admin_token_can_list_devices(self):
        result = kms.list_devices(
            "ELEVATOR_NET", "Bearer " + os.environ["ADMIN_API_TOKEN"]
        )
        self.assertEqual(result["authorized_devices"], ["18", "22"])

    def test_unenrolled_device_is_denied(self):
        with self.assertRaises(kms.HTTPException) as ctx:
            kms.get_network_key(
                "ELEVATOR_NET",
                "Bearer " + os.environ["DEVICE_API_TOKEN"],
                "CC-Tweaked-Node/999",
            )
        self.assertEqual(ctx.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()

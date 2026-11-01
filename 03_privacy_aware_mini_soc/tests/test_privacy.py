
import unittest

from detector import mask_ip, mask_username


class TestPrivacyMasking(unittest.TestCase):

    def test_ipv4_masking(self):
        self.assertEqual(
            mask_ip("203.0.113.25"),
            "203.0.113.xxx"
        )

    def test_ipv6_masking(self):
        self.assertEqual(
            mask_ip("2001:db8::1"),
            "2001:0db8:0000:****"
        )

    def test_invalid_ip(self):
        self.assertEqual(
            mask_ip("invalid-ip"),
            "REDACTED"
        )

    def test_username_masking(self):
        self.assertEqual(
            mask_username("admin"),
            "a***"
        )

    def test_empty_username(self):
        self.assertEqual(
            mask_username(""),
            "REDACTED"
        )


if __name__ == "__main__":
    unittest.main()

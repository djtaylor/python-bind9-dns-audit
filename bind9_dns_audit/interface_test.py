import unittest

from bind9_dns_audit.common_test import private_key, example_args

from bind9_dns_audit.interface import BIND9_DNS_Audit_Interface

class BIND9_DNS_Audit_Interface_Test(unittest.TestCase):
    """Tests for `interface.py`."""

    def test_interface(self):
        """Test running the audit against a Docker container"""
        interface = BIND9_DNS_Audit_Interface(args=example_args['pp_list'])

        # Script should run then exit
        with self.assertRaises(SystemExit) as cm:
            interface.run()

        # Should exit with 0
        self.assertEqual(cm.exception.code, 0)

if __name__ == '__main__':
    unittest.main()

import unittest

from bind9_dns_audit.interface import BIND9_DNS_Audit_Interface

class BIND9_DNS_Audit_Interface_Test(unittest.TestCase):
    """Tests for `interface.py`."""

    test_args = [
        '127.0.0.1',
        '--ssh-user',
        'root',
        '--ssh-port',
        '60022',
        '--ssh-key',
        'docker_test_files/id_rsa_test'
    ]

    def test_interface(self):
        """Test running the audit against a Docker container"""
        interface = BIND9_DNS_Audit_Interface(args=self.test_args)

        # Script should run then exit
        with self.assertRaises(SystemExit) as cm:
            interface.run()

        # Should exit with 0
        self.assertEqual(cm.exception.code, 0)

if __name__ == '__main__':
    unittest.main()

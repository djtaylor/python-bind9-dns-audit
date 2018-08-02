import unittest
from mock import patch

from bind9_dns_audit.interface import BIND9_DNS_Audit_Interface

class BIND9_DNS_Audit_Interface_Test(unittest.TestCase):
    """Tests for `interface.py`."""

    test_private_key = 'docker_test_files/id_rsa_test'

    test_args = [
        '127.0.0.1',
        '--ssh-user',
        'root',
        '--ssh-port',
        '60022',
        '--ssh-key',
        test_private_key,
        '--check-tcp-ports',
        '22,443',
        '--check-tcp-ports-timeout',
        '1',
        '--csv',
        '--debug'
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

import unittest
from six import string_types

from bind9_dns_audit.common import BIND9_DNS_Audit_Common

class BIND9_DNS_Audit_Args_Common(unittest.TestCase):
    """Tests for `common.py`."""

    bind9_common = BIND9_DNS_Audit_Common()

    def test_process_str(self):
        """ Test the _parse_str method for Py2/3 string compatibility """
        processed_str = self.bind9_common._process_str('test str')
        self.assertIsInstance(processed_str, string_types)

    def test_write_stdout(self):
        """ Test the write_stdout method """
        self.assertTrue(self.bind9_common.write_stdout('Testing write_stdout'))

    def test_write_stderr(self):
        """ Test the write_stderr method """
        self.assertTrue(self.bind9_common.write_stderr('Testing write_stderr'))

import unittest

from bind9_dns_audit.common_test import hide_stderr, example_args

from bind9_dns_audit.args import BIND9_DNS_Audit_Args

class BIND9_DNS_Audit_Args_Test(unittest.TestCase):
    """Tests for `args.py`."""

    def test_args_parse(self):
        """Test creating an arguments object directly with `parse`"""
        args = BIND9_DNS_Audit_Args()
        self.assertTrue(args.parse(example_args['pp_list']))

    def test_args_create(self):
        """Test creating args by calling the `construct` classmethod"""
        args = BIND9_DNS_Audit_Args()
        self.assertIsInstance(args.construct(example_args['csv_list']), tuple)

    def test_args_version(self):
        """Test the command to return installed program version"""
        args = BIND9_DNS_Audit_Args()

        with self.assertRaises(SystemExit) as cm:
            args.construct(['--version'])

    def test_args_invalid_command(self):
        """Test args with an invalid command, should fail"""
        args = BIND9_DNS_Audit_Args()

        # This should fail
        with hide_stderr():
            with self.assertRaises(SystemExit):
                args.construct(example_args['invalid'])

if __name__ == '__main__':
    unittest.main()

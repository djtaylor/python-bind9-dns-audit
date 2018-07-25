import sys
import unittest
import argparse
import contextlib
from copy import deepcopy

import bind9_dns_audit.args as bind9_dns_audit_args

class BIND9_DNS_Audit_Args_Test(unittest.TestCase):
    """Tests for `args.py`."""

    example_args = [
        '127.0.0.1',
        '--ssh-user',
        'test',
        '--ssh-port',
        '22',
        '--ssh-passwd',
        '--zones-config',
        '/etc/bind/named.conf.local',
        '--report-noping',
        '--report-file',
        '/tmp/test.txt']

    def test_args_parse(self):
        """Test creating an arguments object directly with `parse`"""
        args = bind9_dns_audit_args.BIND9_DNS_Audit_Args()
        self.assertTrue(args.parse(self.example_args))

    def test_args_create(self):
        """Test creating args by calling the `construct` classmethod"""
        args = bind9_dns_audit_args.BIND9_DNS_Audit_Args()
        self.assertIsInstance(args.construct(self.example_args), tuple)

    def test_args_invalid_command(self):
        """Test args with an invalid command, should fail"""
        args = bind9_dns_audit_args.BIND9_DNS_Audit_Args()

        # Make an invalid args object
        invalid_args = deepcopy(self.example_args)
        invalid_args.append('--unsupported-flag')

        # Supress stderr, should fail
        @contextlib.contextmanager
        def hide_stderr():
            savestderr = sys.stderr
            class Devnull(object):
                def write(self, _): pass
                def flush(self): pass
            sys.stderr = Devnull()
            try:
                yield
            finally:
                sys.stderr = savestderr

        # This should fail
        with hide_stderr():
            with self.assertRaises(SystemExit):
                args.construct(invalid_args)

if __name__ == '__main__':
    unittest.main()

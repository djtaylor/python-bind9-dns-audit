from __future__ import unicode_literals
import sys
import json
import unittest
from six import string_types
from contextlib import contextmanager

from bind9_dns_audit.common import BIND9_DNS_Audit_Common
from bind9_dns_audit.args import BIND9_DNS_Audit_Args

# Private key for Docker testing
private_key = 'docker_test_files/id_rsa_test'

# Base test arguments
_base_args = [
    '127.0.0.1',
    '--ssh-port',
    '60022',
    '--ssh-user',
    'root',
    '--check-tcp-ports',
    '22,80,443',
    '--check-tcp-ports-timeout',
    '1',
    '--ssh-key',
    'docker_test_files/id_rsa_test',
    '--debug']

# Example arguments for running tests
example_args = {
    'csv': BIND9_DNS_Audit_Args.construct(_base_args + ['--csv']),
    'csv_list': _base_args + ['--csv'],
    'pp': BIND9_DNS_Audit_Args.construct(_base_args + ['--pretty-print']),
    'pp_list': _base_args + ['--pretty-print'],
    'json': BIND9_DNS_Audit_Args.construct(_base_args),
    'invalid': _base_args + ['--invalid-argument']
}

# Example constructed zones data
def get_example_zones():
    zone_data = None
    with open('docker_test_files/example_zones.json', 'r') as f:
        zone_data = json.loads(f.read())
    return zone_data

# Supress stderr
@contextmanager
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

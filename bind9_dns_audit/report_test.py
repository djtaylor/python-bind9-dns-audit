import unittest
from six import string_types

from bind9_dns_audit.common_test import example_args, get_example_zones

from bind9_dns_audit.interface import BIND9_DNS_Audit_Report

class BIND9_DNS_Audit_Report_Test(unittest.TestCase):
    """Tests for `report.py`."""

    def test_csv_report(self):
        """Test the method to construct a CSV report"""
        report = BIND9_DNS_Audit_Report.csv(example_args['csv'], get_example_zones())
        self.assertIsInstance(report, string_types)

    def test_pp_report(self):
        """Test the method to construct a pretty-print report"""
        report = BIND9_DNS_Audit_Report.pretty_print(example_args['pp'], get_example_zones(), 20)
        self.assertIsInstance(report, string_types)

    def test_json_report(self):
        """Test the method to construct a JSON report"""
        report = BIND9_DNS_Audit_Report.json(example_args['json'])
        self.assertIsInstance(report, string_types)

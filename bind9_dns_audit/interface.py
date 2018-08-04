from __future__ import unicode_literals
from time import time
from sys import exit

from bind9_dns_audit.args import BIND9_DNS_Audit_Args
from bind9_dns_audit.common import BIND9_DNS_Audit_Common
from bind9_dns_audit.report import BIND9_DNS_Audit_Report
from bind9_dns_audit.connection import BIND9_DNS_Audit_Connection
from bind9_dns_audit.zones import BIND9_DNS_Audit_Zones

class BIND9_DNS_Audit_Interface(BIND9_DNS_Audit_Common):
    """
    Class for handling interactions with the CLI client.
    """
    def __init__(self, args=None):
        self.args = BIND9_DNS_Audit_Args.construct(args)
        super(BIND9_DNS_Audit_Interface, self).__init__(debug=self.args.debug)

        # Define an SSH connection
        self.connection = BIND9_DNS_Audit_Connection(
            self.args.connection.server,
            self.args.connection.ssh_user,
            ssh_port=self.args.connection.ssh_port,
            ssh_key=self.args.connection.ssh_key)

        self.zones = BIND9_DNS_Audit_Zones

    def run(self):
        """
        Run the client with the given arguments.
        """
        audit_start = time()
        self.connection.ssh_open()
        zones = self.zones.from_remote(self.connection, self.args.zones_config,
            tcp_ports=self.args.check_tcp_ports,
            tcp_ports_timeout=self.args.check_tcp_ports_timeout)

        # Parse zones and zone records
        zones.parse()
        zones.get_zone_records()

        # Run connectivity checks
        zones.check_connectivity()

        audit_end = time()
        audit_time_elapsed = audit_end - audit_start

        # Report string
        report_str = None

        # Pretty print a report for CLI viewing
        if self.args.pretty_print:
            report_str = BIND9_DNS_Audit_Report.pretty_print(self.args, zones.get_data(), audit_time_elapsed)

        # Output as CSV
        elif self.args.csv:
            report_str = BIND9_DNS_Audit_Report.csv(self.args, zones.get_data())

        # Dump full JSON output
        else:
            report_str = BIND9_DNS_Audit_Report.json(zones.get_data())

        # Dump the report
        self.write_stdout(report_str, prefix=False)
        exit(0)

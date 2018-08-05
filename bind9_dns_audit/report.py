from __future__ import unicode_literals
import json
from six import iteritems

from bind9_dns_audit.common import BIND9_DNS_Audit_Common

class BIND9_DNS_Audit_Report(BIND9_DNS_Audit_Common):
    """
    A class object for formatting and returning DNS audit reports.
    """
    def __init__(self, args, zones, time_elapsed=None):
        self.args  = args
        self.zones = zones
        super(BIND9_DNS_Audit_Report, self).__init__(debug=self.args.debug)

        # How long did the report take
        self.time_elapsed = time_elapsed

    def _to_csv(self):
        """
        Format a CSV report.
        """
        csv_output = ''
        check_tcp_headers = ''
        tcp_ports_args_list = self._process_str(self.args.check_tcp_ports).split(',')
        if self.args.check_tcp_ports:
            for tcp_port in tcp_ports_args_list:
                check_tcp_headers+=',tcp_port_{}'.format(tcp_port)
        csv_output+='zone,record_name,record_ipaddr,ping_response{}\n'.format(check_tcp_headers)

        # Construct by zone
        for zone in self.zones:
            for record in zone['records']:
                record_csv_str = '{},{},{},{}'.format(
                    zone['name'],
                    record['dnsname'],
                    record['ipaddr'],
                    'yes' if record['ping_response'] else 'no'
                )

                if record['tcp_ports']:
                    for tcp_port in tcp_ports_args_list:
                        record_csv_str+=',{}'.format('open' if record['tcp_ports'][tcp_port] else 'closed')
                csv_output+='{}\n'.format(record_csv_str)

        # Return the report
        return csv_output

    def _to_pretty_print(self):
        """
        Format a pretty-print report.
        """
        report_str = ''
        report_str+='\nAudit Complete: {}\n'.format(self.args.connection.server)
        report_str+='{}\n'.format('-' * 40)
        report_str+='> time elapsed: {}s\n\n'.format(self.time_elapsed)

        # Construct by zone
        for zone in self.zones:

            # Total records / total no ping responses
            total_records           = len(zone['records'])
            total_no_ping_responses = len([ar for ar in zone['records'] if not ar['ping_response']])

            # Format the report for this zone
            report_str+='Forward Zone Report: {}, {} total records\n'.format(zone['name'], total_records)
            report_str+='> {} records responded to ICMP/ping\n'.format(total_records - total_no_ping_responses)
            report_str+='> {} records DID NOT response to ICMP/ping\n'.format(total_no_ping_responses)
            report_str+='> Zone Record Audit Summary:\n\n'
            for record in zone['records']:
                report_str+='  {} [{}]\n'.format(record['dnsname'], record['ipaddr'])
                report_str+='  > ping_response: {}\n'.format('yes' if record['ping_response'] else 'no')
                if record['tcp_ports']:
                    open_tcp_ports   = [tcp_port for tcp_port,port_open in iteritems(record['tcp_ports']) if port_open]
                    closed_tcp_ports = [tcp_port for tcp_port,port_open in iteritems(record['tcp_ports']) if not port_open]
                    report_str+='  > Open TCP Ports: {}\n'.format(','.join(open_tcp_ports))
                    report_str+='  > Closed TCP Ports: {}\n'.format(','.join(closed_tcp_ports))
                report_str+='\n'

            # Records that did not respond to any checks
            no_responses = []
            for record in zone['records']:
                tcp_ports_open = any([tcp_port for tcp_port,port_open in iteritems(record['tcp_ports']) if port_open])
                if not record['ping_response'] and not tcp_ports_open:
                    no_responses.append(record)

            # Display no responses
            no_response_checks = 'ping'
            if self.args.check_tcp_ports:
                no_response_checks+='/tcp_ports[{}],timeout={}s'.format(self.args.check_tcp_ports, self.args.check_tcp_ports_timeout)
            if no_responses:
                report_str+='  A Records w/ No Response ({}):\n'.format(no_response_checks)
                for no_response in no_responses:
                    report_str+='  > {} [{}]\n'.format(no_response['dnsname'], no_response['ipaddr'])
                report_str+='\n'

        # Return the report
        return report_str

    @classmethod
    def json(cls, zones):
        """
        Return formatted JSON output of zones object.
        """
        return json.dumps(zones, indent=2)

    @classmethod
    def pretty_print(cls, args, zones, time_elapsed):
        """
        Dump an audit to CLI for human readable viewing.
        """
        print(zones)
        report = cls(args, zones, time_elapsed=time_elapsed)
        return report._to_pretty_print()

    @classmethod
    def csv(cls, args, zones):
        """
        Dump an audit to CSV.
        """
        print(zones)
        report = cls(args, zones)
        return report._to_csv()

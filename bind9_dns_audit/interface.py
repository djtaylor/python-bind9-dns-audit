from __future__ import unicode_literals
from builtins import str
import re
import json
import socket
import threading
from time import time
from six import iteritems
from getpass import getpass
from subprocess import Popen, PIPE
from sys import stderr,exit

from bind9_dns_audit.args import BIND9_DNS_Audit_Args
from bind9_dns_audit.common import BIND9_DNS_Audit_Common
from bind9_dns_audit.connection import BIND9_DNS_Audit_Connection

class BIND9_DNS_Audit_Interface(BIND9_DNS_Audit_Common):
    """
    Class for handling interactions with the CLI client.
    """
    def __init__(self, args=None):
        self.args = BIND9_DNS_Audit_Args.construct(args)
        super(BIND9_DNS_Audit_Interface, self).__init__(debug=self.args.debug)

        # Open an SSH connection
        self.connection = BIND9_DNS_Audit_Connection(
            self.args.connection.server,
            self.args.connection.ssh_user,
            ssh_port=self.args.connection.ssh_port,
            ssh_key=self.args.connection.ssh_key)

        # Zones objects
        self.zones = {
            'forward': {},
            'reverse': {}
        }

        # Zone record threads
        self.zone_record_threads = []

    def _get_zone_records(self, zone_name, zone_type):
        """
        Get zone records for a zone
        """
        if self.zones[zone_type][zone_name]['type'] == 'forward':
            self.write_stdout('Zone "{}" is a forward zone, skipping...'.format(zone_name))
            return True
        self.write_stdout('Retrieving DNS records for: {}'.format(zone_name))
        zone_config_file = self.zones[zone_type][zone_name]['config']
        zone_config = self.connection.get_file(zone_config_file)
        record_is_a = re.compile(r'^[a-zA-Z0-9.-]+\.\s?[0-9]*\s+IN\s+A')

        # Extract zone A records
        for line in zone_config.split(b'\n'):
            if record_is_a.match(line.decode()):
                formatted_line = re.sub(b' +', b' ', line.replace(b'\t', b' '))

                # Get the A record DNS name and associated IP address
                a_record_dnsname = self._process_str(formatted_line.split(b' ')[0][:-1])
                a_record_ipaddr  = self._process_str(formatted_line.split(b' ')[-1])

                # Store the record
                self.write_stdout('Found A record: {} [{}]'.format(a_record_dnsname, a_record_ipaddr), debug=True)
                self.zones[zone_type][zone_name]['records'].append({
                    'dnsname': a_record_dnsname,
                    'ipaddr': a_record_ipaddr,
                    'ping_response': None,
                    'tcp_ports': {}
                })

    def _get_zones(self):
        """
        Construct a list of zones.
        """
        self.write_stdout('Retrieving zone configurations...')
        zones_config = self.connection.get_file(self.args.zones_config)
        zone_name_regex = re.compile(r'^zone[ ]\"([^\"]+)\".*$')
        zone_type_regex = re.compile(r'^[ \t]+type[ ]([a-z]+);$')
        zone_file_regex = re.compile(r'^[ \t]+file[ ]\"([^\"]+)\";$')
        zone_is_reverse = re.compile(r'^[0-9]+\..*$')

        # Scan zones
        current_zone = None
        zone_type = None
        for line in zones_config.split(b'\n'):
            if line.startswith(b'zone'):
                zone_name = zone_name_regex.sub(r'\g<1>', line.decode())
                current_zone = zone_name

                # Forward zones
                if not zone_is_reverse.match(zone_name):
                    self.zones['forward'][zone_name] = {'records': []}
                    zone_type = 'forward'
                else:
                    # Reverse zones
                    self.zones['reverse'][zone_name] = {'records': []}
                    zone_type = 'reverse'
                self.write_stdout('Found zone: {}, type={}'.format(zone_name, zone_type))

            # Zone type (master/slave)
            if zone_type_regex.match(line.decode()):
                self.zones[zone_type][current_zone]['type'] = zone_type_regex.sub('\g<1>', line.decode())

            # Zone config
            if zone_file_regex.match(line.decode()):
                self.zones[zone_type][current_zone]['config'] = zone_file_regex.sub(r'\g<1>', line.decode())

        # Get zone records (only forward for now)
        for zone_name, zone_attrs in iteritems(self.zones['forward']):
            self._get_zone_records(zone_name, 'forward')
            total_zone_records = len(self.zones['forward'][zone_name]['records'])
            self.write_stdout('Finished retrieving zone records for [{}], {} total records'.format(zone_name, total_zone_records))

    def _check_tcp_port(self, a_record, tcp_port):
        """
        Check to see if a particular TCP port is open.
        """
        dnsname    = self._process_str(a_record['dnsname'])
        ipaddr     = self._process_str(a_record['ipaddr'])
        record_str = '{0} [{1}]'.format(dnsname, ipaddr)
        timeout    = self.args.check_tcp_ports_timeout

        # Check if the port is open
        self.write_stdout('Checking TCP port {} connectivity for: {}, timeout={}s...'.format(tcp_port, record_str, str(timeout)), debug=True)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(int(timeout))
            s.connect((ipaddr, int(tcp_port)))
            s.shutdown(2)
            s.close()
            self.write_stdout('TCP port for {} is OPEN'.format(record_str), debug=True)
            a_record['tcp_ports'][tcp_port] = True
        except:
            self.write_stdout('TCP port for {} is CLOSED'.format(record_str), debug=True)
            a_record['tcp_ports'][tcp_port] = False

    def _check_zone_record(self, zone_name, zone_type, a_record):
        """
        Thread worker for checking ICMP connectivity to a host.
        """
        dnsname    = self._process_str(a_record['dnsname'])
        ipaddr     = self._process_str(a_record['ipaddr'])
        record_str = '{} [{}]'.format(dnsname, ipaddr)

        # Run basic ping check
        self.write_stdout('Checking ICMP connectivity for: {}...'.format(record_str), debug=True)
        proc = Popen(['/usr/bin/env', 'ping', '-c', '3', dnsname], stdout=PIPE, stderr=PIPE)
        proc.communicate()

        # No response to ping, can possibly be deleted
        if not proc.returncode == 0:
            self.write_stdout('A Record({}): no ping response...'.format(record_str), debug=True)
            a_record['ping_response'] = False

        # Responds to ping
        else:
            self.write_stdout('A Record({}): ping response OK...'.format(record_str), debug=True)
            a_record['ping_response'] = True

        # If checking TCP ports
        if self.args.check_tcp_ports:
            check_tcp_ports = self.args.check_tcp_ports.split(',')
            for tcp_port in check_tcp_ports:
                self._check_tcp_port(a_record, tcp_port)

    def _check_zone_connectivity(self, zone_name, zone_type, zone_records):
        """
        Method for checking connectivity of all zone records.
        """
        check_tcp_ports_str = '' if not self.args.check_tcp_ports else '/tcp_ports:{}:timeout={}s'.format(
            self.args.check_tcp_ports,
            self.args.check_tcp_ports_timeout)
        checks_str = 'icmp_ping{}'.format(check_tcp_ports_str)

        self.write_stdout('Running checks for A records in zone [{}]: {}'.format(zone_name, checks_str))
        for a_record in zone_records:
            t = threading.Thread(target=self._check_zone_record, args=(zone_name, zone_type, a_record,))
            self.zone_record_threads.append(t)
            t.start()

        # Wait for zone record connectivity tests to complete
        for t in self.zone_record_threads:
            t.join()

    def _check_zones(self):
        """
        Run basic connectivity tests for all records.
        """

        # Only do forward zones
        for zone_name, zone_attrs in iteritems(self.zones['forward']):
            self._check_zone_connectivity(zone_name, 'forward', zone_attrs['records'])

    def run(self):
        """
        Run the client with the given arguments.
        """
        audit_start = time()
        self.connection.ssh_open()
        self._get_zones()
        self._check_zones()
        audit_end = time()
        audit_time_elapsed = audit_end - audit_start

        report_str = ""

        # Pretty print a report for CLI viewing
        if self.args.pretty_print:
            report_str+='\nAudit Complete: {}\n'.format(self.args.connection.server)
            report_str+='{}\n'.format('-' * 40)
            report_str+='> time elapsed: {}s\n\n'.format(audit_time_elapsed)

            # Construct by zone
            for zone_type, zone_objects in iteritems(self.zones):

                # Forward zones
                if zone_type == 'forward':
                    for zone_name, zone_attrs in iteritems(zone_objects):

                        # Total records / total no ping responses
                        total_records           = len(zone_attrs['records'])
                        total_no_ping_responses = len([ar for ar in zone_attrs['records'] if not ar['ping_response']])

                        # Format the report for this zone
                        report_str+='Forward Zone Report: {}, {} total records\n'.format(zone_name, total_records)
                        report_str+='> {} records responded to ICMP/ping\n'.format(total_records - total_no_ping_responses)
                        report_str+='> {} records DID NOT response to ICMP/ping\n'.format(total_no_ping_responses)
                        report_str+='> Zone Record Audit Summary:\n\n'
                        for record in zone_attrs['records']:
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
                        for record in zone_attrs['records']:
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

                # Reverse zones
                if zone_type == 'reverse':
                    continue

            # Write report to stdout
            self.write_stdout(report_str, prefix=False)

        # Output as CSV
        elif self.args.csv:
            csv_output = ''
            check_tcp_headers = ''
            tcp_ports_args_list = self._process_str(self.args.check_tcp_ports).split(',')
            if self.args.check_tcp_ports:
                for tcp_port in tcp_ports_args_list:
                    check_tcp_headers+=',tcp_port_{}'.format(tcp_port)
            csv_output+='zone,record_name,record_ipaddr,ping_response{}\n'.format(check_tcp_headers)

            # Construct by zone
            for zone_type, zone_objects in iteritems(self.zones):

                # Forward zones
                if zone_type == 'forward':
                    for zone_name, zone_attrs in iteritems(zone_objects):
                        for record in zone_attrs['records']:
                            record_csv_str = '{},{},{},{}'.format(
                                zone_name,
                                record['dnsname'],
                                record['ipaddr'],
                                'yes' if record['ping_response'] else 'no'
                            )

                            if record['tcp_ports']:
                                for tcp_port in tcp_ports_args_list:
                                    record_csv_str+=',{}'.format('open' if record['tcp_ports'][tcp_port] else 'closed')
                            csv_output+='{}\n'.format(record_csv_str)
            self.write_stdout(csv_output, prefix=False)

        # Dump full JSON output
        else:
            self.write_stdout(json.dumps(self.zones, indent=2), prefix=False)
        exit(0)

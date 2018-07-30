from builtins import str
import re
import json
import socket
import threading
from time import time
from six import iteritems
from getpass import getpass
from subprocess import Popen, PIPE
from sys import stdout,stderr,exit

from bind9_dns_audit.args import BIND9_DNS_Audit_Args
from bind9_dns_audit.connection import BIND9_DNS_Audit_Connection

class BIND9_DNS_Audit_Interface(object):
    """
    Class for handling interactions with the CLI client.
    """
    def __init__(self, args=None):
        self.args = BIND9_DNS_Audit_Args.construct(args)

        # If prompting for password
        if self.args.connection.ssh_passwd:
            ssh_passwd = getpass(prompt="Enter a password for SSH user [{0}]: ".format(self.args.connection.ssh_user))

        # Open an SSH connection
        self.connection = BIND9_DNS_Audit_Connection(
            self.args.connection.server,
            self.args.connection.ssh_user,
            ssh_port=self.args.connection.ssh_port,
            ssh_passwd=self.args.connection.ssh_passwd,
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
            stdout.write('Zone "{0}" is a forward zone, skipping...\n'.format(zone_name))
            return True
        stdout.write('Retrieving DNS records for: {0}\n'.format(zone_name))
        zone_config_file = self.zones[zone_type][zone_name]['config']
        zone_config = self.connection.get_file(zone_config_file)
        record_is_a = re.compile(r'^[\w.]+\.\s+IN\s+A')

        # Extract zone A records
        for line in zone_config.split('\n'):
            if record_is_a.match(line):
                formatted_line = re.sub(' +', ' ', line.replace('\t', ' '))

                # Get the A record DNS name and associated IP address
                a_record_dnsname = formatted_line.split(' ')[0][:-1]
                a_record_ipaddr  = formatted_line.split(' ')[3]

                # Store the record
                stdout.write('Found A record: {0} [{1}]\n'.format(a_record_dnsname, a_record_ipaddr))
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
        stdout.write('Retrieving zone configurations...\n')
        zones_config = self.connection.get_file(self.args.zones_config)
        zone_name_regex = re.compile(r'^zone[ ]\"([^\"]+)\".*$')
        zone_type_regex = re.compile('^[ \t]+type[ ]([a-z]+);$')
        zone_file_regex = re.compile('^[ \t]+file[ ]\"([^\"]+)\";$')
        zone_is_reverse = re.compile(r'^[0-9]+\..*$')

        # Scan zones
        current_zone = None
        zone_type = None
        for line in zones_config.split('\n'):
            if line.startswith('zone'):
                zone_name = zone_name_regex.sub(r'\g<1>', line)
                current_zone = zone_name

                # Forward zones
                if not zone_is_reverse.match(zone_name):
                    self.zones['forward'][zone_name] = {'records': []}
                    zone_type = 'forward'
                else:
                    # Reverse zones
                    self.zones['reverse'][zone_name] = {'records': []}
                    zone_type = 'reverse'
                stdout.write('Found zone: {0}, type={1}\n'.format(zone_name, zone_type))

            # Zone type (master/slave)
            if zone_type_regex.match(line):
                self.zones[zone_type][current_zone]['type'] = zone_type_regex.sub('\g<1>', line)

            # Zone config
            if zone_file_regex.match(line):
                self.zones[zone_type][current_zone]['config'] = zone_file_regex.sub(r'\g<1>', line)

        # Get zone records (only forward for now)
        for zone_name, zone_attrs in iteritems(self.zones['forward']):
            self._get_zone_records(zone_name, 'forward')

        stdout.write('Retrieved all zone records...\n')

    def _check_tcp_port(self, a_record, tcp_port):
        """
        Check to see if a particular TCP port is open.
        """
        dnsname    = a_record['dnsname']
        ipaddr     = a_record['ipaddr']
        record_str = '{0} [{1}]'.format(dnsname, ipaddr)
        timeout    = self.args.check_tcp_ports_timeout

        # Check if the port is open
        stdout.write('Checking TCP port {0} connectivity for: {1}, timeout={2}s...\n'.format(tcp_port, record_str, timeout))
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(int(timeout))
            s.connect((ipaddr, int(tcp_port)))
            s.shutdown(2)
            s.close()
            stdout.write('TCP port {0} for {1} is OPEN\n'.format(tcp_port, record_str))
            a_record['tcp_ports'][str(tcp_port)] = True
        except:
            stdout.write('TCP port {0} for {1} is CLOSED\n'.format(tcp_port, record_str))
            a_record['tcp_ports'][str(tcp_port)] = False

    def _check_zone_record(self, zone_name, zone_type, a_record):
        """
        Thread worker for checking ICMP connectivity to a host.
        """
        dnsname    = a_record['dnsname']
        ipaddr     = a_record['ipaddr']
        record_str = '{0} [{1}]'.format(dnsname, ipaddr)

        # Run basic ping check
        stdout.write('Checking ICMP connectivity for: {0}...\n'.format(record_str))
        proc = Popen(['/usr/bin/env', 'ping', '-c', '3', dnsname], stdout=PIPE, stderr=PIPE)
        proc.communicate()

        # No response to ping, can possibly be deleted
        if not proc.returncode == 0:
            stdout.write('A Record({0}): no ping response...\n'.format(record_str))
            a_record['ping_response'] = False

        # Responds to ping
        else:
            stdout.write('A Record({0}): ping response OK...\n'.format(record_str))
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
        stdout.write('Checking ICMP response for A records in: {0}\n'.format(zone_name))
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
            report_str+='\nAudit Complete: {0}\n'.format(self.args.connection.server)
            report_str+='{0}\n'.format('-' * 40)
            report_str+='> time elapsed: {0}s\n\n'.format(audit_time_elapsed)

            # Construct by zone
            for zone_type, zone_objects in iteritems(self.zones):

                # Forward zones
                if zone_type == 'forward':
                    for zone_name, zone_attrs in iteritems(zone_objects):

                        # Total records / total no ping responses
                        total_records           = len(zone_attrs['records'])
                        total_no_ping_responses = len([ar for ar in zone_attrs['records'] if not ar['ping_response']])

                        # Format the report for this zone
                        report_str+='Forward Zone Report: {0}, {1} total records\n'.format(zone_name, str(total_records))
                        report_str+='> {0} records responded to ICMP/ping\n'.format(str(total_records - total_no_ping_responses))
                        report_str+='> {0} records DID NOT response to ICMP/ping\n'.format(total_no_ping_responses)
                        report_str+='> Zone Record Audit Summary:\n\n'
                        for record in zone_attrs['records']:
                            report_str+='  {0} [{1}]\n'.format(record['dnsname'], record['ipaddr'])
                            report_str+='  > ping_response: {0}\n'.format('yes' if record['ping_response'] else 'no')
                            if record['tcp_ports']:
                                open_tcp_ports   = [tcp_port for tcp_port,port_open in iteritems(record['tcp_ports']) if port_open]
                                closed_tcp_ports = [tcp_port for tcp_port,port_open in iteritems(record['tcp_ports']) if not port_open]
                                report_str+='  > Open TCP Ports: {0}\n'.format(','.join(open_tcp_ports))
                                report_str+='  > Closed TCP Ports: {0}\n'.format(','.join(closed_tcp_ports))
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
                            no_response_checks+='/tcp_ports[{0}],timeout={1}s'.format(self.args.check_tcp_ports, self.args.check_tcp_ports_timeout)
                        if no_responses:
                            report_str+='  A Records w/ No Response ({0}):\n'.format(no_response_checks)
                            for no_response in no_responses:
                                report_str+='  > {0} [{1}]\n'.format(no_response['dnsname'], no_response['ipaddr'])
                            report_str+='\n'

                # Reverse zones
                if zone_type == 'reverse':
                    continue

            # Write report to stdout
            stdout.write(report_str)

        # Dump full JSON output
        else:
            report_str=json.dumps(self.zones, indent=2)
        exit(0)

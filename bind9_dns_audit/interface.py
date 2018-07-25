import re
import json
import threading
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
        else:
            stdout.write('Attempting key based authentication to: {0}@{1}:{2}'.format(
                self.args.connection.ssh_user,
                self.args.connection.server,
                self.args.connection.ssh_passwd
            ))

        # Open an SSH connection
        self.connection = BIND9_DNS_Audit_Connection(
            self.args.connection.server,
            self.args.connection.ssh_user,
            ssh_port=self.args.connection.ssh_port,
            ssh_passwd=self.args.connection.ssh_passwd)

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

        for line in zone_config.split('\n'):
            if record_is_a.match(line):
                a_record_val = line.split('\t')[0][:-1]
                stdout.write('Found A record: {0}\n'.format(a_record_val))
                self.zones[zone_type][zone_name]['records'].append(a_record_val)

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
                    self.zones['forward'][zone_name] = {'records': [], 'no_ping_response': []}
                    zone_type = 'forward'
                else:
                    # Reverse zones
                    self.zones['reverse'][zone_name] = {'records': [], 'no_ping_response': []}
                    zone_type = 'reverse'
                stdout.write('Found zone: {0}, type={1}\n'.format(zone_name, zone_type))

            # Zone type (master/slave)
            if 'type' in line:
                self.zones[zone_type][current_zone]['type'] = zone_type_regex.sub('\g<1>', line)

            # Zone config
            if 'file' in line:
                self.zones[zone_type][current_zone]['config'] = zone_file_regex.sub(r'\g<1>', line)

        # Get zone records (only forward for now)
        for zone_name, zone_attrs in iteritems(self.zones['forward']):
            self._get_zone_records(zone_name, 'forward')

        stdout.write('Retrieved all zone records...\n')

    def _check_zone_record(self, zone_name, zone_type, hostname):
        """
        Thread worker for checking ICMP connectivity to a host.
        """
        stdout.write('Checking ICMP connectivity for: {0}...\n'.format(hostname))
        proc = Popen(['/usr/bin/env', 'ping', '-c', '3', hostname], stdout=PIPE, stderr=PIPE)
        proc.communicate()

        # No response to ping, can possibly be deleted
        if not proc.returncode == 0:
            stdout.write('A Record[{0}]: no ping response...\n'.format(hostname))
            self.zones[zone_type][zone_name]['no_ping_response'].append(hostname)
            return False
        stdout.write('A Record[{0}]: ping response OK...\n'.format(hostname))
        return True

    def _check_zone_connectivity(self, zone_name, zone_type, zone_records):
        """
        Method for checking connectivity of all zone records.
        """
        stdout.write('Checking ICMP response for A records in: {0}\n'.format(zone_name))
        for a_record in zone_records:
            t = threading.Thread(target=self._check_zone_record, args=(zone_name, zone_type, a_record,))
            self.zone_record_threads.append(t)
            t.start()

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
        self.connection.ssh_open()
        self._get_zones()
        self._check_zones()

        report_str = ""

        # No ping report
        if self.args.report_noping:
            for zone_name, zone_attrs in iteritems(self.zones['forward']):
                report_str+='Zone: {0}, No Ping Response Report\n'.format(zone_name)
                for hostname in zone_attrs['no_ping_response']:
                    report_str+='> {0}\n'.format(hostname)

        # Dump full JSON output
        else:
            report_str=json.dumps(self.zones, indent=2)

        # If writing report to file
        if self.args.report_file:
            stdout.write('Writing report to: {0}\n'.format(self.args.report_file))
            with open(self.args.report_file, 'w') as f:
                f.write(report_str)

        # Print report to stdout
        else:
            stdout.write(report_str)
        exit(0)

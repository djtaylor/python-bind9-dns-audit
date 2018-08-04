import re
import socket
from threading import Thread
from subprocess import Popen, PIPE

from bind9_dns_audit.common import BIND9_DNS_Audit_Common

class BIND9_DNS_Audit_Zones(BIND9_DNS_Audit_Common):
    """
    Class object for representing a parsed collection of BIND9 DNS zones.
    """
    def __init__(self, connection, zones_config, tcp_ports, tcp_ports_timeout):
        super(BIND9_DNS_Audit_Zones, self).__init__(debug=True)
        self.connection        = connection
        self.zones_config      = zones_config
        self.tcp_ports         = tcp_ports.split(',')
        self.tcp_ports_timeout = tcp_ports_timeout

        # Raw zone data
        self._zones = []
        self._zone_record_threads = []

        # Shared regexes
        self.regex = {
            'name': re.compile(r'^zone[ ]\"([^\"]+)\".*$'),
            'type': re.compile(r'^[ \t]+type[ ]([a-z]+);$'),
            'file': re.compile(r'^[ \t]+file[ ]\"([^\"]+)\";$'),
            'is_reverse': re.compile(r'^[0-9]+\..*$'),
            'is_a_record': re.compile(r'^[a-zA-Z0-9.-]+\.\s+[0-9]*\s*IN\s+A\s+')
        }

    def get_data(self):
        """
        Return raw zones data.
        """
        return self._zones

    def _get_zone_records(self, zone):
        """
        Worker method for getting records for each zone.
        """
        zone_config = self.connection.get_file(zone['config'])

        # Extract zone A records
        for line in zone_config.split(b'\n'):
            if self.regex['is_a_record'].match(line.decode()):
                formatted_line = re.sub(b' +', b' ', line.replace(b'\t', b' '))

                # Get the A record DNS name and associated IP address
                record_dnsname = self._process_str(formatted_line.split(b' ')[0][:-1])
                record_ipaddr  = self._process_str(formatted_line.split(b' ')[-1])

                # Store the record
                zone['records'].append({
                    'dnsname': record_dnsname,
                    'ipaddr': record_ipaddr,
                    'ping_response': None,
                    'tcp_ports': {}
                })
                self.write_stdout('Found A record: DNS({}):IP({})'.format(record_dnsname, record_ipaddr), debug=True)

    def get_zone_records(self):
        """
        Get each zone configuration and parse the records.
        """
        for zone in self._zones:
            self.write_stdout('Retrieving records for: {}'.format(zone['name']))
            self._get_zone_records(zone)
            self.write_stdout('Found {} records in: {}'.format(len(zone['records']), zone['name']))

    def _check_tcp_port(self, hostname, tcp_port):
        """
        Check if a TCP port is open on a host.
        """
        self.write_stdout('Checking TCP port {} connectivity for: {}'.format(tcp_port, hostname), debug=True)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(int(timeout))
            s.connect((hostname, int(tcp_port)))
            s.shutdown(2)
            s.close()
            return True
        except:
            return False

    def _check_record_connectivity(self, record):
        """
        Check connectivity for an individual record.
        """
        self.write_stdout('Checking ping/ICMP connectivity for: {}'.format(record['dnsname']), debug=True)

        # Run basic ping check
        proc = Popen(['/usr/bin/env', 'ping', '-c', '3', record['dnsname']], stdout=PIPE, stderr=PIPE)
        proc.communicate()

        # Ping response
        record['ping_response'] = False if not proc.returncode == 0 else True

        # TCP port checks
        if self.tcp_ports:
            for tcp_port in self.tcp_ports:
                record['tcp_ports'][tcp_port] = self._check_tcp_port(record['dnsname'], tcp_port)

    def _check_connectivity(self, zone):
        """
        Worker method for checking zone connectivity.
        """
        for record in zone['records']:
            t = Thread(target=self._check_record_connectivity, args=(record,))
            self._zone_record_threads.append(t)
            t.start()

        # Wait for zone record connectivity tests to complete
        for t in self._zone_record_threads:
            t.join()


    def check_connectivity(self):
        """
        Run connectivity checks for zones and records.
        """
        for zone in self._zones:
            self.write_stdout('Checking records connectivity for: {}'.format(zone['name']))
            self._check_connectivity(zone)

    def parse(self):
        """
        Parse zones from the BIND9 configuration file.
        """
        self.write_stdout('Retrieving zone configurations from: {}'.format(self.zones_config))
        zones_config = self.connection.get_file(self.zones_config)

        # Scan zones
        current_zone = None
        zone_type    = None
        zone_obj     = None
        for line in zones_config.split(b'\n'):
            if line.startswith(b'zone'):
                if zone_obj:
                    self._zones.append(zone_obj)
                zone_obj = {}
                zone_name = self.regex['name'].sub(r'\g<1>', line.decode())
                current_zone = zone_name

                # Forward zones only for now
                if not self.regex['is_reverse'].match(zone_name):
                    zone_obj['is_forward'] = True
                    zone_obj['is_reverse'] = False
                    zone_obj['name'] = zone_name
                    zone_obj['records'] = []

            # Zone type (master/slave)
            if self.regex['type'].match(line.decode()):
                zone_obj['type'] = self.regex['type'].sub('\g<1>', line.decode())

            # Zone config
            if self.regex['file'].match(line.decode()):
                zone_obj['config'] = self.regex['file'].sub(r'\g<1>', line.decode())
        if zone_obj:
            self._zones.append(zone_obj)

        # Report discovered zones on stdout
        for zone in self._zones:
            self.write_stdout('Found zone "{}": {}'.format(zone['name'], ', '.join(
                ['{}={}'.format(x, zone[x]) for x in ['config', 'type', 'is_forward', 'is_reverse']]
            )))

    @classmethod
    def from_remote(cls, connection, zones_config, tcp_ports, tcp_ports_timeout):
        """
        Begin to parse zones from a remote server.
        """
        return cls(connection, zones_config, tcp_ports, tcp_ports_timeout)

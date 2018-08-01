from __future__ import unicode_literals
import argparse
from os import getenv
from sys import stderr, exit, argv
from immutable_collection import ImmutableCollection

from bind9_dns_audit.common import BIND9_DNS_Audit_Common

class BIND9_DNS_Audit_Args(BIND9_DNS_Audit_Common):
    """
    Construct and return an arguments object.
    """
    def __init__(self):
        self.args = {
            'connection': {}
        }

    def _parse_args(self, args):
        """
        Construct arguments to form an API connection.
        """
        parser = argparse.ArgumentParser()

        # Connection parameters
        parser.add_argument("server", help="The IP address or hostname of a BIND9 server to connect to")
        parser.add_argument("--ssh-user", help="The SSH user to connect with (required), env: BIND9_DNS_AUDIT_SSH_USER")
        parser.add_argument("--ssh-key", help="Explicity define which identity file to use to connect (optional), env: BIND9_DNS_AUDIT_SSH_KEY")
        parser.add_argument("--ssh-port", help="The SSH port to connect to. Default is 22, env: BIND9_DNS_AUDIT_SSH_PORT",
            default=22)

        # BIND9 file paths
        parser.add_argument('--zones-config',
            help="The BIND9 configuration file to parse for zones,defaults to /etc/bind/named.conf. env: BIND9_DNS_AUDIT_ZONES_CONF",
            default="/etc/bind/named.conf")

        # Optional port scanning
        parser.add_argument('--check-tcp-ports', help="An optional comma separated list of TCP ports to check: --check-tcp-ports 22,80,3389")
        parser.add_argument('--check-tcp-ports-timeout', help="A timeout value in seconds for TCP port checks. Defaults to 2 seconds", default=2)

        # Output options
        output_group = parser.add_mutually_exclusive_group()
        output_group.add_argument('--pretty-print', help="Generate a formatted report for the CLI", action='store_true')
        output_group.add_argument('--csv', help="Generate CSV formatted output for loading into other applications", action='store_true')

        # Debug output
        parser.add_argument('--debug', help="Show additional debug messages", action='store_true')

        # Parse provided arguments
        args = parser.parse_args(args)

        # Store connection parameters
        self.args['connection']['server']   = getattr(args, 'server')
        self.args['connection']['ssh_user'] = getenv('BIND9_DNS_AUDIT_SSH_USER', getattr(args, 'ssh_user'))
        self.args['connection']['ssh_port'] = getenv('BIND9_DNS_AUDIT_SSH_PORT', getattr(args, 'ssh_port'))
        self.args['connection']['ssh_key']  = getenv('BIND9_DNS_AUDIT_SSH_KEY', getattr(args, 'ssh_key'))

        # SSH user required
        if not self.args['connection']['ssh_user']:
            self.die('ERROR: The parameter "ssh_user" is required')

        # Store BIND9 file paths
        self.args['zones_config'] = getenv('BIND9_DNS_AUDIT_ZONES_CONF', getattr(args, 'zones_config'))

        # Output flags
        self.args['pretty_print'] = getattr(args, 'pretty_print', False)
        self.args['csv'] = getattr(args, 'csv', False)

        # Debug flag
        self.args['debug'] = getattr(args, 'debug', False)

        # Optional port checksf
        self.args['check_tcp_ports'] = getattr(args, 'check_tcp_ports', None)
        self.args['check_tcp_ports_timeout'] = getattr(args, 'check_tcp_ports_timeout')

        # Params look good
        return True

    def parse(self, args):
        """
        Public method for constructing arguments.
        """
        self._parse_args(args)
        return True

    def get_collection(self):
        """
        Return the immutable collection for arguments.
        """
        return ImmutableCollection.create(self.args)

    @classmethod
    def construct(cls, args=argv[1:]):
        """
        Class method for constructing and returning an arguments object.
        """
        parser = cls()
        parser.parse(args)

        # Return a formatted arguments object
        return parser.get_collection()

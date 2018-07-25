import argparse
from os import getenv
from sys import stderr, exit, argv

from bind9_dns_audit.collection import Collection

class BIND9_DNS_Audit_Args(object):
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
        parser.add_argument("--ssh-port", help="The SSH port to connect to. Default is 22, env: BIND9_DNS_AUDIT_SSH_PORT", default=22)
        parser.add_argument("--ssh-passwd", help="Prompt for an SSH password. Defaults to using system keys.", action='store_true', default=False)

        # BIND9 file paths
        parser.add_argument('--zones-config', help="The BIND9 configuration file to parse for zones (required), env: BIND9_DNS_AUDIT_ZONES_CONF")

        # Report arguments
        parser.add_argument('--report-noping', help="Generate a report showing no ping responses", action='store_true')
        parser.add_argument('--report-file', help="Write the report to a file instead of stdout", default=None)

        # Parse provided arguments
        args = parser.parse_args(args)

        # Store connection parameters
        self.args['connection']['server']   = getattr(args, 'server')
        self.args['connection']['ssh_user'] = getenv('BIND9_DNS_AUDIT_SSH_USER', getattr(args, 'ssh_user'))
        self.args['connection']['ssh_port'] = getenv('BIND9_DNS_AUDIT_SSH_PORT', getattr(args, 'ssh_port'))
        self.args['connection']['ssh_passwd'] = getattr(args, 'ssh_passwd', None)

        # SSH user required
        if not self.args['connection']['ssh_user']:
            stderr.write('ERROR: The parameter "ssh_user" is required\n')
            exit(1)

        # Store BIND9 file paths
        self.args['zones_config'] = getenv('BIND9_DNS_AUDIT_ZONES_CONF', getattr(args, 'zones_config'))

        # Report flags
        self.args['report_noping'] = getattr(args, 'report_noping', False)
        self.args['report_file'] = getattr(args, 'report_file', None)

        # Zones config required
        if not self.args['zones_config']:
            stderr.write('ERROR: The parameter "zones_config" is required\n')
            exit(1)

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
        return Collection.create(self.args)

    @classmethod
    def construct(cls, args=argv[1:]):
        """
        Class method for constructing and returning an arguments object.
        """
        parser = cls()
        parser.parse(args)

        # Return a formatted arguments object
        return parser.get_collection()

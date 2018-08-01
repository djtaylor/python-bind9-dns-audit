from __future__ import unicode_literals
from builtins import str
import paramiko
import traceback
from sys import stderr, exit

paramiko.util.log_to_file("ssh_client_debug.log")

from bind9_dns_audit.common import BIND9_DNS_Audit_Common

class BIND9_DNS_Audit_Connection(BIND9_DNS_Audit_Common):
    """
    Class for managing SSH connection to a BIND9 server.
    """
    def __init__(self, server, ssh_user, ssh_port=22, ssh_key=None):
        self.server     = server
        self.ssh_user   = ssh_user
        self.ssh_port   = int(ssh_port)
        self.ssh_key    = ssh_key

        # Client object
        self.ssh_client = None

    def get_file(self, file_path):
        """ Get the contents of a remote file """

        self.write_stdout('Getting contents of "{}:{}"...'.format(self.server, file_path), newline=False)
        try:

            # Get the named config file
            _stdin, _stdout, _stderr = self.ssh_client.exec_command('cat {}'.format(file_path))

            file_contents = _stdout.read()
            if not file_contents:
                self.write_stdout('FAILED', prefix=False)
                self.die([
                    'ERROR: Could not retrieve file contents',
                    '> stderr: \n{}'.format(_stderr.read())
                ])
            self.write_stdout('SUCCESS', prefix=False)

            # Return contents
            return file_contents

        # Failed to get file contents
        except Exception as e:
            self.write_stdout('FAILED', prefix=False)
            self.die('ERROR: Failed to get file contents: {}\n'.format(str(e)))

    def ssh_open(self):
        """ Open the SSH connection """

        # Try to establish a connection
        try:
            self.write_stdout('Opening SSH connection: {}@{}...'.format(self.ssh_user, self.server), newline=False)

            # Make a new SSH connection object
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.load_system_host_keys()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Open the connection
            self.ssh_client.connect(self.server,
                port=self.ssh_port,
                username=self.ssh_user,
                key_filename=self.ssh_key)

            # Connection established
            self.write_stdout('SUCCESS', prefix=False)
        except Exception as e:
            self.write_stdout('FAILED', prefix=False)
            self.die([
                'Failed to open SSH connection to [{}]: {}'.format(self.server, str(e)),
                traceback.print_exc()
            ])

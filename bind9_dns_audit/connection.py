import paramiko
from sys import stderr, stdout, exit

class BIND9_DNS_Audit_Connection(object):
    """
    Class for managing SSH connection to a BIND9 server.
    """
    def __init__(self, server, ssh_user, ssh_port=22, ssh_passwd=None):
        self.server     = server
        self.ssh_user   = ssh_user
        self.ssh_port   = ssh_port
        self.ssh_passwd = ssh_passwd

        # Client object
        self.ssh_client = None

    def get_file(self, file_path):
        """ Get the contents of a remote file """

        stdout.write('Getting contents of "{0}:{1}"...'.format(self.server, file_path))
        try:

            # Get the named config file
            _stdin, _stdout, _stderr = self.ssh_client.exec_command('cat {0}'.format(file_path))

            file_contents = _stdout.read()
            if not file_contents:
                stdout.write('FAILED\n')
                stderr.write('ERROR: Could not retrieve file contents\n')
                stderr.write('> stderr: \n{0}'.format(_stderr.read()))
            stdout.write('SUCCESS\n')

            # Return contents
            return file_contents

        # Failed to get file contents
        except Exception as e:
            stdout.write('FAILED\n')
            stderr.write('ERROR: Failed to get file contents: {0}\n'.format(str(e)))
            exit(1)

    def ssh_open(self):
        """ Open the SSH connection """

        # Try to establish a connection
        try:
            stdout.write('Opening SSH connection: {0}@{1}...'.format(self.ssh_user, self.server))

            # Make a new SSH connection object
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.load_system_host_keys()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Open the connection
            self.ssh_client.connect(self.server,
                port=self.ssh_port,
                username=self.ssh_user,
                password=self.ssh_passwd)

            # Connection established
            stdout.write('SUCCESS\n')
        except Exception as e:
            stdout.write('FAILED\n')
            stderr.write('Failed to open SSH connection to [{0}]: {1}\n'.format(self.server, str(e)))
            exit(1)

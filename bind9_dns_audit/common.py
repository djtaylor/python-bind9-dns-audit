from __future__ import unicode_literals
from colorama import init as colorama_init
from termcolor import colored
from sys import stdout, stderr, exit

# Make it work in Windows just in case
colorama_init()

class BIND9_DNS_Audit_Common(object):
    """
    Parent class object for common methods.
    """
    def __init__(self, debug=False):
        self.debug = debug

    def _process_str(self, msgstr):
        """
        Process a string to make sure it is unicode before printing
        """
        try:
            return msgstr.decode('utf8')
        except (UnicodeEncodeError,AttributeError):
            return msgstr

    def die(self, message, exit_code=1):
        """
        Print an array or string to stderr and exit
        """
        if isinstance(message, list):
            for line in message:
                self.write_stderr(line)
        else:
            self.write_stderr(message)
        exit(exit_code)

    def write_stdout(self, message, newline=True, debug=False, prefix=True):
        """
        Print to stdout and encode utf-8
        """
        newline_char = u'\n' if newline else u''
        if debug:
            msg_prefix = '{}: '.format(colored('DEBUG', 'cyan')) if prefix else ''
            if self.debug:
                stdout.write(self._process_str('{}{}{}'.format(msg_prefix, message, newline_char)))
        else:
            msg_prefix = '{}: '.format(colored('INFO', 'green')) if prefix else ''
            stdout.write(self._process_str('{}{}{}'.format(msg_prefix, message, newline_char)))
        return True

    def write_stderr(self, message, newline=True):
        """
        Print to stderr and encode utf-8
        """
        newline_char = u'\n' if newline else u''
        stderr.write(self._process_str('{}{}'.format(message, newline_char)))
        return True

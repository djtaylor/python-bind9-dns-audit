# -*- coding: utf-8 -*-
__version__ = '0.1.post1'

from bind9_dns_audit.interface import BIND9_DNS_Audit_Interface

def cli_client():
    """
    Invoked from the command line to interact with the libraries functionality.
    """
    client = BIND9_DNS_Audit_Interface()
    client.run()

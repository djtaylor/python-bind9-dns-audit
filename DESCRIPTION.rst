# BIND9 DNS Audit

This module connects to a BIND9 server with SSH, pulls down zones, and audits the zones and records to look for entries that don't have any backing infrastructure and can be deleted.

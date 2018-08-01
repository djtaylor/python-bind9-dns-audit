[![Build Status](https://api.travis-ci.org/djtaylor/python-bind9-dns-audit.png)](https://api.travis-ci.org/djtaylor/python-bind9-dns-audit)

# BIND9 DNS Audit

This module deploys a command line script to audit a BIND9 server to look for DNS records that don't have any backing infrastructure and be deleted. This script takes a BIND9 configuration path, and parses this for any zone definitions, then parses each zone configuration for A records to audit for connectivity.

**NOTE**: This module currently only works with SSH key based authentication. You will need to install your public key on the BIND9 DNS server for the account you plan to connect with. This user should have read access to BIND9 configuration files.

 - [Testing](#testing)
 - [Installing Locally](#installing-locally)
 - [Usage](#usage)
   - [Pretty Print](#pretty-print)
   - [CSV Output](#csv-output)
 - [Docker](#docker)
   - [Building](#building-in-docker)
   - [Running](#running-in-docker)

### Testing
To run the test suite for this module you must have [Docker](https://www.docker.com/get-docker) available on the machine you will be testing on. This spins up a BIND9 Docker container, sets up SSHD, injects keys, and also configuration files for parsing during the test.

```
$ ./test.sh
```

### Installing Locally
The preferred option is to install this module into its own `virtualenv`. You will need `pip` if you don't already have it.

```
$ pip install virtualenv
$ git clone https://github.com/djtaylor/python-bind9-dns-audit
$ cd python-bind9-dns-audit
$ virtualenv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
$ python setup.py install
```

### Usage
The following is an example of basic usage to audit a BIND9 DNS server. This assumes you are running on your local machine as a script. All arguments passed to the script can be passed to the [Docker container](#running-in-docker):

```
# This will dump a JSON report to stdout and use system SSH host keys to connect
$ bind9_dns_audit 192.168.3.10 --ssh-user myuser --zones-config /etc/bind/named.conf.local
$
# Scan TCP ports in case infrastructure not responding to ICMP
$ bind9_dns_audit 192.168.3.10 --ssh-user myuser --zones-config /etc/bind/named.conf.local --check-tcp-ports 22,80,443
# Explicitly tell the script which SSH key file to use, use the default parent configuration (/etc/bind/named.conf)
$ bind9_dns_audit 192.168.3.10 --ssh-user myuser --ssh-key /path/to/key.rsa
```

Depending on your use case you may also use the `--check-tcp-ports-timeout` to increase the timeout for port checks. Default is `2`. Value is in seconds.

##### Pretty Print
Use the `--pretty-print` parameter to format a report for the CLI. Default is the dump the JSON generated on `stdout`.

```
$ bind9_dns_audit 192.168.3.10 --ssh-user myuser --zones-config /etc/bind/named.conf.local --check-tcp-ports 22,80,443 --pretty-print
$ .....
Audit Complete: 192.168.3.10
----------------------------------------
> time elapsed: 15.7087161541

Forward Zone Report: mydomain.com, 13 total records
> 1 records responded to ICMP/ping
> 3 records DID NOT response to ICMP/ping

  one.mydomain.com [192.168.3.55]
  > ping_response: no
  > Open TCP Ports: 22
  > Closed TCP Ports: 80,443

  two.mydomain.com [192.168.3.59]
  > ping_response: yes
  > Open TCP Ports: 22, 443
  > Closed TCP Ports: 80

  A Records w/ No Response (ping/tcp_ports[22,80,443],timeout=2s):
  > three.mydomain.com [192.168.3.99]
  > four.mydomain.com [192.168.3.42]

```

##### CSV Output
You may also elect to have the output rendered as a CSV. To achieve this use `--csv`. This argument is incompatible with `--pretty-print`.

### Docker
This repository ships with a `Dockerfile` you can use to build an executable container instead of running locally.

##### Building in Docker
Build the Docker image before running:
```
# Build the image
$ docker build -t bind9_dns_audit .
```

##### Running in Docker
This repository comes with a helper script to run the container. Because SSH key is required for authentication, it should be mounted at runtime. If you use this script and set the environment variable `BIND9_DNS_AUDIT_SSH_PRIVKEY`, you don't need to explicitly pass the `--ssh-key` argument.

```
$ export BIND9_DNS_AUDIT_SSH_PRIVKEY=/path/to/bind9_server_privkey
$ ./docker_run.sh <bind9_server_ip> <all other args besides '--ssh-key'>
```

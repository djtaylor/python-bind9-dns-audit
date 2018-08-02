#!/bin/bash

# Cleanup helper
function cleanup() {
  echo -n "Stopping container [$1]..."
  docker stop $1
  echo -n "Removing container [$1]..."
  docker rm $1
}

# Build the BIND9 container
docker build . -t bind9_dns_audit_test_bind9 -f Dockerfile_BIND9

if [ "$?" != "0" ]; then
  exit
fi

# Run the BIND9 container
docker run -d --name bind9_dns_audit_test_bind9 -p 60053:53 -p 60053:53/udp -p 60022:22 \
-v $(pwd)/docker_test_files/named.conf:/etc/bind/named.conf:ro \
-v $(pwd)/docker_test_files/zone1.conf:/etc/bind/master/zone1.local.conf:ro \
-v $(pwd)/docker_test_files/zone2.conf:/etc/bind/master/zone2.local.conf:ro \
bind9_dns_audit_test_bind9

# Run the tests
python setup.py test

# Cleanup
cleanup "bind9_dns_audit_test_bind9"

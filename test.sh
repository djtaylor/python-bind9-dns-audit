#!/bin/bash
CONTAINER_NAME="bind9_dns_audit_test"

# Wrapper script for spinning up a Dockerized BIND9 server for testing
echo -n "Creating BIND9 Docker container for testing..."
docker run -d --name ${CONTAINER_NAME} -p 60053:53 -p 60053:53/udp -p 60022:22 \
-v $(pwd)/docker_test_files/named.conf:/etc/bind/named.conf:ro \
-v $(pwd)/docker_test_files/zone1.conf:/etc/bind/master/zone1.local.conf:ro \
-v $(pwd)/docker_test_files/zone2.conf:/etc/bind/master/zone2.local.conf:ro \
-v $(pwd)/docker_test_files/id_rsa_test.pub:/root/.ssh/authorized_keys:ro \
resystit/bind9:latest

# Install/configure SSHD
echo "Installing/configuring SSH server w/ keys..."
echo "------------------------------------------------------------"
docker exec bind9_dns_audit_test sh -c "apk add --update git openssh-client openssh-server"
docker exec bind9_dns_audit_test sh -c "chmod 700 /root/.ssh"

# Copy host keys
docker cp $(pwd)/docker_test_files/id_rsa_host_test bind9_dns_audit_test:/etc/ssh/ssh_host_rsa_key
docker cp $(pwd)/docker_test_files/id_rsa_host_test.pub bind9_dns_audit_test:/etc/ssh/ssh_host_rsa_key.pub
docker exec bind9_dns_audit_test sh -c "chmod 600 /etc/ssh/ssh_host_rsa_key"

# Start up SSHD
echo "Starting SSHD..."
echo "------------------------------------------------------------"
docker exec -d bind9_dns_audit_test sh -c "/usr/sbin/sshd -D -f /etc/ssh/sshd_config"

# Run the Python tests
echo "Running Python tests..."
echo "------------------------------------------------------------"
/usr/bin/env python setup.py test

# Test complete
echo "------------------------------------------------------------"
if [ "$?" == "0" ]; then
  echo "> Test suite completed successfully, beginning cleanup..."
else
  echo "> Test suite failed to complete, beginning cleanup..."
fi

# Stop down the container
echo "------------------------------------------------------------"
echo -n "Stopping container [${CONTAINER_NAME}]..."
docker stop ${CONTAINER_NAME} &> /dev/null
if [ "$?" == "0" ]; then
  echo "SUCCESS"
else
  echo "FAILED"
fi

# Remove down the container
echo -n "Removing container [${CONTAINER_NAME}]..."
docker rm ${CONTAINER_NAME} &> /dev/null
if [ "$?" == "0" ]; then
  echo "SUCCESS"
else
  echo "FAILED"
fi

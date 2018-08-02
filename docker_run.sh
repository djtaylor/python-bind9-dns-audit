#!/usr/bin/env bash
BIND9_DNS_AUDIT_SSH_PRIVKEY_DEFAULT="$(pwd)/docker_test_files/id_rsa_test"
if [ -z "${BIND9_DNS_AUDIT_SSH_PRIVKEY}" ]; then
  BIND9_DNS_AUDIT_SSH_PRIVKEY=${BIND9_DNS_AUDIT_SSH_PRIVKEY_DEFAULT}
  echo "Envar[] not found, (default): ${BIND9_DNS_AUDIT_SSH_PRIVKEY}"
else
  BIND9_DNS_AUDIT_SSH_PRIVKEY=${BIND9_DNS_AUDIT_SSH_PRIVKEY}
fi

docker run -v ${BIND9_DNS_AUDIT_SSH_PRIVKEY}:/root/.ssh/id_rsa:ro bind9_dns_audit $@ --ssh-key /root/.ssh/id_rsa

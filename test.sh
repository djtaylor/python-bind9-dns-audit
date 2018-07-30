#!/bin/bash

# Read commands from Travis yaml so we don't duplicate them
while IFS='' read -r line || [[ -n "$line" ]]; do
  if [ ! -z "$(echo $line | grep -E '^-[ ].*$')" ]; then
    CMD_STR="$(echo $line | sed 's/^-[ ]\(.*$\)/\1/g')"
    eval $CMD_STR
  fi
done < <(sed -n '/^before_install:$/,/^$/p' .travis.yml)

# Run the tests
python setup.py test

# Cleanup
echo -n "Stopping container..."
docker stop bind9_dns_audit_test
echo -n "Removing container..."
docker rm bind9_dns_audit_test

FROM python:3.7-alpine3.8

# OpenSSH client for connecting to BIND9 server
RUN apk add --no-cache git openssh-client musl libc6-compat linux-headers \
build-base bash ca-certificates libffi libffi-dev openssl openssl-dev
RUN mkdir -m 700 -p /root/.ssh

# Application working directory
WORKDIR /usr/src/app

# Install requirements
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy in the application
COPY . .

RUN python setup.py build && python setup.py install

ENTRYPOINT [ "bind9_dns_audit" ]
CMD [ "--help" ]

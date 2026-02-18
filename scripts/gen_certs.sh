#!/bin/bash
# Generate self-signed certs for MTD HTTPS testing
mkdir -p certs
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
    -keyout certs/server.key -out certs/server.crt \
    -subj "/C=US/ST=State/L=City/O=MTD-HealthNet/CN=localhost"
chmod 644 certs/server.crt
chmod 600 certs/server.key
echo "Certificates generated in certs/"

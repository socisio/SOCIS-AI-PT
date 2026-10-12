#!/bin/bash
# SOCIS-AI-PT — Self-Signed SSL Generator
# This script generates a 4096-bit RSA self-signed certificate for local development.

set -e

DOMAIN="${1:-socis.local}"
SSL_DIR=$(dirname "$0")

echo "Generating SSL certificates for ${DOMAIN} in ${SSL_DIR}..."

openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
    -keyout "${SSL_DIR}/key.pem" \
    -out "${SSL_DIR}/cert.pem" \
    -subj "/C=US/ST=Cyber/L=SOC/O=SOCIS/OU=AI-PT/CN=${DOMAIN}" \
    -addext "subjectAltName=DNS:${DOMAIN},DNS:*.${DOMAIN},IP:127.0.0.1"

chmod 600 "${SSL_DIR}/key.pem" "${SSL_DIR}/cert.pem"

echo "Success! Certificates generated:"
ls -l "${SSL_DIR}"/*.pem

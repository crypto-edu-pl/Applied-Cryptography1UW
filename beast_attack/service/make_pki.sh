#!/bin/sh
set -e

rm -r pki/key.pem pki/cert.pem
mkdir -p pki

# From https://stackoverflow.com/a/10176685
openssl req -x509 -newkey rsa:4096 -keyout pki/key.pem -out pki/cert.pem -sha256 -days 365 -nodes -subj "/CN=beast.example"

echo 'All set!'

#!/bin/sh
# Demo PKI (one-shot): a demo CA and one certificate for every fake "public" service of the demo.
# The gateway trusts this CA for its upstream connections (AFW_UPSTREAM_CA_FILE); agents never see it.
# Idempotent: keeps an existing, still valid PKI.
set -eu
out="${PKI_DIR:-/pki}"
names="${PKI_NAMES:-api.anthropic.com api.openai.com exfil.example allowed.example api.github.com s3.demo.example *.s3.demo.example}"
ips="${PKI_IPS:-198.18.0.10 198.18.0.11 198.18.0.12 198.18.0.13}"
mkdir -p "$out"
umask 077

if [ -s "$out/demo-ca.crt" ] && [ -s "$out/upstream.crt" ] &&
  openssl verify -CAfile "$out/demo-ca.crt" "$out/upstream.crt" >/dev/null 2>&1 &&
  openssl x509 -checkend 86400 -noout -in "$out/upstream.crt" >/dev/null 2>&1; then
  echo "demo PKI already present in $out"
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
openssl ecparam -name prime256v1 -genkey -noout -out "$out/demo-ca.key"
openssl req -x509 -new -key "$out/demo-ca.key" -sha256 -days 825 \
  -subj "/O=agents-firewall demo/CN=agents-firewall demo upstream CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$out/demo-ca.crt"

san=""
for n in $names; do san="${san:+$san,}DNS:$n"; done
for i in $ips; do san="${san:+$san,}IP:$i"; done
openssl ecparam -name prime256v1 -genkey -noout -out "$out/upstream.key"
openssl req -new -key "$out/upstream.key" -subj "/O=agents-firewall demo/CN=demo upstream" -out "$tmp/upstream.csr"
printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' "$san" > "$tmp/ext.cnf"
openssl x509 -req -in "$tmp/upstream.csr" -CA "$out/demo-ca.crt" -CAkey "$out/demo-ca.key" -CAcreateserial \
  -days 398 -sha256 -extfile "$tmp/ext.cnf" -out "$out/upstream.crt"
chmod 600 "$out/demo-ca.key" "$out/upstream.key"
chmod 644 "$out/demo-ca.crt" "$out/upstream.crt"
rm -f "$out/demo-ca.srl"
echo "demo PKI created in $out ($san)"

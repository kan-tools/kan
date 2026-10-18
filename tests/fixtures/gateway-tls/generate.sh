#!/bin/sh
# PUBLIC, SYNTHETIC TEST KEYS. Never use this CA for a real instance.
set -eu
cd "$(dirname "$0")"
umask 077
openssl req -sha256 -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -nodes -keyout ca.key -out ca.pem -days 3650 -subj /CN=kan-test-ca
openssl req -sha256 -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -nodes -keyout foreign.key -out foreign.pem -days 3650 -subj /CN=kan-foreign-test-ca
for name in server client; do
  openssl req -sha256 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -nodes -keyout "$name.key" -out "$name.csr" -subj "/CN=kan-test-$name"
  if [ "$name" = server ]; then
    printf '%s\n' 'subjectAltName=DNS:localhost,IP:127.0.0.1' 'extendedKeyUsage=serverAuth' > "$name.ext"
  else
    printf '%s\n' 'extendedKeyUsage=clientAuth' > "$name.ext"
  fi
  openssl x509 -sha256 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -out "$name.pem" -days 3650 -extfile "$name.ext"
done
cat client.pem client.key > identity.pem
openssl req -sha256 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -nodes -keyout foreign-client.key -out foreign-client.csr -subj /CN=foreign-client
printf '%s\n' 'extendedKeyUsage=clientAuth' > foreign-client.ext
openssl x509 -sha256 -req -in foreign-client.csr -CA foreign.pem -CAkey foreign.key -CAcreateserial -out foreign-client.pem -days 3650 -extfile foreign-client.ext
cat foreign-client.pem foreign-client.key > foreign-identity.pem
rm foreign-client.key foreign-client.csr foreign-client.ext foreign-client.pem foreign.srl
rm ca.key foreign.key ca.srl server.csr client.csr server.ext client.ext

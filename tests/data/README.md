# Test TLS certificates

These certificates and keys are **only for the automated tests** in
`tests/tls_transport_test.cc`. They are self-signed, public, and must never be
used outside the test suite.

- `server.crt` / `server.key`: self-signed server certificate for `localhost`
  (`CN=localhost`, SAN `DNS:localhost`). `basicConstraints=CA:TRUE` so the
  certificate doubles as its own CA, which lets the client verify it with
  `ca_file = tests/data/server.crt`.
- `client.crt` / `client.key`: self-signed client certificate (`CN=libtrie-test-client`,
  `extendedKeyUsage=clientAuth`) used by the mutual-TLS test.

Regenerate them from the repository root with:

```sh
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout tests/data/server.key -out tests/data/server.crt \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign" \
  -addext "extendedKeyUsage=serverAuth"

openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout tests/data/client.key -out tests/data/client.crt \
  -subj "/CN=libtrie-test-client" \
  -addext "subjectAltName=DNS:libtrie-test-client" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign" \
  -addext "extendedKeyUsage=clientAuth"
```

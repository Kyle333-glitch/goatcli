# Test-only security material

Everything in this directory exists only for hostile updater and native fixture
tests. None of it is a GOAT production trust root, production signing key,
release credential, distributed engine, or release artifact.

`localhost-cert.pem` and `localhost-key.pem` are a self-signed RSA certificate
and private key whose subject is `GOAT v0.4.0 TEST ONLY localhost CA`. The
certificate is valid only for `localhost` and `127.0.0.1`. Tests trust it
explicitly through a local `https.Agent`; it is never loaded by production
policy code or included in the npm package.

The certificate SHA-256 fingerprint is:

`73:A6:C0:DB:B5:DE:58:50:B4:9E:96:24:EF:E9:8C:5B:EC:40:6C:25:FB:82:A0:06:B2:6D:7E:F3:8A:FD:7D:41`

`fixture-engine.c` is source code compiled on each native CI runner. Compiled
fixture binaries are temporary test output and must never be checked in or
packed into `goatcli`.

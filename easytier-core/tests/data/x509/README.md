# Public test credentials

These certificates and private keys are committed only for authentication tests.
Never trust this CA or use these private keys in a deployed node.

- `ca.pem`: client trust anchor; its private key is not stored.
- `client.pem` / `client.key.pem`: authorized client identity (serial 1).
- `server-only.pem` / `server-only.key.pem`: identity with only serverAuth EKU.
- `other-ca.pem`: unrelated trust anchor.
- `revoked.crl.pem`: CA-signed CRL revoking the authorized client certificate.

The certificates and CRL were generated with OpenSSL in November 2026 with a
3650-day validity period. Crypto unit tests use a fixed verification time in
2027; handshake integration tests use the system clock.

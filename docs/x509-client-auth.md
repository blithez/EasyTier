# X.509 authentication for public-node clients

A public node can require clients to present an X.509 certificate issued by a
trusted private CA and prove possession of its private key. This authorizes use
of the node; it does not make the client a member of the node's overlay network.
Existing network-secret, credential, and relay-whitelist checks still apply.

The standard builds enable the `x509-auth` Cargo feature. Custom builds must
enable `easytier/x509-auth` (or `easytier-core/x509-auth`). Builds without the
feature reject X.509 configuration instead of ignoring it.

## Configure the public node

Add trusted client CA certificates to the node's TOML configuration:

```toml
[secure_mode]
enabled = true

[secure_mode.x509]
trusted_client_ca_pem = ['''
-----BEGIN CERTIFICATE-----
<your private client CA certificate>
-----END CERTIFICATE-----
''']
```

A nonempty `trusted_client_ca_pem` makes certificate authentication mandatory for
**every incoming network peer connection**, including peers claiming the node's own
network name. Missing, untrusted, invalid, expired, or revoked certificates are
rejected. Legacy handshakes are rejected. The policy applies to all transports
that use the peer handshake and is checked again on each new connection,
including connections joining an existing session.

VPN portal attached peers use a separate authenticated in-process path. The host
registers each attached peer's ephemeral Noise public key before creating its
ring connection, then verifies that exact key during the Noise handshake. This
path is restricted to host-created attached rings in the host's own network;
ordinary listener connections still require X.509 certificates even when their
Noise keys are already trusted. Attached peers do not inherit the host's CA
policy or client certificate/private key and retain credential-level privileges.
They cannot use legacy handshakes on the authenticated attached path.

Use a dedicated client CA. Every certificate accepted under these roots is
allowed to access this node, subject to the existing relay policy. Do not put
public Web PKI roots in this trust store. Nodes without trusted client CAs keep
their existing admission behavior; configuring a client identity alone does not
restrict incoming connections.

## Configure each client

Issue each client its own certificate with digital-signature key usage and
`clientAuth` extended key usage. Configure the leaf certificate followed by any
intermediate certificates, and its matching unencrypted PEM private key:

```toml
[secure_mode]
enabled = true

[secure_mode.x509]
client_certificate_pem = '''
-----BEGIN CERTIFICATE-----
<client leaf certificate, followed by intermediate certificates if needed>
-----END CERTIFICATE-----
'''
client_private_key_pem = '''
-----BEGIN PRIVATE KEY-----
<client PKCS#8 private key>
-----END PRIVATE KEY-----
'''
```

Protect this configuration as a private-key file. Keys are redacted in redacted
configuration dumps and X.509 configuration Debug output. The normal full
configuration dump intentionally contains the private key, as it does for
existing key material. A node may configure both trusted CAs and a client
identity when it also connects to other protected nodes. Existing CLI secure-mode
key overrides preserve the X.509 configuration.

This feature authenticates clients to nodes. Continue to pin the public node's
Noise static key using the existing peer key-pinning mechanism to authenticate
the node to the client.

## Android GUI certificate import

In the Android GUI, open a network's configuration, expand **Public node
certificate authentication** under basic settings, and use **Import certificate
chain** and **Import private key** to select the corresponding PEM files from
the system file picker. The certificate file must contain the client certificate
first, followed by any intermediates. Importing an identity enables secure mode.
Both files are required before saving or starting the network. File imports are
local; they are not uploaded to a certificate service.

The form shows whether each file is configured without displaying private-key
material. Invalid replacements leave the previous identity unchanged. **Remove
client certificate and private key** removes only the client identity and
preserves any server CA/revocation settings imported through TOML. Certificates
also survive save/load and switching to the temporary-credential identity mode.

This imports PEM files, not PKCS#12/PFX bundles or password-protected keys. It
does not use Android Keystore: the PEM private key is saved with the network
configuration and is included in configuration exports. The GUI and native
library must both be rebuilt from this source to include X.509 support.

## Revocation and rotation

Use short-lived certificates or configure PEM CRLs on the server:

```toml
[secure_mode.x509]
# Include trusted_client_ca_pem here as above.
client_crl_pem = ['''
-----BEGIN X509 CRL-----
<CA-signed certificate revocation list>
-----END X509 CRL-----
''']
```

CRLs must cover the chain being checked. Revocation is only checked when CRLs
are configured. Updating trust or revocation settings affects new handshakes;
restart the node to disconnect existing sessions immediately after revocation.
Keep CRLs current. Multiple trusted CA PEM entries support CA rotation.

## Protocol

The client advertises `x509-client-auth-v1` in Noise message 1. A protected server
sends a fresh random challenge before allocating a session or disclosing session
keys in Noise message 2. The client responds with its certificate chain,
signature scheme, and signature over a domain-separated context containing the
Noise transcript after message 1 and the challenge. The server validates the
chain, client-auth usage, validity, configured revocation information, and proof
of possession before continuing.

The challenge exchange is part of the admission handshake but precedes Noise
encryption: **client certificates are visible to network observers**. Private
keys are never transmitted. The certificate key signs the transcript again in
Noise message 3, inside Noise encryption. Authentication never substitutes for
overlay membership checks or changes the existing peer identity classification.

Chains are limited to 8 certificates and 48 KiB of DER. Handshake messages have a
60 KiB payload limit and handshake reads have timeouts. Old clients cannot access
protected nodes. Updated clients can still connect to unprotected nodes.

## Validation

Run on a host with Rust and the project's native build prerequisites installed:

```sh
cargo test -p easytier-core --lib x509 --features x509-auth
cargo test -p easytier-core --lib secure_attached_runtime_removes_admin_and_group_secrets
cargo test -p easytier-core --lib peer_conn_noise_handshake_advertises_liveness_echo
cargo check -p easytier --features x509-auth
cargo check -p easytier-core --no-default-features
cargo fmt --all -- --check
```

Frontend import and configuration persistence tests:

```sh
pnpm --dir easytier-web/frontend-lib test:config-ui
pnpm --dir easytier-gui build
```

The tests cover certificate validation, proof tampering and replay, certificate
validity, revocation, mismatched private keys, client-auth usage, successful
same-network and foreign-network handshakes, and legacy-client rejection.
Test certificates and private keys in `easytier-core/tests/data/x509` are public
test fixtures and must never be used in production. Their validity starts in
November 2026 and ends in October 2036; the crypto unit tests use a fixed 2027
verification time. End-to-end handshake tests use the current time.

import { describe, expect, it } from 'vitest'
import { DEFAULT_NETWORK_CONFIG, normalizeNetworkConfig, toBackendNetworkConfig } from '../src/types/network'

const x509 = {
  trusted_client_ca_pem: ['trusted-ca'], client_crl_pem: ['revocations'],
  client_certificate_pem: 'client-certificate', client_private_key_pem: 'client-private-key',
}

describe('X.509 configuration persistence', () => {
  it.each([false, true])('preserves the certificate identity across save/load in credential mode=%s', (credentialMode) => {
    const config = {
      ...DEFAULT_NETWORK_CONFIG(),
      network_secret: credentialMode ? undefined : 'network-secret',
      secure_mode: { enabled: true, local_private_key: 'noise-key', local_public_key: 'noise-public-key', x509 },
    }
    const form = normalizeNetworkConfig(config)
    if (credentialMode) expect(form.credential_secret).toBe('noise-key')
    expect(form.secure_mode?.x509).toEqual(x509)
    const loaded = normalizeNetworkConfig(JSON.parse(JSON.stringify(form)))
    const saved = toBackendNetworkConfig(loaded)
    expect(saved.secure_mode?.x509).toEqual(x509)
    expect(saved.secure_mode?.local_private_key).toBe('noise-key')
    expect(config.secure_mode.local_private_key).toBe('noise-key')
  })
})

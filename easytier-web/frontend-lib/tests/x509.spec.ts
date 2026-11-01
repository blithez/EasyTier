import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { readX509Pem, validateX509Pem } from '../src/modules/x509'

const certificate = readFileSync(new URL('../../../easytier-core/tests/data/x509/client.pem', import.meta.url), 'utf8')
const privateKey = readFileSync(new URL('../../../easytier-core/tests/data/x509/client.key.pem', import.meta.url), 'utf8')

describe('X.509 PEM import', () => {
  it('reads a certificate chain and a matching private key from document files', async () => {
    expect(await readX509Pem(new File([certificate + certificate], 'chain.pem'), 'certificate')).toBe(certificate + certificate)
    expect(await readX509Pem(new File([privateKey], 'client.key'), 'private-key')).toBe(privateKey)
  })

  it('rejects swapped files, non-PEM input, truncated DER, and combined certificate/key files', () => {
    expect(() => validateX509Pem(privateKey, 'certificate')).toThrow('x509_invalid_certificate')
    expect(() => validateX509Pem(certificate, 'private-key')).toThrow('x509_invalid_private_key')
    expect(() => validateX509Pem('not a certificate', 'certificate')).toThrow('x509_invalid_certificate')
    expect(() => validateX509Pem('-----BEGIN CERTIFICATE-----\nMAMCAQ==\n-----END CERTIFICATE-----', 'certificate')).toThrow('x509_invalid_certificate')
    expect(() => validateX509Pem(certificate + privateKey, 'certificate')).toThrow('x509_invalid_certificate')
  })

  it('rejects encrypted keys and chains that exceed the core limits', async () => {
    expect(() => validateX509Pem('-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----', 'private-key')).toThrow('x509_encrypted_key')
    expect(() => validateX509Pem(certificate.repeat(9), 'certificate')).toThrow('x509_chain_too_large')
    await expect(readX509Pem(new File(['x'.repeat(128 * 1024 + 1)], 'huge.pem'), 'certificate')).rejects.toThrow('x509_file_too_large')
  })
})

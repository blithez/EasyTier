export type X509PemKind = 'certificate' | 'private-key'

const MAX_PEM_FILE_BYTES = 128 * 1024
const MAX_CERTIFICATE_BYTES = 48 * 1024

export class X509ImportError extends Error {
  constructor(public readonly translationKey: string) {
    super(translationKey)
  }
}

/** Check the PEM container here; the core validates trust and key matching. */
export function validateX509Pem(text: string, kind: X509PemKind): string {
  if (kind === 'private-key' && /ENCRYPTED/.test(text)) {
    throw new X509ImportError('x509_encrypted_key')
  }
  const invalid = kind === 'certificate' ? 'x509_invalid_certificate' : 'x509_invalid_private_key'
  const blocks = [...text.matchAll(/-----BEGIN ([A-Z ]+)-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END \1-----/g)]
  let totalBytes = 0
  for (const block of blocks) {
    const label = block[1]
    if (kind === 'certificate' ? label !== 'CERTIFICATE' : !['PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY'].includes(label)) {
      throw new X509ImportError(invalid)
    }
    const base64 = block[2].replace(/\s/g, '')
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64)) {
      throw new X509ImportError(invalid)
    }
    let der: string
    try {
      der = atob(base64)
    } catch {
      throw new X509ImportError(invalid)
    }
    // Certificates and supported private keys are DER SEQUENCE values. Check
    // their declared size, so truncated files fail before replacing an identity.
    if (der.length < 2 || der.charCodeAt(0) !== 0x30) throw new X509ImportError(invalid)
    const lengthByte = der.charCodeAt(1)
    let headerBytes = 2
    let contentBytes = lengthByte
    if (lengthByte >= 0x80) {
      const lengthBytes = lengthByte & 0x7f
      if (lengthBytes < 1 || lengthBytes > 4 || der.length < 2 + lengthBytes) throw new X509ImportError(invalid)
      contentBytes = 0
      for (let i = 0; i < lengthBytes; i++) contentBytes = contentBytes * 256 + der.charCodeAt(2 + i)
      headerBytes += lengthBytes
    }
    if (contentBytes === 0 || headerBytes + contentBytes !== der.length) throw new X509ImportError(invalid)
    totalBytes += der.length
  }
  const remaining = text.replace(/-----BEGIN ([A-Z ]+)-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END \1-----/g, '').trim()
  if (!blocks.length || remaining || (kind === 'private-key' && blocks.length !== 1)) {
    throw new X509ImportError(invalid)
  }
  if (kind === 'certificate' && (blocks.length > 8 || totalBytes > MAX_CERTIFICATE_BYTES)) {
    throw new X509ImportError('x509_chain_too_large')
  }
  return text.trim() + '\n'
}

export async function readX509Pem(file: File, kind: X509PemKind): Promise<string> {
  if (file.size > MAX_PEM_FILE_BYTES) throw new X509ImportError('x509_file_too_large')
  let text: string
  try {
    text = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = () => resolve(String(reader.result ?? ''))
      reader.onerror = () => reject(new Error('file read failed'))
      reader.onabort = () => reject(new Error('file read aborted'))
      reader.readAsText(file)
    })
  } catch {
    throw new X509ImportError('x509_read_failed')
  }
  return validateX509Pem(text, kind)
}

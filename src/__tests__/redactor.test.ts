import { describe, it, expect } from 'vitest'
import { redact } from '../redactor.js'

describe('redact', () => {
  it('redacts a single AWS key', () => {
    const input = 'Key is AKIAIOSFODNN7EXAMPLE here'
    const result = redact(input)
    expect(result.redacted).toBe('Key is [REDACTED-AWS_KEY] here')
    expect(result.count).toBe(1)
  })

  it('redacts a GitHub token', () => {
    const input = 'Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'
    const result = redact(input)
    expect(result.redacted).toContain('[REDACTED-GITHUB_TOKEN]')
    expect(result.redacted).not.toContain('ghp_')
    expect(result.count).toBe(1)
  })

  it('redacts a private key header', () => {
    const input = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK'
    const result = redact(input)
    expect(result.redacted).toContain('[REDACTED-PRIVATE_KEY]')
    expect(result.redacted).not.toContain('BEGIN RSA PRIVATE KEY')
    expect(result.count).toBe(1)
  })

  it('redacts multiple secrets', () => {
    const input = [
      'AWS: AKIAIOSFODNN7EXAMPLE',
      'DB: postgresql://admin:hunter2@db.example.com/prod',
    ].join('\n')
    const result = redact(input)
    expect(result.redacted).toContain('[REDACTED-AWS_KEY]')
    expect(result.redacted).toContain('[REDACTED-CONNECTION_STRING]')
    expect(result.count).toBe(2)
  })

  it('preserves surrounding text', () => {
    const input = 'before AKIAIOSFODNN7EXAMPLE after'
    const result = redact(input)
    expect(result.redacted).toBe('before [REDACTED-AWS_KEY] after')
  })

  it('does not mutate the original string', () => {
    const input = 'Key is AKIAIOSFODNN7EXAMPLE'
    const originalCopy = input
    redact(input)
    expect(input).toBe(originalCopy)
  })

  it('returns count 0 for clean text', () => {
    const input = 'Just some normal text with no secrets'
    const result = redact(input)
    expect(result.redacted).toBe(input)
    expect(result.count).toBe(0)
  })

  it('redacts a connection string', () => {
    const input = 'mongodb+srv://user:pass@cluster.mongodb.net/db'
    const result = redact(input)
    expect(result.redacted).toBe('[REDACTED-CONNECTION_STRING]')
    expect(result.count).toBe(1)
  })
})

import { describe, it, expect } from 'vitest'
import { scan } from '../scanner.js'
import { SecretType } from '../types.js'

describe('scan', () => {
  it('detects AWS access keys', () => {
    const result = scan('Found key AKIAIOSFODNN7EXAMPLE in config')
    expect(result.clean).toBe(false)
    expect(result.detections).toHaveLength(1)
    expect(result.detections[0]?.type).toBe(SecretType.AWS_KEY)
    expect(result.detections[0]?.match).toBe('AKIAIOSF...')
  })

  it('detects GitHub personal access tokens', () => {
    const token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'
    const result = scan(`Token: ${token}`)
    expect(result.clean).toBe(false)
    expect(result.detections).toHaveLength(1)
    expect(result.detections[0]?.type).toBe(SecretType.GITHUB_TOKEN)
  })

  it('detects GitHub fine-grained PATs', () => {
    const token = 'github_pat_ABCDEFGHIJKLMNOPQRSTUV1234567890abcdef'
    const result = scan(`PAT: ${token}`)
    expect(result.clean).toBe(false)
    expect(result.detections).toHaveLength(1)
    expect(result.detections[0]?.type).toBe(SecretType.GITHUB_TOKEN)
  })

  it('detects private key headers', () => {
    const result = scan('-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...')
    expect(result.clean).toBe(false)
    expect(result.detections).toHaveLength(1)
    expect(result.detections[0]?.type).toBe(SecretType.PRIVATE_KEY)
  })

  it('detects EC private key headers', () => {
    const result = scan('-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...')
    expect(result.clean).toBe(false)
    expect(result.detections[0]?.type).toBe(SecretType.PRIVATE_KEY)
  })

  it('detects JWT tokens', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
    const result = scan(`Authorization header contains ${jwt}`)
    expect(result.clean).toBe(false)
    expect(result.detections).toHaveLength(1)
    expect(result.detections[0]?.type).toBe(SecretType.JWT)
  })

  it('detects PostgreSQL connection strings', () => {
    const result = scan('DATABASE_URL=postgresql://user:pass@localhost:5432/mydb')
    expect(result.clean).toBe(false)
    expect(result.detections).toHaveLength(1)
    expect(result.detections[0]?.type).toBe(SecretType.CONNECTION_STRING)
  })

  it('detects MongoDB connection strings', () => {
    const result = scan('MONGO_URI=mongodb+srv://admin:secret@cluster0.abc.net/test')
    expect(result.clean).toBe(false)
    expect(result.detections).toHaveLength(1)
    expect(result.detections[0]?.type).toBe(SecretType.CONNECTION_STRING)
  })

  it('detects API keys in config', () => {
    const result = scan('api_key: "abcdef1234567890abcdef"')
    expect(result.clean).toBe(false)
    expect(result.detections).toHaveLength(1)
    expect(result.detections[0]?.type).toBe(SecretType.API_KEY)
  })

  it('detects secret_key assignments', () => {
    const result = scan('secret_key = "xyzzy98765432109876543210"')
    expect(result.clean).toBe(false)
    expect(result.detections[0]?.type).toBe(SecretType.API_KEY)
  })

  it('detects Bearer tokens', () => {
    const bearer = 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9abcdefghijklmnopq'
    const result = scan(`Authorization: ${bearer}`)
    expect(result.clean).toBe(false)
    expect(result.detections.some((d) => d.type === SecretType.BEARER_TOKEN)).toBe(true)
  })

  it('returns clean for normal code', () => {
    const normalCode = `
      function hello() {
        const x = 42
        return x + 1
      }
      const config = { port: 3000, host: 'localhost' }
      console.log('Hello, world!')
    `
    const result = scan(normalCode)
    expect(result.clean).toBe(true)
    expect(result.detections).toHaveLength(0)
  })

  it('returns clean for text mentioning keys without actual secrets', () => {
    const text = 'Please set your API key in the environment variables. Use AWS_ACCESS_KEY_ID.'
    const result = scan(text)
    expect(result.clean).toBe(true)
  })

  it('detects multiple secrets in one text', () => {
    const text = [
      'AWS key: AKIAIOSFODNN7EXAMPLE',
      'GitHub token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij',
      'DB: postgresql://admin:hunter2@db.example.com/prod',
    ].join('\n')
    const result = scan(text)
    expect(result.clean).toBe(false)
    expect(result.detections.length).toBeGreaterThanOrEqual(3)

    const types = result.detections.map((d) => d.type)
    expect(types).toContain(SecretType.AWS_KEY)
    expect(types).toContain(SecretType.GITHUB_TOKEN)
    expect(types).toContain(SecretType.CONNECTION_STRING)
  })

  it('truncates matched text for safety', () => {
    const result = scan('AKIAIOSFODNN7EXAMPLE')
    expect(result.detections[0]?.match).toBe('AKIAIOSF...')
    expect(result.detections[0]?.match.length).toBeLessThan(20)
  })

  it('records the correct index position', () => {
    const prefix = 'prefix: '
    const result = scan(`${prefix}AKIAIOSFODNN7EXAMPLE`)
    expect(result.detections[0]?.index).toBe(prefix.length)
  })
})

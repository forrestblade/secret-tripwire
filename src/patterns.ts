import type { SecretType } from './types.js'
import { SecretType as ST } from './types.js'

export const SECRET_PATTERNS: readonly {
  readonly type: SecretType
  readonly pattern: RegExp
  readonly label: string
}[] = [
  { type: ST.AWS_KEY, pattern: /AKIA[0-9A-Z]{16}/g, label: 'AWS Access Key' },
  { type: ST.GITHUB_TOKEN, pattern: /gh[pos]_[a-zA-Z0-9_]{36,255}/g, label: 'GitHub Token' },
  { type: ST.GITHUB_TOKEN, pattern: /github_pat_[a-zA-Z0-9_]{22,255}/g, label: 'GitHub PAT' },
  { type: ST.PRIVATE_KEY, pattern: /-----BEGIN (RSA|EC|PGP|OPENSSH|DSA) PRIVATE KEY-----/g, label: 'Private Key' },
  { type: ST.JWT, pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g, label: 'JWT Token' },
  { type: ST.CONNECTION_STRING, pattern: /(mongodb\+srv|postgresql|mysql|redis):\/\/[^\s'"]+@[^\s'"]+/g, label: 'Connection String' },
  { type: ST.API_KEY, pattern: /(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]/gi, label: 'API Key' },
  { type: ST.BEARER_TOKEN, pattern: /Bearer\s+[a-zA-Z0-9\-._~+/]{40,}/g, label: 'Bearer Token' },
]

export const SecretType = {
  AWS_KEY: 'AWS_KEY',
  GITHUB_TOKEN: 'GITHUB_TOKEN',
  PRIVATE_KEY: 'PRIVATE_KEY',
  JWT: 'JWT',
  CONNECTION_STRING: 'CONNECTION_STRING',
  API_KEY: 'API_KEY',
  BEARER_TOKEN: 'BEARER_TOKEN',
} as const

export type SecretType = typeof SecretType[keyof typeof SecretType]

export interface Detection {
  readonly type: SecretType
  readonly match: string
  readonly index: number
}

export interface ScanResult {
  readonly detections: readonly Detection[]
  readonly clean: boolean
}

export const TripwireErrorCode = {
  IO_FAILED: 'IO_FAILED',
  PARSE_FAILED: 'PARSE_FAILED',
} as const

export type TripwireErrorCode = typeof TripwireErrorCode[keyof typeof TripwireErrorCode]

export interface TripwireError {
  readonly code: TripwireErrorCode
  readonly message: string
}

import { SECRET_PATTERNS } from './patterns.js'

export function redact (text: string): { readonly redacted: string; readonly count: number } {
  let redacted = text
  let count = 0

  for (const { type, pattern } of SECRET_PATTERNS) {
    pattern.lastIndex = 0
    const replacement = `[REDACTED-${type}]`
    const before = redacted
    redacted = redacted.replace(pattern, replacement)
    // Count how many replacements were made by comparing
    if (redacted !== before) {
      // Re-count by running the pattern on the original segment
      pattern.lastIndex = 0
      let match = pattern.exec(before)
      while (match !== null) {
        count++
        match = pattern.exec(before)
      }
    }
  }

  return { redacted, count }
}

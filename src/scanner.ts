import type { Detection, ScanResult } from './types.js'
import { SECRET_PATTERNS } from './patterns.js'

function truncateMatch (match: string): string {
  if (match.length <= 8) {
    return match
  }
  return `${match.slice(0, 8)}...`
}

export function scan (text: string): ScanResult {
  const detections: Detection[] = []

  for (const { type, pattern } of SECRET_PATTERNS) {
    // Reset lastIndex since we reuse patterns with /g flag
    pattern.lastIndex = 0
    let match = pattern.exec(text)
    while (match !== null) {
      detections.push({
        type,
        match: truncateMatch(match[0]),
        index: match.index,
      })
      match = pattern.exec(text)
    }
  }

  return {
    detections,
    clean: detections.length === 0,
  }
}

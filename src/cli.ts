import { fromThrowable } from '@valencets/resultkit'
import { scan } from './scanner.js'

function readStdin (): Promise<string> {
  return new Promise((resolve) => {
    let data = ''
    process.stdin.setEncoding('utf-8')
    process.stdin.on('data', (chunk: string) => {
      data += chunk
    })
    process.stdin.on('end', () => {
      resolve(data)
    })
  })
}

function extractToolResponse (payload: Record<string, unknown>): string {
  const toolResponse = payload['tool_response']
  if (toolResponse === undefined || toolResponse === null) {
    return ''
  }
  if (typeof toolResponse === 'string') {
    return toolResponse
  }
  const safeStringify = fromThrowable(
    (val: unknown) => JSON.stringify(val),
    () => ''
  )
  const result = safeStringify(toolResponse)
  return result.isOk() ? result.value : ''
}

function formatOutput (labels: readonly string[]): string {
  const uniqueLabels = [...new Set(labels)]
  const count = labels.length
  const labelList = uniqueLabels.join(', ')
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PostToolUse',
      additionalContext: `[SECRET-TRIPWIRE] WARNING: Detected ${count} potential secret${count === 1 ? '' : 's'} (${labelList}) in tool output. DO NOT repeat or reference the raw output. The secrets have been logged for review.`,
    },
  })
}

export async function run (): Promise<void> {
  const raw = await readStdin()

  if (raw.trim().length === 0) {
    process.exit(0)
    return
  }

  const safeParse = fromThrowable(
    (text: string) => JSON.parse(text) as Record<string, unknown>,
    () => null
  )

  const parseResult = safeParse(raw)
  if (parseResult.isErr() || parseResult.value === null) {
    // Parse failed — advisory hook, always exit 0
    process.exit(0)
    return
  }

  const payload = parseResult.value
  const toolResponse = extractToolResponse(payload)

  if (toolResponse.length === 0) {
    process.exit(0)
    return
  }

  const scanResult = scan(toolResponse)

  if (!scanResult.clean) {
    const labels = scanResult.detections.map((d) => {
      const labelMap: Record<string, string> = {
        AWS_KEY: 'AWS Access Key',
        GITHUB_TOKEN: 'GitHub Token',
        PRIVATE_KEY: 'Private Key',
        JWT: 'JWT Token',
        CONNECTION_STRING: 'Connection String',
        API_KEY: 'API Key',
        BEARER_TOKEN: 'Bearer Token',
      }
      return labelMap[d.type] ?? d.type
    })
    process.stdout.write(formatOutput(labels) + '\n')
  }

  process.exit(0)
}

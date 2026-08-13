/** Runtime security policy and canonical redaction for DeepSeek Harness. */

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import type { Context } from '@deepseek-ai/cordis'
import type { CommandInvocation } from '@deepseek-ai/dsh-commands'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import type { ContentBlock } from '@deepseek-ai/dsh-llm'
import type { JsonValue } from '@deepseek-ai/dsh-session'
import type {} from '@deepseek-ai/dsh-skill'
import type { PostToolDecision, PreToolDecision, ToolExecution, ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import z from '@deepseek-ai/schemastery'

/** Loader-facing plugin name. */
export const name = 'guardian'

/** Services required for runtime enforcement and the review command. */
export const inject = ['commands', 'skills', 'tools']

const PACKAGE_ROOT = fileURLToPath(new URL('../', import.meta.url))
const COMMAND_KEYS = ['command', 'script', 'query', 'sql'] as const
const PATH_KEYS = ['path', 'file_path', 'filePath', 'target'] as const

/** Built-in enforcement profile. */
export type GuardianProfile = 'strict' | 'standard' | 'permissive'

/** User-configured argument rule evaluated as a regular expression over JSON arguments. */
export interface GuardianRuleConfig {
  readonly name: string
  readonly pattern: string
  readonly flags?: string
  readonly action: 'deny' | 'ask'
  readonly reason: string
}

/** User-configured redaction expression. */
export interface RedactionPatternConfig {
  readonly label: string
  readonly pattern: string
  readonly flags?: string
}

/** Output redaction configuration. */
export interface RedactionConfig {
  readonly enabled?: boolean
  readonly patterns?: RedactionPatternConfig[]
}

/** Deployment configuration for Guardian. */
export interface Config {
  readonly profile?: GuardianProfile
  readonly rules?: GuardianRuleConfig[]
  readonly redaction?: RedactionConfig
}

/** Loader validation for Guardian configuration. */
export const Config: z<Config> = z.object({
  profile: z.union(['strict', 'standard', 'permissive']).default('standard'),
  rules: z.array(z.object({
    name: z.string(),
    pattern: z.string(),
    flags: z.string().default(''),
    action: z.union(['deny', 'ask']),
    reason: z.string(),
  })).default([]),
  redaction: z.object({
    enabled: z.boolean().default(true),
    patterns: z.array(z.object({
      label: z.string(),
      pattern: z.string(),
      flags: z.string().default(''),
    })).default([]),
  }).default({ enabled: true, patterns: [] }),
})

interface CompiledRule {
  readonly name: string
  readonly action: 'deny' | 'ask'
  readonly reason: string
  matches(exec: ToolExecution): boolean
}

/** Compiled expression accepted by the standalone redaction helpers. */
export interface CompiledRedaction {
  readonly label: string
  readonly expression: RegExp
}

interface ResolvedConfig {
  readonly rules: readonly CompiledRule[]
  readonly redaction: readonly CompiledRedaction[]
}

/** Result of one recursive redaction pass. */
export interface RedactionResult<T> {
  readonly value: T
  readonly count: number
  readonly labels: readonly string[]
}

const BUILTIN_REDACTIONS: readonly RedactionPatternConfig[] = [
  { label: 'aws-access-key', pattern: '\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b' },
  { label: 'github-token', pattern: '\\bgh[pousr]_[A-Za-z0-9_]{20,255}\\b' },
  { label: 'api-key', pattern: '\\bsk-[A-Za-z0-9_-]{16,}\\b' },
  { label: 'private-key', pattern: '-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\\s\\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----' },
  { label: 'credential', pattern: '\\b(?:api[_-]?key|access[_-]?token|password|secret)\\s*[:=]\\s*["\\x27]?[^\\s,"\\x27}]{8,}' },
]

function commandArguments(exec: ToolExecution): string {
  if (typeof exec.arguments !== 'object' || exec.arguments === null || Array.isArray(exec.arguments)) return ''
  const record = exec.arguments as Record<string, unknown>
  return COMMAND_KEYS.flatMap(key => typeof record[key] === 'string' ? [record[key] as string] : []).join('\n')
}

function protectedPath(exec: ToolExecution): boolean {
  if (typeof exec.arguments !== 'object' || exec.arguments === null || Array.isArray(exec.arguments)) return false
  const record = exec.arguments as Record<string, unknown>
  return PATH_KEYS.some((key) => {
    const value = record[key]
    return typeof value === 'string' && (value === '/etc' || value.startsWith('/etc/'))
  })
}

function builtInRules(profile: GuardianProfile): CompiledRule[] {
  const rules: CompiledRule[] = [
    {
      name: 'recursive-force-delete-root',
      action: 'deny',
      reason: 'recursive force deletion of a root or home path is blocked',
      matches: exec => /(?:^|[;&|]\s*)rm\s+(?=[^\n]*-[^\n]*r)(?=[^\n]*-[^\n]*f)[^\n]*(?:\s\/|\s~|\s\$HOME)(?:\s|$)/iu.test(commandArguments(exec)),
    },
    {
      name: 'remote-script-pipe',
      action: 'deny',
      reason: 'piping a network response directly into a shell is blocked',
      matches: exec => /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|fi)?sh\b/iu.test(commandArguments(exec)),
    },
    {
      name: 'device-overwrite',
      action: 'deny',
      reason: 'raw writes to device nodes are blocked',
      matches: exec => /\bdd\b[^\n]*\bof=\/dev\//iu.test(commandArguments(exec)),
    },
    {
      name: 'protected-system-path',
      action: 'deny',
      reason: 'writes to /etc are blocked by the Guardian policy',
      matches: exec => protectedPath(exec) || /(?:>|\btee\b)\s*\/etc(?:\/|\s|$)/iu.test(commandArguments(exec)),
    },
    {
      name: 'force-push',
      action: 'ask',
      reason: 'force-pushing can replace remote history',
      matches: exec => /\bgit\s+push\b[^\n]*(?:--force(?!-with-lease)|\s-f(?:\s|$))/iu.test(commandArguments(exec)),
    },
    {
      name: 'destructive-sql',
      action: 'ask',
      reason: 'destructive SQL requires explicit review',
      matches: exec => /\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE)\b/iu.test(commandArguments(exec)),
    },
    {
      name: 'recursive-force-delete',
      action: 'ask',
      reason: 'recursive force deletion requires explicit review',
      matches: exec => /(?:^|[;&|]\s*)rm\s+(?=[^\n]*-[^\n]*r)(?=[^\n]*-[^\n]*f)/iu.test(commandArguments(exec)),
    },
  ]
  if (profile === 'strict') {
    rules.push({
      name: 'sudo',
      action: 'ask',
      reason: 'privileged command execution requires explicit review in strict mode',
      matches: exec => /(?:^|[;&|]\s*)sudo\s+/iu.test(commandArguments(exec)),
    })
  }
  return profile === 'permissive' ? rules.filter(rule => rule.action === 'deny') : rules
}

function regexFlags(flags: string | undefined): string {
  const requested = flags ?? ''
  if (/[^imsu]/u.test(requested)) throw new TypeError(`unsupported regular-expression flags ${JSON.stringify(requested)}`)
  return [...new Set(`${requested}g`)].join('')
}

function compileRule(rule: GuardianRuleConfig): CompiledRule {
  if (rule.name.trim().length === 0 || rule.reason.trim().length === 0) {
    throw new TypeError('custom Guardian rules require non-empty name and reason')
  }
  const expression = new RegExp(rule.pattern, regexFlags(rule.flags))
  return {
    name: rule.name,
    action: rule.action,
    reason: rule.reason,
    matches: exec => {
      expression.lastIndex = 0
      return expression.test(JSON.stringify(exec.arguments))
    },
  }
}

function compileRedaction(pattern: RedactionPatternConfig): CompiledRedaction {
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(pattern.label)) {
    throw new TypeError(`redaction label must be lower-kebab-case, got ${JSON.stringify(pattern.label)}`)
  }
  return { label: pattern.label, expression: new RegExp(pattern.pattern, regexFlags(pattern.flags)) }
}

function resolveConfig(config: Config): ResolvedConfig {
  const profile = config.profile ?? 'standard'
  const enabled = config.redaction?.enabled ?? true
  return {
    rules: [...builtInRules(profile), ...(config.rules ?? []).map(compileRule)],
    redaction: enabled
      ? [...BUILTIN_REDACTIONS, ...(config.redaction?.patterns ?? [])].map(compileRedaction)
      : [],
  }
}

function redactString(input: string, patterns: readonly CompiledRedaction[]): RedactionResult<string> {
  let value = input
  let count = 0
  const labels = new Set<string>()
  for (const pattern of patterns) {
    pattern.expression.lastIndex = 0
    value = value.replace(pattern.expression, () => {
      count += 1
      labels.add(pattern.label)
      return `<redacted:${pattern.label}>`
    })
  }
  return { value, count, labels: [...labels] }
}

/** Redact strings recursively while preserving the JSON value's non-string types and structure. */
export function redactJson(value: JsonValue, patterns: readonly CompiledRedaction[]): RedactionResult<JsonValue> {
  if (typeof value === 'string') return redactString(value, patterns)
  if (value === null || typeof value !== 'object') return { value, count: 0, labels: [] }
  let count = 0
  const labels = new Set<string>()
  if (Array.isArray(value)) {
    const output = value.map((item) => {
      const result = redactJson(item, patterns)
      count += result.count
      for (const label of result.labels) labels.add(label)
      return result.value
    })
    return { value: output, count, labels: [...labels] }
  }
  const output: Record<string, JsonValue> = {}
  for (const [key, item] of Object.entries(value)) {
    const result = redactJson(item, patterns)
    count += result.count
    for (const label of result.labels) labels.add(label)
    output[key] = result.value
  }
  return { value: output, count, labels: [...labels] }
}

/** Redact consecutive text blocks as one stream so a credential split across blocks is still removed. */
export function redactContent(blocks: readonly ContentBlock[], patterns: readonly CompiledRedaction[]): RedactionResult<ContentBlock[]> {
  const output: ContentBlock[] = []
  let count = 0
  const labels = new Set<string>()
  for (let index = 0; index < blocks.length;) {
    const block = blocks[index]
    if (block === undefined) break
    if (block.type !== 'text') {
      output.push(block)
      index += 1
      continue
    }
    const texts: string[] = []
    while (index < blocks.length && blocks[index]?.type === 'text') {
      texts.push((blocks[index] as Extract<ContentBlock, { type: 'text' }>).text)
      index += 1
    }
    const result = redactString(texts.join(''), patterns)
    count += result.count
    for (const label of result.labels) labels.add(label)
    output.push({ type: 'text', text: result.value })
  }
  return { value: output, count, labels: [...labels] }
}

function policyDecision(rules: readonly CompiledRule[], exec: ToolExecution): { action: 'deny' | 'ask'; reason: string } | undefined {
  const matched = rules.filter(rule => rule.matches(exec))
  const rule = matched.find(candidate => candidate.action === 'deny') ?? matched[0]
  return rule === undefined ? undefined : { action: rule.action, reason: `${rule.name}: ${rule.reason}` }
}

function combinePolicy(guardian: ReturnType<typeof policyDecision>, downstream: PreToolDecision): PreToolDecision {
  if (downstream.kind === 'deny' || guardian === undefined) return downstream
  if (guardian.action === 'deny') return { kind: 'deny', reason: guardian.reason }
  if (downstream.kind === 'ask') return downstream
  return { kind: 'ask', reason: guardian.reason }
}

function redactPostDecision(
  result: Readonly<ToolExecutionResult>,
  decision: PostToolDecision,
  patterns: readonly CompiledRedaction[],
): { readonly decision: PostToolDecision; readonly count: number; readonly labels: readonly string[] } {
  if (decision.kind === 'block') {
    const redacted = redactContent(decision.feedback, patterns)
    return { decision: redacted.count === 0 ? decision : { ...decision, feedback: redacted.value }, count: redacted.count, labels: redacted.labels }
  }
  const replacementValue = 'value' in decision ? decision.value : undefined
  const canonicalValue = replacementValue ?? (result.isError ? undefined : result.value)
  if (canonicalValue !== undefined) {
    const redacted = redactJson(canonicalValue, patterns)
    if (redacted.count > 0) {
      return {
        decision: { kind: 'accept', value: redacted.value, ...decision.additionalContexts === undefined ? {} : { additionalContexts: decision.additionalContexts } },
        count: redacted.count,
        labels: redacted.labels,
      }
    }
  }
  const content = decision.content ?? result.content
  const redacted = redactContent(content, patterns)
  return {
    decision: redacted.count === 0
      ? decision
      : { kind: 'accept', content: redacted.value, ...decision.additionalContexts === undefined ? {} : { additionalContexts: decision.additionalContexts } },
    count: redacted.count,
    labels: redacted.labels,
  }
}

function dispatchReview(invocation: CommandInvocation): void {
  invocation.signal.throwIfAborted()
  const guidance = invocation.rawInput.trim()
  invocation.agent.followup(createUserMessage({
    content: [{ type: 'text', text: guidance.length === 0 ? '/security-review' : `/security-review ${guidance}` }],
    source: { kind: 'user' },
  }))
}

function skillContent(): string {
  return readFileSync(new URL('../skills/security-review/SKILL.md', import.meta.url), 'utf8')
}

/** Register the policy waterfall, canonical redaction, and security-review workflow. */
export function apply(ctx: Context, config: Config = {}): void {
  const resolved = resolveConfig(config)

  ctx.skills.register({
    name: 'security-review',
    description: 'Review the current change set for concrete security vulnerabilities and missing controls.',
    content: skillContent(),
    source: 'bundled',
    resourceBase: { kind: 'directory', path: PACKAGE_ROOT },
  })
  ctx.commands.register({
    name: 'security-review',
    description: 'Run a focused security review of the current change set',
    input: { hint: '[scope or threat-model guidance]' },
    handler: (invocation) => {
      dispatchReview(invocation)
      return { kind: 'success', text: 'queued security review' }
    },
  })

  ctx.on('tools/pre-execute', async (exec, next) => {
    const guardian = policyDecision(resolved.rules, exec)
    const downstream = await next()
    return combinePolicy(guardian, downstream)
  })

  ctx.on('tools/post-execute', async (exec, result, next) => {
    const downstream = await next()
    if (resolved.redaction.length === 0) return downstream
    const redacted = redactPostDecision(result, downstream, resolved.redaction)
    if (redacted.count > 0) {
      ctx.logger.info(`[guardian] redacted ${redacted.count} sensitive value(s) from ${exec.name}; labels=${redacted.labels.join(',')}`)
    }
    return redacted.decision
  })
}

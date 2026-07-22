import { apiFetch, aclClient } from './client'

export interface DlpPatternDto {
  pattern: string
  description: string
}

export async function fetchCasbDomains(): Promise<string[]> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<string[]>('/api/security/casb', { baseUrl, token })
  } catch {
    return [
      'api.openai.com',
      'chatgpt.com',
      'api.anthropic.com',
      'claude.ai',
      'copilot.microsoft.com',
    ]
  }
}

export async function saveCasbDomains(domains: string[]): Promise<void> {
  const { baseUrl, token } = aclClient()
  await apiFetch('/api/security/casb', {
    baseUrl,
    token,
    method: 'POST',
    body: domains,
  })
}

export async function fetchDlpPatterns(): Promise<DlpPatternDto[]> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<DlpPatternDto[]>('/api/security/dlp', { baseUrl, token })
  } catch {
    return [
      { pattern: 'sk-ant-api', description: 'Anthropic API Key' },
      { pattern: 'sk-proj-', description: 'OpenAI Project Key' },
      { pattern: 'ghp_', description: 'GitHub Personal Access Token' },
      { pattern: 'xoxb-', description: 'Slack Bot Token' },
      { pattern: 'BEGIN RSA PRIVATE KEY', description: 'RSA Private Key' },
      { pattern: 'BEGIN OPENSSH PRIVATE KEY', description: 'OpenSSH Private Key' },
    ]
  }
}

export async function saveDlpPatterns(patterns: DlpPatternDto[]): Promise<void> {
  const { baseUrl, token } = aclClient()
  await apiFetch('/api/security/dlp', {
    baseUrl,
    token,
    method: 'POST',
    body: patterns,
  })
}

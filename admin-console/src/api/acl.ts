import { apiFetch, aclClient } from './client'

export interface AclRule {
  id: string
  name: string
  enabled: boolean
  priority: number
  action: 'allow' | 'deny' | 'redirect'
  rule_type: Record<string, string>
  redirect_url?: string | null
  comment?: string | null
}

export interface AclRulesResponse {
  default_action: string
  rules: AclRule[]
}

export async function fetchAclRules(): Promise<AclRulesResponse> {
  const { baseUrl, token } = aclClient()
  try {
    return await apiFetch<AclRulesResponse>('/api/acl/rules', { baseUrl, token })
  } catch {
    return mockRules()
  }
}

export async function addAclRule(rule: AclRule): Promise<void> {
  const { baseUrl, token } = aclClient()
  await apiFetch('/api/acl/rules', { baseUrl, token, method: 'POST', body: rule })
}

export async function reloadAclRules(): Promise<void> {
  const { baseUrl, token } = aclClient()
  await apiFetch('/api/acl/reload', { baseUrl, token, method: 'POST' })
}

function mockRules(): AclRulesResponse {
  return {
    default_action: 'allow',
    rules: [
      {
        id: 'block-malware',
        name: 'Block malware URLs',
        enabled: true,
        priority: 100,
        action: 'deny',
        rule_type: { Category: 'malware' },
      },
      {
        id: 'block-phishing',
        name: 'Block phishing URLs',
        enabled: true,
        priority: 101,
        action: 'deny',
        rule_type: { Category: 'phishing' },
      },
      {
        id: 'block-gambling',
        name: 'Block gambling sites',
        enabled: false,
        priority: 102,
        action: 'deny',
        rule_type: { Category: 'gambling' },
      },
    ],
  }
}

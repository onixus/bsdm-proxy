import { Checkbox, FormGrid, FormSection, Input, Select } from '../../../components/ui/Form'
import type { FormTabProps } from '../types'

export function AuthTab({ form, update, tr }: FormTabProps) {
  return (
    <div className="space-y-4">
      <FormSection title={tr.settings.tabAuth}>
        <Checkbox label="AUTH_ENABLED" checked={form.authEnabled} onChange={(v) => update('authEnabled', v)} />
        {form.authEnabled && (
          <>
            <FormGrid>
              <Select
                label="AUTH_BACKEND"
                value={form.authBackend}
                onChange={(e) => update('authBackend', e.target.value)}
                options={[
                  { value: 'basic', label: 'basic' },
                  { value: 'ldap', label: 'ldap' },
                  { value: 'ntlm', label: 'ntlm' },
                ]}
              />
              <Input
                label="AUTH_CACHE_TTL"
                type="number"
                value={form.authCacheTtl}
                onChange={(e) => update('authCacheTtl', e.target.value)}
              />
            </FormGrid>
            <Input
              label="AUTH_REALM"
              value={form.authRealm}
              onChange={(e) => update('authRealm', e.target.value)}
            />
            {form.authBackend === 'ldap' && (
              <>
                <FormGrid>
                  <Input
                    label="LDAP_SERVERS"
                    value={form.ldapServers}
                    onChange={(e) => update('ldapServers', e.target.value)}
                  />
                  <Input
                    label="LDAP_BASE_DN"
                    value={form.ldapBaseDn}
                    onChange={(e) => update('ldapBaseDn', e.target.value)}
                  />
                </FormGrid>
                <FormGrid>
                  <Input
                    label="LDAP_BIND_DN"
                    value={form.ldapBindDn}
                    onChange={(e) => update('ldapBindDn', e.target.value)}
                  />
                  <Input
                    label="LDAP_BIND_PASSWORD"
                    type="password"
                    value={form.ldapBindPassword}
                    onChange={(e) => update('ldapBindPassword', e.target.value)}
                    hint="Session-only, never persisted"
                  />
                </FormGrid>
                <Input
                  label="LDAP_USER_FILTER"
                  value={form.ldapUserFilter}
                  onChange={(e) => update('ldapUserFilter', e.target.value)}
                />
                <Checkbox
                  label="LDAP_USE_TLS"
                  checked={form.ldapUseTls}
                  onChange={(v) => update('ldapUseTls', v)}
                />
              </>
            )}
            {form.authBackend === 'ntlm' && (
              <FormGrid>
                <Input
                  label="NTLM_DOMAIN"
                  value={form.ntlmDomain}
                  onChange={(e) => update('ntlmDomain', e.target.value)}
                />
                <Input
                  label="NTLM_WORKSTATION"
                  value={form.ntlmWorkstation}
                  onChange={(e) => update('ntlmWorkstation', e.target.value)}
                />
              </FormGrid>
            )}
          </>
        )}
      </FormSection>

      <FormSection title="ZTNA / IAP Reverse Proxy">
        <p className="mb-2 text-xs text-text-secondary">Experimental (Frozen) — not pilot day-1.</p>
        <Checkbox
          label="REVERSE_PROXY_ENABLED"
          checked={form.reverseProxyEnabled}
          onChange={(v) => update('reverseProxyEnabled', v)}
          hint="Enable reverse proxy mode"
        />
        {form.reverseProxyEnabled && (
          <>
            <Input
              label="REVERSE_PROXY_UPSTREAM"
              value={form.reverseProxyUpstream}
              onChange={(e) => update('reverseProxyUpstream', e.target.value)}
              hint="Internal backend URL (e.g. http://internal-app:8080)"
            />
            <FormGrid>
              <Input
                label="OIDC_CLIENT_ID"
                value={form.oidcClientId}
                onChange={(e) => update('oidcClientId', e.target.value)}
              />
              <Input
                label="OIDC_CLIENT_SECRET"
                type="password"
                value={form.oidcClientSecret}
                onChange={(e) => update('oidcClientSecret', e.target.value)}
              />
            </FormGrid>
            <FormGrid>
              <Input
                label="OIDC_ISSUER_URL"
                value={form.oidcIssuerUrl}
                onChange={(e) => update('oidcIssuerUrl', e.target.value)}
              />
              <Input
                label="OIDC_REDIRECT_URI"
                value={form.oidcRedirectUri}
                onChange={(e) => update('oidcRedirectUri', e.target.value)}
              />
            </FormGrid>
          </>
        )}
      </FormSection>
    </div>
  )
}

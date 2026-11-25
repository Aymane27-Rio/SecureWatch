const SSH_FINDINGS = {
  permitrootlogin: {
    title: 'Review direct root SSH access',
    explanation: 'Direct root login exposes the most privileged account to remote authentication.',
  },
  passwordauthentication: {
    title: 'Review SSH password authentication',
    explanation: 'Password login can be exposed to guessing and credential reuse when SSH is reachable.',
  },
  permitemptypasswords: {
    title: 'Disable empty-password SSH access',
    explanation: 'An account with no password may be able to authenticate without a credential.',
  },
  pubkeyauthentication: {
    title: 'Review SSH public-key authentication',
    explanation: 'Public-key authentication provides a stronger alternative when password login is restricted.',
  },
  maxauthtries: {
    title: 'Review SSH authentication attempts',
    explanation: 'A high per-connection attempt limit gives an attacker more guesses before disconnecting.',
  },
}

export const REMEDIATION_PERSONAS = [
  {
    value: 'standard',
    label: 'Standard user',
    advice: 'Ask the host administrator to review this setting. Before restricting SSH access, confirm that an authorized admin account and recovery path still work.',
  },
  {
    value: 'developer',
    label: 'Developer',
    advice: 'Test the change in staging and check deployment automation, service accounts, and SSH Match rules before applying it to production.',
  },
  {
    value: 'pentester',
    label: 'Pentester',
    advice: 'Record the effective setting and evaluated connection context as evidence. Do not change a target unless the engagement explicitly authorizes remediation.',
  },
]

export function getRemediation(event, persona = 'standard') {
  if (event?.category !== 'ssh') return null

  const data = event._data ?? event.data
  if (!data || typeof data !== 'object' || Array.isArray(data)) return null

  const setting = String(data.setting || '').toLowerCase()
  if (!Object.prototype.hasOwnProperty.call(SSH_FINDINGS, setting)) return null
  const finding = SSH_FINDINGS[setting]
  if (!finding || !['string', 'number'].includes(typeof data.current)) return null

  const recommended = data.recommended ?? data.recommended_maximum
  if (!['string', 'number'].includes(typeof recommended)) return null

  const audience = REMEDIATION_PERSONAS.find((item) => item.value === persona)
    || REMEDIATION_PERSONAS[0]

  return {
    ...finding,
    setting,
    current: String(data.current),
    recommended: setting === 'maxauthtries'
      ? `${recommended} or fewer`
      : String(recommended),
    context: typeof data.context === 'string' ? data.context : '',
    advice: audience.advice,
  }
}

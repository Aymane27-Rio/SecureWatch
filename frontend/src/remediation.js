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
    sshAdvice: 'Ask the host administrator to review this setting. Before restricting SSH access, confirm that an authorized admin account and recovery path still work.',
    networkAdvice: 'Ask the host administrator to identify the service and confirm whether it should be listening. Do not block the port until remote access and dependent services are understood.',
  },
  {
    value: 'developer',
    label: 'Developer',
    sshAdvice: 'Test the change in staging and check deployment automation, service accounts, and SSH Match rules before applying it to production.',
    networkAdvice: 'Identify the owning process and service, then verify its bind address and deployment need. Test any restriction in staging and update the managed service or firewall configuration through your deployment workflow.',
  },
  {
    value: 'pentester',
    label: 'Pentester',
    sshAdvice: 'Record the effective setting and evaluated connection context as evidence. Do not change a target unless the engagement explicitly authorizes remediation.',
    networkAdvice: 'Record the protocol and port, then test reachability only within the authorized scope. A local listening socket alone does not establish external exposure; do not change the target unless remediation is explicitly authorized.',
  },
]

export function getRemediation(event, persona = 'standard') {
  const data = event?._data ?? event?.data
  if (!data || typeof data !== 'object' || Array.isArray(data)) return null

  const audience = REMEDIATION_PERSONAS.find((item) => item.value === persona)
    || REMEDIATION_PERSONAS[0]

  if (event?.category === 'network') {
    const protocol = String(data.proto || '').toLowerCase()
    if (!['number', 'string'].includes(typeof data.port)) return null
    if (typeof data.port === 'string' && !/^\d{1,5}$/.test(data.port)) return null
    const port = Number(data.port)
    if (!['tcp', 'tcp6', 'udp', 'udp6'].includes(protocol)) return null
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null

    return {
      title: 'Review listening service exposure',
      explanation: 'A local socket is listening on this port. The scan does not identify its owning process or determine whether the socket is reachable from other hosts.',
      setting: 'Listening socket',
      current: `${protocol.toUpperCase()} port ${port}`,
      recommended: 'Confirm the service is required and limit access to trusted interfaces or hosts',
      context: '',
      advice: audience.networkAdvice,
    }
  }

  if (event?.category !== 'ssh') return null

  const setting = String(data.setting || '').toLowerCase()
  if (!Object.prototype.hasOwnProperty.call(SSH_FINDINGS, setting)) return null
  const finding = SSH_FINDINGS[setting]
  if (!finding || !['string', 'number'].includes(typeof data.current)) return null

  const recommended = data.recommended ?? data.recommended_maximum
  if (!['string', 'number'].includes(typeof recommended)) return null

  return {
    ...finding,
    setting,
    current: String(data.current),
    recommended: setting === 'maxauthtries'
      ? `${recommended} or fewer`
      : String(recommended),
    context: typeof data.context === 'string' ? data.context : '',
    advice: audience.sshAdvice,
  }
}

const CSV_HEADERS = [
  'timestamp',
  'severity',
  'severity_label',
  'category',
  'summary',
  'host',
  'data_json',
]

const SEVERITY_LABELS = ['Informational', 'Low', 'Moderate', 'High', 'Critical']

export function csvCell(value) {
  const text = value == null ? '' : String(value)
  const safeText = /^[\u0000-\u0020]*[=+\-@]/.test(text) ? `'${text}` : text
  return `"${safeText.replaceAll('"', '""')}"`
}

export function eventsToCsv(events) {
  const rows = [CSV_HEADERS]

  for (const event of events) {
    const severity = Number(event.severity)
    const severityLabel = Number.isInteger(severity)
      ? SEVERITY_LABELS[severity] || 'Unknown'
      : 'Unknown'
    const eventData = event._data ?? event.data ?? {}

    rows.push([
      event.ts,
      Number.isInteger(severity) ? severity : '',
      severityLabel,
      event.category,
      event.summary,
      event.host,
      JSON.stringify(eventData),
    ])
  }

  return `${rows.map((row) => row.map(csvCell).join(',')).join('\r\n')}\r\n`
}

export function csvFilename(reportId) {
  const safeId = String(reportId || 'scan')
    .replace(/[^a-zA-Z0-9._-]+/g, '_')
    .replace(/^\.+/, '')

  return `securewatch-${safeId || 'scan'}.csv`
}

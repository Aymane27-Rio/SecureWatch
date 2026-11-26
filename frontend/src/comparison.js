const VOLATILE_DATA_KEYS = new Set([
  'count',
  'last_seen',
  'observed_at',
  'timestamp',
  'ts',
  'updated_at',
])

function stableData(value) {
  if (Array.isArray(value)) return value.map(stableData)
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .filter((key) => !VOLATILE_DATA_KEYS.has(key.toLowerCase()))
        .sort((a, b) => a.localeCompare(b))
        .map((key) => [key, stableData(value[key])]),
    )
  }
  return value
}

function eventData(event) {
  let data = event?._data ?? event?.data ?? {}
  if (typeof data === 'string') {
    try {
      data = JSON.parse(data)
    } catch {
      data = {value: data}
    }
  }
  return data
}

function stableSummary(event) {
  const summary = String(event.summary || '')
  if (event.category !== 'auth') return summary
  return summary
    .replace(/^(SSH failed logins from .+): \d+$/, '$1')
    .replace(/^(Sudo authentication failures): \d+$/, '$1')
}

function findingKey(event) {
  return JSON.stringify([
    String(event.category || 'uncategorized'),
    String(event.host || ''),
    stableSummary(event),
    stableData(eventData(event)),
  ])
}

function isFinding(event) {
  return Number(event.severity) > 0
}

/** Compare two reports, matching findings as a multiset by stable identity. */
export function compareReports(currentEvents, previousEvents) {
  const previousByKey = new Map()
  for (const event of previousEvents) {
    if (!isFinding(event)) continue
    const key = findingKey(event)
    const queue = previousByKey.get(key) || []
    queue.push(event)
    previousByKey.set(key, queue)
  }

  const counts = {new: 0, persistent: 0, resolved: 0, severityChanged: 0}
  const events = currentEvents.map((event) => {
    if (!isFinding(event)) return {...event, _change: null}

    const matches = previousByKey.get(findingKey(event))
    const previous = matches?.shift()
    if (!previous) {
      counts.new += 1
      return {...event, _change: 'new'}
    }

    counts.persistent += 1
    const previousSeverity = Number(previous.severity) || 0
    const currentSeverity = Number(event.severity) || 0
    const severityChanged = currentSeverity !== previousSeverity
    if (severityChanged) counts.severityChanged += 1
    return {
      ...event,
      _change: 'persistent',
      _previousSeverity: severityChanged ? previousSeverity : null,
    }
  })

  const resolvedEvents = []
  for (const queue of previousByKey.values()) {
    for (const event of queue) {
      counts.resolved += 1
      resolvedEvents.push(event)
    }
  }

  return {events, resolvedEvents, counts}
}

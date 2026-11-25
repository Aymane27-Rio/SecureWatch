import React, {useEffect, useMemo, useState} from 'react'
import {csvFilename, eventsToCsv} from './csv.js'
import {getRemediation, REMEDIATION_PERSONAS} from './remediation.js'

const PAGE_SIZE = 25
const SEVERITIES = [
  {value: '0', label: 'Informational'},
  {value: '1', label: 'Low'},
  {value: '2', label: 'Moderate'},
  {value: '3', label: 'High'},
  {value: '4', label: 'Critical'},
]

async function fetchJson(path, signal) {
  const response = await fetch(path, {signal})
  if (!response.ok) {
    throw new Error(`Request failed with status ${response.status}`)
  }
  return response.json()
}

function normalizeReports(payload) {
  const items = Array.isArray(payload)
    ? payload
    : Array.isArray(payload?.reports) ? payload.reports : []

  return items
    .map((report) => {
      const id = report.report_id || report.id
      return {
        ...report,
        id: id ? String(id) : '',
        filename: report.filename || report.file || '',
        timestamp: report.ts || report.created_at || id || '',
        total: Number(report.total ?? report.summary?.total ?? 0),
      }
    })
    .filter((report) => report.id)
    .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
}

function normalizeEvents(payload) {
  const events = Array.isArray(payload)
    ? payload
    : Array.isArray(payload?.events) ? payload.events : null

  if (!events) {
    throw new Error('The report response did not contain an event list.')
  }

  return events.map((event, index) => {
    let data = event.data ?? {}
    if (typeof data === 'string') {
      try {
        data = JSON.parse(data)
      } catch {
        data = {value: data}
      }
    }

    const severity = Number(event.severity)
    return {
      ...event,
      _index: index,
      _data: data,
      severity: Number.isInteger(severity) && severity >= 0 && severity <= 4
        ? severity
        : 0,
      category: event.category || 'uncategorized',
      summary: event.summary || 'Unlabeled event',
      host: event.host || '',
    }
  })
}

function formatDate(value) {
  if (!value) return 'Unknown time'

  const source = String(value)
  const stamp = source.match(/^(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})/)
  const date = stamp
    ? new Date(
      Number(stamp[1]), Number(stamp[2]) - 1, Number(stamp[3]),
      Number(stamp[4]), Number(stamp[5]), Number(stamp[6]),
    )
    : new Date(source)

  if (Number.isNaN(date.getTime())) return source
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date)
}

function formatCategory(value) {
  return value
    .split(/[_-]+/)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ')
}

function severityName(value) {
  return SEVERITIES.find((severity) => Number(severity.value) === value)?.label || 'Unknown'
}

function ShieldMark() {
  return (
    <svg viewBox="0 0 40 40" aria-hidden="true" className="brand-mark">
      <path d="M20 3.5 34 9v10.3c0 8.2-5.8 14.1-14 17.2C11.8 33.4 6 27.5 6 19.3V9l14-5.5Z" />
      <path d="m13.7 20.3 4.2 4.2 8.7-9" />
    </svg>
  )
}

function App() {
  const [reports, setReports] = useState([])
  const [selectedReportId, setSelectedReportId] = useState('')
  const [events, setEvents] = useState([])
  const [reportsLoading, setReportsLoading] = useState(true)
  const [eventsLoading, setEventsLoading] = useState(false)
  const [reportsError, setReportsError] = useState('')
  const [eventsError, setEventsError] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [categoryFilter, setCategoryFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [expandedEvent, setExpandedEvent] = useState(null)
  const [remediationPersona, setRemediationPersona] = useState('standard')

  useEffect(() => {
    const controller = new AbortController()

    fetchJson('/api/reports', controller.signal)
      .then((payload) => {
        const items = normalizeReports(payload)
        setReports(items)
        setSelectedReportId((current) => (
          current && items.some((report) => report.id === current)
            ? current
            : items[0]?.id || ''
        ))
      })
      .catch((error) => {
        if (error.name !== 'AbortError') setReportsError('Unable to load scan reports.')
      })
      .finally(() => {
        if (!controller.signal.aborted) setReportsLoading(false)
      })

    return () => controller.abort()
  }, [])

  useEffect(() => {
    if (!selectedReportId) {
      setEvents([])
      setEventsError('')
      setEventsLoading(false)
      return undefined
    }

    const controller = new AbortController()
    setEvents([])
    setEventsError('')
    setEventsLoading(true)
    setSeverityFilter('all')
    setCategoryFilter('all')
    setSearch('')
    setPage(1)
    setExpandedEvent(null)

    fetchJson(`/api/reports/${encodeURIComponent(selectedReportId)}`, controller.signal)
      .then((payload) => setEvents(normalizeEvents(payload)))
      .catch((error) => {
        if (error.name !== 'AbortError') setEventsError('Unable to load this report’s events.')
      })
      .finally(() => {
        if (!controller.signal.aborted) setEventsLoading(false)
      })

    return () => controller.abort()
  }, [selectedReportId])

  const activeReport = reports.find((report) => report.id === selectedReportId)
  const categories = useMemo(
    () => [...new Set(events.map((event) => event.category))].sort((a, b) => a.localeCompare(b)),
    [events],
  )
  const filteredEvents = useMemo(() => {
    const query = search.trim().toLocaleLowerCase()
    return events.filter((event) => {
      if (severityFilter !== 'all' && event.severity !== Number(severityFilter)) return false
      if (categoryFilter !== 'all' && event.category !== categoryFilter) return false
      if (!query) return true
      return [event.summary, event.category, event.host, event.ts]
        .some((value) => String(value || '').toLocaleLowerCase().includes(query))
    })
  }, [events, severityFilter, categoryFilter, search])
  const pageCount = Math.max(1, Math.ceil(filteredEvents.length / PAGE_SIZE))
  const visibleEvents = filteredEvents.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)
  const highSeverityCount = events.filter((event) => event.severity >= 3).length

  useEffect(() => {
    if (page > pageCount) setPage(pageCount)
  }, [page, pageCount])

  useEffect(() => {
    setExpandedEvent(null)
  }, [severityFilter, categoryFilter, search, page])

  function resetFilters() {
    setSeverityFilter('all')
    setCategoryFilter('all')
    setSearch('')
    setPage(1)
  }

  function downloadFilteredEvents() {
    const csv = eventsToCsv(filteredEvents)
    const blob = new Blob(['\uFEFF', csv], {type: 'text/csv;charset=utf-8'})
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = csvFilename(activeReport.id)
    link.hidden = true
    document.body.append(link)
    link.click()
    link.remove()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  return (
    <div className="app-shell">
      <aside className="side-rail" aria-label="Main navigation">
        <a className="brand" href="#top" aria-label="SecureWatch home">
          <ShieldMark />
          <span>Secure<span className="brand-accent">Watch</span></span>
        </a>
        <div className="rail-divider" />
        <div className="rail-label">WORKSPACE</div>
        <a className="nav-item nav-item-active" href="#reports" aria-current="page">
          <span className="nav-icon" aria-hidden="true">◫</span>
          <span>Scan reports</span>
        </a>
        <div className="rail-footer">
          <span className="status-dot" />
          <span>Local security console</span>
        </div>
      </aside>

      <main className="main-content" id="top">
        <header className="page-header">
          <div>
            <div className="eyebrow"><span className="eyebrow-line" /> HOST SECURITY / ANALYTICS</div>
            <h1>Scan reports</h1>
            <p className="page-intro">Review scan history and investigate security events.</p>
          </div>
          <div className="header-status"><span className="status-dot" /> Private workspace</div>
        </header>

        {reportsError && (
          <div className="alert alert-error" role="alert">
            <strong>Reports unavailable</strong>
            <span>{reportsError} Check that the SecureWatch API is running, then reload this page.</span>
          </div>
        )}

        <section className="summary-grid" aria-label="Selected report summary">
          <article className="summary-card">
            <span className="summary-label">REPORT HISTORY</span>
            <strong className="summary-value">{reportsLoading ? '—' : reports.length}</strong>
            <span className="summary-note">scan{reports.length === 1 ? '' : 's'} available</span>
            <span className="summary-icon icon-cyan" aria-hidden="true">▤</span>
          </article>
          <article className="summary-card">
            <span className="summary-label">EVENTS IN REPORT</span>
            <strong className="summary-value">{eventsLoading ? '—' : events.length}</strong>
            <span className="summary-note">{activeReport ? 'selected scan' : 'select a scan to inspect'}</span>
            <span className="summary-icon icon-blue" aria-hidden="true">⌁</span>
          </article>
          <article className="summary-card summary-card-alert">
            <span className="summary-label">HIGH SEVERITY</span>
            <strong className="summary-value">{eventsLoading ? '—' : highSeverityCount}</strong>
            <span className="summary-note">severity 3 or 4</span>
            <span className="summary-icon icon-amber" aria-hidden="true">!</span>
          </article>
          <article className="summary-card summary-card-last">
            <span className="summary-label">SELECTED SCAN</span>
            <strong className="summary-date">{activeReport ? formatDate(activeReport.timestamp) : '—'}</strong>
            <span className="summary-note">{activeReport?.filename || 'No report selected'}</span>
            <span className="summary-icon icon-violet" aria-hidden="true">◷</span>
          </article>
        </section>

        <section className="workspace-grid" id="reports">
          <aside className="panel report-panel" aria-labelledby="history-title">
            <div className="panel-heading">
              <div>
                <div className="section-kicker">HISTORY</div>
                <h2 id="history-title">Recent scans</h2>
              </div>
              <span className="count-pill">{reportsLoading ? '…' : reports.length}</span>
            </div>

            {reportsLoading ? (
              <div className="loading-state"><span className="spinner" /> Loading reports</div>
            ) : reportsError ? (
              <div className="empty-state empty-history">
                <span className="empty-symbol empty-symbol-error" aria-hidden="true">!</span>
                <strong>Report history unavailable</strong>
                <span>Reconnect to the SecureWatch API and reload this page.</span>
              </div>
            ) : reports.length ? (
              <div className="report-list" role="list" aria-label="Available scan reports">
                {reports.map((report) => {
                  const selected = report.id === selectedReportId
                  return (
                    <button
                      className={`report-item${selected ? ' report-item-selected' : ''}`}
                      type="button"
                      key={report.id}
                      onClick={() => setSelectedReportId(report.id)}
                      aria-pressed={selected}
                    >
                      <span className="report-item-top">
                        <span className={`report-state${selected ? ' report-state-active' : ''}`} />
                        <time>{formatDate(report.timestamp)}</time>
                      </span>
                      <span className="report-item-name">{report.filename || report.id}</span>
                      <span className="report-item-bottom">
                        <span>{report.total} event{report.total === 1 ? '' : 's'}</span>
                        {selected && <span className="selected-label">SELECTED</span>}
                      </span>
                    </button>
                  )
                })}
              </div>
            ) : (
              <div className="empty-state empty-history">
                <span className="empty-symbol" aria-hidden="true">▤</span>
                <strong>No reports yet</strong>
                <span>Run a SecureWatch scan to start building report history.</span>
              </div>
            )}
            <div className="panel-footnote">Reports are stored locally on this host.</div>
          </aside>

          <section className="panel events-panel" aria-labelledby="events-title">
            <div className="panel-heading events-heading">
              <div>
                <div className="section-kicker">INVESTIGATION</div>
                <h2 id="events-title">Event explorer</h2>
              </div>
              {activeReport && (
                <div className="event-actions">
                  <button
                    className="export-button"
                    type="button"
                    onClick={downloadFilteredEvents}
                    disabled={eventsLoading || Boolean(eventsError)}
                    aria-label={`Export ${filteredEvents.length} matching events as CSV`}
                  >
                    <span aria-hidden="true">↓</span>
                    Export CSV <span className="export-count">{filteredEvents.length}</span>
                  </button>
                  <a
                    className="json-link"
                    href={`/api/reports/${encodeURIComponent(activeReport.id)}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    View JSON <span aria-hidden="true">↗</span>
                  </a>
                </div>
              )}
            </div>

            <div className="filter-bar">
              <label className="search-field">
                <span className="search-icon" aria-hidden="true">⌕</span>
                <span className="sr-only">Search events</span>
                <input
                  type="search"
                  placeholder="Search event, host, category…"
                  value={search}
                  onChange={(event) => { setSearch(event.target.value); setPage(1) }}
                  disabled={!activeReport || eventsLoading}
                />
                {search && (
                  <button className="clear-search" type="button" onClick={() => { setSearch(''); setPage(1) }} aria-label="Clear search">×</button>
                )}
              </label>
              <label className="filter-select">
                <span className="sr-only">Filter by severity</span>
                <select
                  value={severityFilter}
                  onChange={(event) => { setSeverityFilter(event.target.value); setPage(1) }}
                  disabled={!activeReport || eventsLoading}
                >
                  <option value="all">All severities</option>
                  {SEVERITIES.map((severity) => (
                    <option value={severity.value} key={severity.value}>{severity.label}</option>
                  ))}
                </select>
              </label>
              <label className="filter-select">
                <span className="sr-only">Filter by category</span>
                <select
                  value={categoryFilter}
                  onChange={(event) => { setCategoryFilter(event.target.value); setPage(1) }}
                  disabled={!activeReport || eventsLoading}
                >
                  <option value="all">All categories</option>
                  {categories.map((category) => (
                    <option value={category} key={category}>{formatCategory(category)}</option>
                  ))}
                </select>
              </label>
              {(severityFilter !== 'all' || categoryFilter !== 'all' || search) && (
                <button className="reset-button" type="button" onClick={resetFilters}>Reset</button>
              )}
            </div>

            {eventsError && <div className="inline-error" role="alert">{eventsError}</div>}

            {eventsLoading ? (
              <div className="loading-state loading-events"><span className="spinner" /> Loading report events</div>
            ) : !activeReport ? (
              <div className="empty-state events-empty">
                <span className="empty-symbol" aria-hidden="true">⌁</span>
                <strong>Select a scan report</strong>
                <span>Choose a report from the history panel to inspect its events.</span>
              </div>
            ) : eventsError ? (
              <div className="empty-state events-empty">
                <span className="empty-symbol empty-symbol-error" aria-hidden="true">!</span>
                <strong>Could not load events</strong>
                <span>{eventsError}</span>
              </div>
            ) : events.length === 0 ? (
              <div className="empty-state events-empty">
                <span className="empty-symbol empty-symbol-good" aria-hidden="true">✓</span>
                <strong>No events in this scan</strong>
                <span>The report is valid and contains no recorded findings.</span>
              </div>
            ) : filteredEvents.length === 0 ? (
              <div className="empty-state events-empty">
                <span className="empty-symbol" aria-hidden="true">⌕</span>
                <strong>No matching events</strong>
                <span>Adjust or reset the filters to see more results.</span>
                <button className="secondary-button" type="button" onClick={resetFilters}>Reset filters</button>
              </div>
            ) : (
              <>
                <div className="table-wrap">
                  <table className="event-table">
                    <thead>
                      <tr>
                        <th scope="col">SEVERITY</th>
                        <th scope="col">CATEGORY</th>
                        <th scope="col">EVENT</th>
                        <th scope="col" className="host-column">HOST</th>
                        <th scope="col" className="time-column">TIME</th>
                        <th scope="col"><span className="sr-only">Details</span></th>
                      </tr>
                    </thead>
                    <tbody>
                      {visibleEvents.map((event) => {
                        const expanded = expandedEvent === event._index
                        const remediation = expanded
                          ? getRemediation(event, remediationPersona)
                          : null
                        return (
                          <React.Fragment key={`${selectedReportId}-${event._index}`}>
                            <tr className={`event-row${expanded ? ' event-row-expanded' : ''}`}>
                              <td>
                                <span className={`severity-badge severity-${event.severity}`}>
                                  <span className="severity-dot" />
                                  {severityName(event.severity)}
                                </span>
                              </td>
                              <td><span className="category-label">{formatCategory(event.category)}</span></td>
                              <td className="event-summary-cell">
                                <button
                                  type="button"
                                  className="event-summary-button"
                                  aria-expanded={expanded}
                                  onClick={() => setExpandedEvent(expanded ? null : event._index)}
                                >
                                  {event.summary}
                                </button>
                              </td>
                              <td className="host-column host-cell">{event.host || '—'}</td>
                              <td className="time-column time-cell">{formatDate(event.ts)}</td>
                              <td className="expand-cell">
                                <button
                                  className="expand-button"
                                  type="button"
                                  aria-label={`${expanded ? 'Hide' : 'Show'} details for ${event.summary}`}
                                  aria-expanded={expanded}
                                  onClick={() => setExpandedEvent(expanded ? null : event._index)}
                                >
                                  <span aria-hidden="true">{expanded ? '−' : '+'}</span>
                                </button>
                              </td>
                            </tr>
                            {expanded && (
                              <tr className="details-row">
                                <td colSpan="6">
                                  <div className="event-details">
                                    <div className="detail-meta">
                                      <span><strong>Host</strong>{event.host || 'Not reported'}</span>
                                      <span><strong>Recorded</strong>{formatDate(event.ts)}</span>
                                      <span><strong>Severity</strong>{severityName(event.severity)} ({event.severity})</span>
                                    </div>
                                    {remediation && (
                                      <section className="remediation-card" aria-label="Remediation guidance">
                                        <div className="remediation-heading">
                                          <div>
                                            <div className="section-kicker">ADVISORY NEXT STEP</div>
                                            <h3>{remediation.title}</h3>
                                          </div>
                                          <label className="remediation-persona">
                                            <span>Guidance for</span>
                                            <select
                                              value={remediationPersona}
                                              onChange={(change) => setRemediationPersona(change.target.value)}
                                            >
                                              {REMEDIATION_PERSONAS.map((persona) => (
                                                <option value={persona.value} key={persona.value}>
                                                  {persona.label}
                                                </option>
                                              ))}
                                            </select>
                                          </label>
                                        </div>
                                        <p className="remediation-explanation">{remediation.explanation}</p>
                                        <div className="remediation-values">
                                          <span><strong>Setting</strong><code>{remediation.setting}</code></span>
                                          <span><strong>Observed</strong><code>{remediation.current}</code></span>
                                          <span><strong>Suggested</strong><code>{remediation.recommended}</code></span>
                                        </div>
                                        {remediation.context && (
                                          <p className="remediation-context">
                                            Evaluated connection: <code>{remediation.context}</code>
                                          </p>
                                        )}
                                        <p className="remediation-advice">{remediation.advice}</p>
                                        <p className="remediation-note">
                                          Guidance is advisory. SecureWatch will not change the host configuration.
                                        </p>
                                      </section>
                                    )}
                                    <div className="detail-data-heading">EVENT DATA</div>
                                    <pre className="event-data">{JSON.stringify(event._data, null, 2)}</pre>
                                  </div>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
                <footer className="table-footer">
                  <span>
                    Showing <strong>{(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, filteredEvents.length)}</strong> of <strong>{filteredEvents.length}</strong> events
                    {filteredEvents.length !== events.length && <span> · {events.length} total</span>}
                  </span>
                  <div className="pagination" aria-label="Event pages">
                    <button type="button" onClick={() => setPage((current) => Math.max(1, current - 1))} disabled={page === 1} aria-label="Previous page">‹</button>
                    <span>Page <strong>{page}</strong> of <strong>{pageCount}</strong></span>
                    <button type="button" onClick={() => setPage((current) => Math.min(pageCount, current + 1))} disabled={page === pageCount} aria-label="Next page">›</button>
                  </div>
                </footer>
              </>
            )}
          </section>
        </section>

        <footer className="app-footer">
          <span><ShieldMark /> SecureWatch</span>
          <span>Security events stay within your configured environment.</span>
        </footer>
      </main>
    </div>
  )
}

export default App

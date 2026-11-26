import test from 'node:test'
import assert from 'node:assert/strict'
import {compareReports} from './comparison.js'

function finding(summary, severity = 2, data = {setting: 'PasswordAuthentication'}) {
  return {
    category: 'ssh',
    host: 'server-1',
    summary,
    severity,
    data,
  }
}

test('classifies findings as new, persistent, or resolved', () => {
  const previous = [finding('Persistent finding'), finding('Resolved finding')]
  const current = [finding('Persistent finding'), finding('New finding', 3)]

  const result = compareReports(current, previous)

  assert.deepEqual(result.events.map((event) => event._change), ['persistent', 'new'])
  assert.deepEqual(result.resolvedEvents.map((event) => event.summary), ['Resolved finding'])
  assert.deepEqual(result.counts, {new: 1, persistent: 1, resolved: 1, severityChanged: 0})
})

test('treats a severity-only change as persistent and reports it', () => {
  const result = compareReports(
    [finding('SSH permits root login', 4)],
    [finding('SSH permits root login', 3)],
  )

  assert.equal(result.events[0]._change, 'persistent')
  assert.equal(result.events[0]._previousSeverity, 3)
  assert.equal(result.counts.severityChanged, 1)
  assert.equal(result.counts.new, 0)
  assert.equal(result.counts.resolved, 0)
})

test('matches duplicate findings one occurrence at a time', () => {
  const result = compareReports(
    [finding('Repeated'), finding('Repeated'), finding('Repeated')],
    [finding('Repeated'), finding('Repeated')],
  )

  assert.deepEqual(result.events.map((event) => event._change), ['persistent', 'persistent', 'new'])
  assert.equal(result.counts.new, 1)
  assert.equal(result.counts.persistent, 2)
})

test('ignores object key order and volatile event counts in finding identity', () => {
  const result = compareReports(
    [{...finding('SSH failed logins from 192.0.2.10: 9', 2, {count: 9, ip: '192.0.2.10'}), category: 'auth'}],
    [{...finding('SSH failed logins from 192.0.2.10: 5', 2, {ip: '192.0.2.10', count: 5}), category: 'auth'}],
  )

  assert.equal(result.events[0]._change, 'persistent')
  assert.equal(result.counts.persistent, 1)
  assert.equal(result.counts.new, 0)
  assert.equal(result.counts.resolved, 0)
})

test('package counts change without hiding a different package manager', () => {
  const previous = [
    {...finding('Upgradable packages: 3', 1, {count: 3, manager: 'apt'}), category: 'packages'},
  ]
  const current = [
    {...finding('Upgradable packages: 8', 1, {count: 8, manager: 'apt'}), category: 'packages'},
    {...finding('Upgradable packages: 2', 1, {count: 2, manager: 'dnf'}), category: 'packages'},
  ]

  const result = compareReports(current, previous)
  assert.deepEqual(result.events.map((event) => event._change), ['persistent', 'new'])
  assert.equal(result.counts.resolved, 0)
})

test('rkhunter warning counts remain persistent and zero warnings resolve', () => {
  const warning = (count, severity) => ({
    ...finding(`rkhunter warnings: ${count}`, severity, {warnings: count}),
    category: 'malware',
  })

  const recurring = compareReports([warning(2, 2)], [warning(5, 2)])
  assert.equal(recurring.events[0]._change, 'persistent')

  const cleared = compareReports([warning(0, 0)], [warning(5, 2)])
  assert.equal(cleared.counts.resolved, 1)
  assert.equal(cleared.counts.new, 0)
})

test('file changes on the same path stay persistent as changed attributes vary', () => {
  const changedFile = (path, changes) => ({
    ...finding('Tracked file changed since baseline', 3, {path, changes}),
    category: 'integrity',
  })
  const result = compareReports(
    [changedFile('/etc/passwd', ['mode']), changedFile('/etc/group', ['owner'])],
    [changedFile('/etc/passwd', ['content'])],
  )

  assert.deepEqual(result.events.map((event) => event._change), ['persistent', 'new'])
  assert.equal(result.counts.resolved, 0)
})

test('does not count informational events as findings', () => {
  const result = compareReports(
    [{...finding('Current healthy status', 0)}],
    [{...finding('Previous healthy status', 0)}],
  )

  assert.equal(result.events[0]._change, null)
  assert.deepEqual(result.resolvedEvents, [])
  assert.deepEqual(result.counts, {new: 0, persistent: 0, resolved: 0, severityChanged: 0})
})

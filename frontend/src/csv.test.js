import assert from 'node:assert/strict'
import test from 'node:test'
import {csvCell, csvFilename, eventsToCsv} from './csv.js'

test('CSV cells quote commas, quotes, and line breaks', () => {
  assert.equal(csvCell('first, "second"\nthird'), '"first, ""second""\nthird"')
})

test('CSV cells neutralize spreadsheet formula prefixes', () => {
  assert.equal(csvCell('=1+1'), '"\'=1+1"')
  assert.equal(csvCell('  @SUM(A1)'), '"\'  @SUM(A1)"')
  assert.equal(csvCell('-3'), '"\'-3"')
})

test('event exports include the full event data in CRLF-delimited rows', () => {
  const csv = eventsToCsv([{
    ts: '2026-11-24T12:00:00Z',
    severity: 3,
    category: 'ssh',
    summary: 'Unexpected login, review',
    host: 'host-1',
    _data: {user: 'alice'},
  }])

  assert.equal(
    csv,
    '"timestamp","severity","severity_label","category","summary","host","data_json"\r\n'
      + '"2026-11-24T12:00:00Z","3","High","ssh","Unexpected login, review","host-1","{""user"":""alice""}"\r\n',
  )
})

test('empty reports export a header row and filenames cannot contain paths', () => {
  assert.equal(
    eventsToCsv([]),
    '"timestamp","severity","severity_label","category","summary","host","data_json"\r\n',
  )
  assert.equal(csvFilename('../../events:latest'), 'securewatch-_.._events_latest.csv')
})

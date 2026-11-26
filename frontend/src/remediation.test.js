import assert from 'node:assert/strict'
import test from 'node:test'
import {getRemediation} from './remediation.js'

test('SSH findings get guidance from structured setting evidence', () => {
  const guidance = getRemediation({
    category: 'ssh',
    _data: {
      setting: 'passwordauthentication',
      current: 'yes',
      recommended: 'no',
      context: 'root-external-ipv4',
    },
  })

  assert.equal(guidance.setting, 'passwordauthentication')
  assert.equal(guidance.current, 'yes')
  assert.equal(guidance.recommended, 'no')
  assert.equal(guidance.context, 'root-external-ipv4')
  assert.match(guidance.explanation, /guessing and credential reuse/)
})

test('authentication attempt guidance expresses an upper bound', () => {
  const guidance = getRemediation({
    category: 'ssh',
    _data: {setting: 'maxauthtries', current: 8, recommended_maximum: 4},
  })

  assert.equal(guidance.recommended, '4 or fewer')
})

test('persona guidance changes while observed evidence stays the same', () => {
  const event = {
    category: 'ssh',
    _data: {setting: 'permitrootlogin', current: 'yes', recommended: 'no'},
  }
  const standard = getRemediation(event, 'standard')
  const developer = getRemediation(event, 'developer')
  const pentester = getRemediation(event, 'pentester')

  assert.notEqual(standard.advice, developer.advice)
  assert.notEqual(developer.advice, pentester.advice)
  assert.equal(standard.current, developer.current)
  assert.equal(developer.recommended, pentester.recommended)
  assert.match(pentester.advice, /Do not change a target/)
})

test('listening-port guidance uses the observed protocol and port without assuming exposure', () => {
  const guidance = getRemediation({
    category: 'network',
    _data: {proto: 'tcp6', port: 8443},
  })

  assert.equal(guidance.setting, 'Listening socket')
  assert.equal(guidance.current, 'TCP6 port 8443')
  assert.match(guidance.explanation, /does not identify its owning process/)
  assert.match(guidance.explanation, /reachable from other hosts/)
  assert.match(guidance.recommended, /trusted interfaces or hosts/)
})

test('listening-port guidance is tailored to each persona', () => {
  const event = {category: 'network', _data: {proto: 'udp', port: '5353'}}
  const standard = getRemediation(event, 'standard')
  const developer = getRemediation(event, 'developer')
  const pentester = getRemediation(event, 'pentester')

  assert.notEqual(standard.advice, developer.advice)
  assert.notEqual(developer.advice, pentester.advice)
  assert.match(standard.advice, /Do not block the port/)
  assert.match(developer.advice, /staging/)
  assert.match(pentester.advice, /authorized scope/)
})

test('listening-port guidance rejects incomplete or malformed socket evidence', () => {
  for (const data of [
    {},
    {proto: 'icmp', port: 53},
    {proto: 'tcp', port: 0},
    {proto: 'tcp', port: 65536},
    {proto: 'tcp', port: 1.5},
    {proto: 'tcp', port: true},
    {proto: 'tcp', port: '22/tcp'},
  ]) {
    assert.equal(getRemediation({category: 'network', _data: data}), null)
  }
  assert.equal(getRemediation(undefined), null)
})

test('guidance is omitted for clean, unsupported, or incomplete events', () => {
  assert.equal(getRemediation({category: 'packages', _data: {}}), null)
  assert.equal(getRemediation({category: 'ssh', _data: {verified_settings: 5}}), null)
  assert.equal(getRemediation({
    category: 'ssh',
    _data: {setting: 'unknownsetting', current: 'yes', recommended: 'no'},
  }), null)
  assert.equal(getRemediation({
    category: 'ssh',
    _data: {setting: '__proto__', current: 'yes', recommended: 'no'},
  }), null)
})

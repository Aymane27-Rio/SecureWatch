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

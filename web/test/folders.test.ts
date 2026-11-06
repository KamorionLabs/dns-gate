// EuroDNS folders in the console: folder globs, rules selecting zones by
// folder, the zone list filter and the policy editor.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { folderMatch } from '../src/lib/glob.ts';
import { folderOf, folderOptions, inFolder, rememberFolders, ruleCovers } from '../src/lib/folders.ts';
import { canWriteZone, rbacAllows } from '../src/lib/rights.ts';
import { describePermissions } from '../src/lib/permissions.ts';
import { fromDoc, toDoc } from '../src/lib/editor.ts';
import type { Me } from '../src/lib/types.ts';

test('folder globs: /ES exact, /ES/** below, / the root', () => {
  assert.ok(folderMatch('/ES', '/ES'));
  assert.ok(!folderMatch('/ES', '/ES/Madrid'));
  assert.ok(folderMatch('/ES/**', '/ES/Madrid/Centro'));
  assert.ok(!folderMatch('/ES/**', '/ES'));
  assert.ok(folderMatch('/ES/*', '/ES/Madrid'));
  assert.ok(!folderMatch('/ES/*', '/ES/Madrid/Centro'));
  assert.ok(folderMatch('/', '/'));
  assert.ok(!folderMatch('/**', '/'));
  assert.ok(!folderMatch('/ES', '/es'));
  assert.ok(!folderMatch('/ES', ''));
});

test('rules select zones by folder once the folder is known', () => {
  rememberFolders([{ zone: 'example.es', folder: '/ES/Madrid' }, { zone: 'example.com', folder: '/' }, { zone: 'example.net' }]);
  assert.equal(folderOf('example.es'), '/ES/Madrid');
  assert.equal(folderOf('example.net'), '');
  assert.ok(ruleCovers({ zones: [], folders: ['/ES/**'] }, 'example.es'));
  assert.ok(!ruleCovers({ zones: [], folders: ['/ES/**'] }, 'example.com'));
  assert.ok(ruleCovers({ zones: ['example.net'], folders: ['/ES/**'] }, 'example.net'));
  assert.ok(!ruleCovers({ zones: null, folders: ['/**'] }, 'unknown.org'));

  const me: Me = {
    subject: 'idp:es', name: 'es', category: 'human', roles: ['es'], teams: ['es'], groups: [],
    permissions: [{ role: 'es', zones: [], folders: ['/ES', '/ES/**'], actions: ['dns.record.write'], hosts: [], types: [] }],
  };
  assert.ok(canWriteZone(me, 'example.es'));
  assert.ok(rbacAllows(me, 'example.es', 'www', 'A'));
  assert.ok(!canWriteZone(me, 'example.com'));
  rememberFolders([{ zone: 'example.es', folder: '/FR' }]);
  assert.ok(!canWriteZone(me, 'example.es'), 'a zone moved out of the folder');
  assert.deepEqual(describePermissions(me.permissions!), ['Write records in the zones in folders /ES, /ES/**']);
});

test('the zone list filters on a folder and its subfolders', () => {
  const zones = [{ folder: '/ES/Madrid' }, { folder: '/' }, { folder: '/FR' }, {}];
  assert.deepEqual(folderOptions(zones), ['/', '/ES', '/ES/Madrid', '/FR']);
  assert.ok(inFolder('/ES', '/ES/Madrid'));
  assert.ok(inFolder('/ES', '/ES'));
  assert.ok(!inFolder('/ES', '/ESP'));
  assert.ok(!inFolder('/', '/ES'));
  assert.ok(inFolder('/', '/'));
  assert.ok(inFolder('', undefined));
  assert.ok(!inFolder('/ES', undefined));
});

test('the policy editor keeps the folders of rules', () => {
  const doc = {
    groups: {},
    roles: { es: { rules: [{ zones: [], folders: ['/ES/**'], actions: ['dns.read'] }] } },
    bindings: [],
    virtual_keys: [],
  };
  const back = toDoc(fromDoc(doc));
  assert.deepEqual(back.roles.es?.rules[0], { zones: [], folders: ['/ES/**'], actions: ['dns.read'] });
  const plain = toDoc(fromDoc({ ...doc, roles: { r: { rules: [{ zones: ['example.com'], actions: ['dns.read'] }] } } }));
  assert.deepEqual(plain.roles.r?.rules[0], { zones: ['example.com'], actions: ['dns.read'] });
});

import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const icons = require('../cmd/razvilka/web/ui-icons.js');

// Custom and community services are recognised by ID words or domains.
assert.equal(icons.brandFor({ id: 'custom-telegram-networks', name: 'Telegram · домены и сети' }), 'telegram');
assert.equal(icons.brandFor({ id: 'custom-netflix', name: 'Netflix' }), 'netflix');
assert.equal(icons.brandFor({ id: 'custom-abc', name: 'Мой чат', domains: ['cdn.discordapp.com'] }), 'discord');
assert.equal(icons.brandFor({ id: 'riotgames', name: 'Riot Games · вход' }), 'riotgames');
assert.equal(icons.brandFor({ id: 'nfqws2-common', name: 'Общие CDN и служебные домены', domains: ['example.org'] }), '');
// A word inside another word is not a match ("xbox" is not "x").
assert.equal(icons.brandFor({ id: 'custom-boxes', name: 'Boxes' }), '');
const svg = icons.brandSVG('telegram', 'Telegram <script>');
assert.match(svg, /^<svg class="brand-icon" viewBox="0 0 24 24"/);
assert.doesNotMatch(svg, /<script>/);
assert.equal(icons.brandSVG('unknown'), '');
// Flags: bundled, escaped, and per-flag IDs do not collide in one page.
assert.match(icons.flag('DE', 'Германия'), /^<svg class="flag-icon" viewBox="0 0 640 480" role="img" aria-label="Германия">/);
assert.equal(icons.flag('ZZ'), '');
assert.equal(icons.flag('d"e'), '');
const ids = new Map();
for (const code of icons.flagCodes) {
  for (const [, id] of icons.flag(code).matchAll(/\bid="([^"]+)"/g)) {
    assert(!ids.has(id), `duplicate id ${id} in ${code} and ${ids.get(id)}`);
    ids.set(id, code);
  }
  assert.doesNotMatch(icons.flag(code), /style=/, `inline style in ${code} is blocked by CSP`);
}
for (const slug of icons.brandSlugs) assert.doesNotMatch(icons.brandSVG(slug), /style=/);
console.log('ui icons: ok', icons.flagCodes.length, 'flags', icons.brandSlugs.length, 'brands');

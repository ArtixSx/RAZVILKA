import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const read=name=>readFileSync(new URL('../'+name,import.meta.url),'utf8');
const source=read('cmd/razvilka/web/console.js');
const fn=source.match(/function renderConsoleProviders\(\)\s*\{[\s\S]*?\n\}/)[0];
const presets=[
 {id:'tiagorrg',name:'VLESS Key Checker'},
 {id:'igareck-reality',name:'igareck · Reality'},
 {id:'igareck-black-vless',name:'igareck · VLESS для России'},
 {id:'kort0881',name:'Kort0881'},
 {id:'new-source',name:'<New catalog>'},
];
const card={innerHTML:''};
const ctx=vm.createContext({state:{nodeFeeds:{presets}},$:()=>card,ci:()=>'',esc:value=>String(value).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;')});
vm.runInContext(fn,ctx);ctx.renderConsoleProviders();
for(const preset of presets){
 assert.equal(card.innerHTML.split(`data-r4-fetch="${preset.id}"`).length-1,1,'one check action per actual preset');
 assert.equal(card.innerHTML.split(`data-console-feed="${preset.id}"`).length-1,1,'one subscription action per actual preset');
}
assert.equal(card.innerHTML.split('<article ').length-1,presets.length+2);
assert.match(card.innerHTML,/&lt;New catalog&gt;/);
assert.doesNotMatch(card.innerHTML,/<New catalog>/);
assert.doesNotMatch(read('cmd/razvilka/web/index.html'),/id="nodePublicCatalogs"/,'no duplicate catalog grid');
assert.doesNotMatch(read('cmd/razvilka/web/node-browser.js'),/nodePublicCatalogs/,'no dead renderer or action binding');
ctx.state.nodeFeeds=null;ctx.renderConsoleProviders();
assert.equal(card.innerHTML.split('<article ').length-1,2,'missing API presets cannot become blank custom-source buttons');
assert.doesNotMatch(card.innerHTML,/data-r4-fetch="igareck/);
console.log('PASS provider catalog: one card per preset, exact actions, new presets, unavailable data and escaping');

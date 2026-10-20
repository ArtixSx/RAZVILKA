import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const read=name=>readFileSync(new URL('../'+name,import.meta.url),'utf8');
const root='cmd/razvilka/web/',html=read(root+'index.html');
const version=read('VERSION').trim();
const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);
let count=0;function test(name,fn){fn();count++;console.log('PASS '+name);}
test('unique DOM IDs',()=>assert.equal(new Set(ids).size,ids.length));
const baseline=JSON.parse(read('scripts/fixtures/interface-ui2-ids.json'));
test('all inherited controls retain IDs',()=>assert.deepEqual(baseline.filter(id=>!ids.includes(id)),[]));
test('8 primary destinations',()=>assert.equal([...html.matchAll(/data-main-nav="/g)].length,8));
test('21 retained views',()=>assert.equal(ids.filter(id=>id.startsWith('view-')).length,21));
test('quick setup does not announce a working connection before checking',()=>{
  assert.match(html,/<h2>Быстрая настройка автопилота<\/h2>/);
  assert.doesNotMatch(html,/Три вопроса — и автопилот работает/);
});
test('saved exclusion switches keep checkbox sizing instead of full-width search styling',()=>{
 const css=read(root+'interface-shell.css'),source=read(root+'resource-exclusions-ui.js');
 assert.match(source,/<input id="resourceRussianEnabled" type="checkbox"/);assert.match(source,/<input id="resourceRussianAuto" type="checkbox"/);
 assert.doesNotMatch(css,/\.exclusion-stock input\s*\{/,'generic rule stretches checkbox inputs');
 assert.match(css,/\.exclusion-stock input:not\(\[type=checkbox\]\):not\(\[type=radio\]\)\s*\{[^}]*width:100%/);
});
test('short authentication viewport has its own scroll and safe alignment with a start fallback',()=>{
 const css=read(root+'interface-shell.css');
 const rule=css.match(/\.interface-ui \.auth-screen\{([^}]+)}/);assert.ok(rule);
 assert.match(rule[1],/overflow-y:auto/);assert.match(rule[1],/align-items:start;align-items:safe center/);
 assert.match(html,/<section class="auth-screen"[^>]*id="authScreen"/);
});

test('one compiled stylesheet',()=>assert.equal([...html.matchAll(/rel="stylesheet"/g)].length,1));
test('compiled CSS reproducible',()=>assert.equal(read(root+'interface.css'),read(root+'interface-compat.css')+'\n'+read(root+'interface-shell.css')));
test('home scope body has an inset while its header retains full card width',()=>{
  const css=read(root+'interface-shell.css');
  assert.match(css,/#listScopeContent>\.panel\{padding:22px;min-width:0\}/);
  assert.match(css,/#listScopeContent>\.panel>\.panel-title\{margin:-22px -22px 18px\}/);
});
test('quick start spacing is scoped to visible setup and preserves responsive consent controls',()=>{
  const css=read(root+'interface-shell.css');
  const scope='.interface-ui .autonomy-zone #a1-quickStart:not([hidden])';
  assert.ok(css.includes(scope+'{padding:12px}'));
  assert.ok(css.includes(scope+'>fieldset>.check-row{margin:0;padding:10px;min-width:0}'));
  assert.ok(css.includes(scope+'>fieldset:first-of-type{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}'));
  assert.ok(css.includes('@media(max-width:800px){'+scope+'>fieldset:first-of-type{grid-template-columns:minmax(0,1fr)}}'));
  assert.ok(css.includes(scope+' #a1-quickDevices{grid-column:1/-1}'));
  assert.ok(css.includes(scope+'>.form-footer{display:flex;flex-wrap:wrap;gap:12px}'));
  const rules=css.split('\n').filter(line=>line.includes(scope)).join('\n');
  assert.doesNotMatch(rules,/font-size|position:sticky|display:none/);
});
test('first-run scope radios cannot inherit full-width text fields',()=>{
  assert.match(html,/<input[^>]*name="quick-scope"[^>]*type="radio"/);
  for(const file of ['console-autonomy.css','interface-compat.css','interface.css']){
    const css=read(root+file);
    assert.doesNotMatch(css,/\.console-ui \.autonomy-zone input:not\(\[type=checkbox\]\),/);
    assert.match(css,/\.console-ui \.autonomy-zone input:not\(\[type=checkbox\]\):not\(\[type=radio\]\)/);
    assert.match(css,/\.console-ui \.autonomy-zone input\[type=radio\]\{[^}]*min-height:16px;[^}]*flex:0 0 16px/);
    assert.match(css,/#a1-quickStart \.check-row>span\{min-width:0;overflow-wrap:anywhere\}/);
    assert.match(css,/#a1-quickStart \.form-footer\{[^}]*flex-wrap:wrap/);
  }
});
for(const m of html.matchAll(/<script[^>]+src="([^"]+)"/g))test('current asset cache '+m[1],()=>{const asset=new URL(m[1],'https://razvilka.invalid');assert.equal(asset.searchParams.get('v'),version);assert.ok(read(root+asset.pathname.replace(/^\//,'')).length>0);});
for(const f of ['index.html','interface.js','interface-model.js','console-autonomy.js','console.js','awg-workspace.js','dns-service-lab.js'])test('no preview transport in '+f,()=>assert.doesNotMatch(read(root+f),/__demoData|__demoRequests|window\.fetch\s*=/));
test('no external stylesheet/font',()=>assert.doesNotMatch(html,/(?:href|src)="https?:\/\/[^" ]+\.(?:woff2?|ttf|css|js)/));
test('model never performs requests',()=>assert.doesNotMatch(read(root+'interface-model.js'),/\b(fetch|XMLHttpRequest|setInterval|localStorage|sessionStorage)\s*\(/));
test('group is not a new route',()=>assert.doesNotMatch(read(root+'interface.js'),/route\s*:\s*['"]ai['"]/));
test('destructive action and Apply dialogs announce their actual title and explanation',()=>{
 for(const [id,title,description] of [['actionDialog','actionDialogTitle','actionDialogText'],['applyReviewDialog','applyReviewTitle','applyReviewSubtitle']]){
  const tag=[...html.matchAll(/<dialog\b[^>]*>/g)].map(match=>match[0]).find(tag=>tag.includes(`id="${id}"`));
  assert.ok(tag,id);assert.ok(tag.includes(`aria-labelledby="${title}"`));assert.ok(tag.includes(`aria-describedby="${description}"`));
  for(const target of [title,description])assert.equal(html.split(`id="${target}"`).length-1,1,'dialog references a unique real element');
 }
});

test('every served static dialog has a name without referencing raw details or secret inputs',()=>{
 for(const match of html.matchAll(/<dialog\b[^>]*>/g)){
  const tag=match[0],id=/\bid="([^"]+)"/.exec(tag)?.[1];
  assert.ok(/(?:aria-label|aria-labelledby)="[^"]+"/.test(tag),'unnamed dialog '+id);
  for(const attr of ['aria-labelledby','aria-describedby']){
   const references=new RegExp(attr+'="([^"]+)"').exec(tag)?.[1]?.split(/\s+/)||[];
   for(const target of references){
    if(target==='ui3InspectorTitle'){assert.match(read(root+'interface.js'),/<h2 id="ui3InspectorTitle"/);continue;}
    assert.equal(html.split(`id="${target}"`).length-1,1,'nonunique name target '+target);
    const element=new RegExp('<([a-z0-9]+)\\b[^>]*id="'+target+'"[^>]*>','i').exec(html);
    assert.ok(element);assert.ok(!['textarea','input','pre','code'].includes(element[1]),'dialog announces secret/raw field');
   }
  }
 }
});

test('dynamically created app update dialog is named and reused',()=>{
 const source=read(root+'app-update-ui.js'),fn=source.match(/function ensureAppUpdateDialog\([^]*?\n}\n/);assert.ok(fn);
 let current=null;const attrs={};
 const dialog={setAttribute:(key,value)=>attrs[key]=value,querySelector:()=>({addEventListener(){}}),addEventListener(){}};
 const context=vm.createContext({$:()=>current,document:{createElement:()=>dialog,body:{appendChild:value=>{current=value;}}},closeAppUpdate(){},refreshAppUpdate(){},prepareAppUpdate(){},cancelAppUpdatePreparation(){},installAppUpdate(){}});
 vm.runInContext(fn[0],context);assert.equal(context.ensureAppUpdateDialog(),dialog);assert.equal(attrs['aria-label'],'Обновление приложения');assert.equal(context.ensureAppUpdateDialog(),dialog);
});

test('native inspector accessible name',()=>assert.match(html,/<dialog[^>]*aria-labelledby="ui3InspectorTitle"[^>]*id="ui3ServiceDialog"|<dialog[^>]*id="ui3ServiceDialog"[^>]*aria-labelledby="ui3InspectorTitle"/));
test('retry fenced across authentication epochs',()=>assert.match(read(root+'console-autonomy.js'),/api\(path,method,body,attempt\+1,requestGeneration\)/));
test('mutation timeout',()=>assert.match(read(root+'interface.js'),/setTimeout\(\(\)=>controller\.abort\(\),20000\)/));
test('side drawer always clears on session end',()=>assert.match(read(root+'interface.js'),/interfaceRequests\.clear\(\);interfaceCloseInspector\(\);consoleSnapshot=null/));
test('visible explanations omit obsolete implementation labels',()=>{
 assert.doesNotMatch(html,/ДИАГНОСТИКА · DC1|В A1 автоматический цикл|backend R4|в облако в DC1/);
 assert.doesNotMatch(read(root+'console-autonomy.js'),/пресеты будут сохранены backend|backend A1|работают с rc\.2/);
 assert.match(html,/Правильный адрес ещё не доказывает работу сайта/);
 assert.match(html,/Авторизация, звонки, IPv6 и медиапотоки не выдаются за подтверждённые/);
});
test('palette uses navigation labels and retains old query aliases with exact destinations',()=>{
 const input={value:''},results={innerHTML:''};
 const context=vm.createContext({state:{services:[]},consoleEngineMeta:{},consolePaletteItems:[],consolePaletteIndex:0,
  viewMeta:{connections:['Соединения','Сетевой трафик'],sources:['Источники','Списки доменов'],providers:['Каталог ссылок','Подписки на подключения']},
  document:{getElementById:id=>ids.includes(id)?{}:null},$:id=>id==='#consoleSearchInput'?input:results,ci:()=>'',esc:String});
 vm.runInContext(read(root+'interface-model.js'),context);
 const fn=read(root+'console.js').match(/function consolePalette\([^]*?\n}\n/);assert.ok(fn);
 vm.runInContext(fn[0],context);
 for(const [query,view,label] of [['Соединения','connections','Трафик'],['Трафик','connections','Трафик'],['Источники','sources','Списки сайтов'],['Источники','providers','Источники'],['Каталог ссылок','providers','Источники']]){
  input.value=query;context.consolePalette();
  const result=context.consolePaletteItems.find(item=>item.view===view);assert.ok(result,query+' '+view);assert.equal(result.label,label);
 }
});
console.log(JSON.stringify({suite:'interface-contract',passed:count}));

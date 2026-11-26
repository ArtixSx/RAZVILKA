// Deterministic local CSS build. --check never modifies files.
import {readFileSync,writeFileSync} from 'node:fs';
const root=new URL('../cmd/razvilka/web/',import.meta.url);
const content=['interface-compat.css','interface-shell.css'].map(p=>readFileSync(new URL(p,root),'utf8')).join('\n');
if(process.argv.includes('--check')){
 if(readFileSync(new URL('interface.css',root),'utf8')!==content){console.error('Rebuild interface.css: node scripts/build-interface.mjs');process.exit(1);}
 console.log('interface.css: current');
}else{writeFileSync(new URL('interface.css',root),content);console.log('interface.css: rebuilt');}

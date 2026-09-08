import {readFileSync,writeFileSync} from 'node:fs';
const root=new URL('../web/',import.meta.url);
const content=['interface-compat.css','interface-shell.css'].map(p=>readFileSync(new URL(p,root),'utf8')).join('\n');
if(process.argv.includes('--check')){if(readFileSync(new URL('interface.css',root),'utf8')!==content)process.exit(1);console.log('CSS build: current');}
else writeFileSync(new URL('interface.css',root),content);

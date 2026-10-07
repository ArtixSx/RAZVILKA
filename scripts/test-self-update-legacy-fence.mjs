import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

const root=mkdtempSync(join(tmpdir(),'razvilka-raw-self-fence-'));
const quote=value=>`'${value.replaceAll("'","'\\''")}'`;
const shell=process.argv[2]||'sh';
const fileLimit=spawnSync(shell,['-c','ulimit -f 128'],{encoding:'utf8',timeout:5000});
assert.ifError(fileLimit.error);
// MSYS has no RLIMIT_FSIZE. Model only the successful limit for ABI cases;
// the separate reader fixture proves the actual unsupported host refuses.
const limitModel=fileLimit.status===0?'':'ulimit() { return 0; }\n';
try {
  for (const name of ['upgrade-entware.sh','rollback-entware.sh']) {
    const source=readFileSync(new URL(name,import.meta.url),'utf8').replaceAll('\r\n','\n');
    const start=source.indexOf('require_legacy_file_protocol_free() {\n');
    const end=source.indexOf('\n}\n',start);
    assert(start>=0 && end>start);
    const gate=source.slice(start,end+3);
    const probeStart=source.indexOf('probe_self_update_metadata() (\n');
    const helpers=probeStart>=0?source.slice(probeStart,start):'';
    const stop=source.indexOf('RAZVILKA_BASE="$BASE" "$RAZ_INIT" stop');
    assert(source.indexOf('require_legacy_file_protocol_free',end)<stop);
    assert(source.lastIndexOf('require_legacy_file_protocol_free')>stop);
    mkdirSync(join(root,'bin'),{recursive:true});
    const run=(expected)=>{
      const result=spawnSync(shell,['-s'],{input:`set -eu\nSTATEDIR=${quote(root.replaceAll('\\','/'))}\nBINDIR="$STATEDIR/bin"\n${limitModel}${helpers}\n${gate}\nrequire_legacy_file_protocol_free\n`,encoding:'utf8',timeout:10000});
      assert.ifError(result.error);
      assert.equal(result.status,expected,result.stdout+result.stderr);
    };
    run(0);
    for (const rel of ['self-update/current.json','self-update-files/current.json','self-update-stop']) {
      if (rel.endsWith('.json')) { mkdirSync(join(root,rel,'..'),{recursive:true});writeFileSync(join(root,rel),'{"phase":"accepted"}'); }
      else mkdirSync(join(root,rel));
      run(1);
      rmSync(join(root,rel),{recursive:true});
    }
    const binary=join(root,'bin','razvilka');
    for (const value of ['0','1','2','3','future']) {
      writeFileSync(binary,`#!/bin/sh\ncase "$1" in\n-self-update-read-version) printf 'flag provided but not defined: -self-update-read-version\\n' >&2; exit 2 ;;\n-self-update-schema) printf '%s\\n' '${value}' ;;\n*) exit 99 ;;\nesac\n`,{mode:0o755});
      run(value==='0'||value==='1'?0:1);
    }
    rmSync(binary);
  }
} finally {rmSync(root,{recursive:true,force:true});}
console.log('Raw replacement refused for retained control/file protocol and managed controllers: PASS');

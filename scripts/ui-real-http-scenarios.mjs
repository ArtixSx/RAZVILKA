// Reusable actual HTTP/browser scenarios extracted from the Windows gate.
// All requests use the supplied existing QA instance. No response interception.
import assert from 'node:assert/strict';

const navTo=async(page,name)=>{await page.locator('.nav[data-view="'+name+'"]').click();await page.waitForFunction(name=>state.currentView===name&&!panelLoad.request,name);};

export async function runRealHTTPOfflineSources({page,requests,test,readJSON}) {
  await test('saved Sources uses actual GET-only offline handler','real HTTP; saved metadata only',async()=>{
    const start=requests.length;await navTo(page,'settings');
    // Sources is an advanced Settings task, not a top-level sidebar button.
    const advanced=page.locator('#view-settings details.r5-advanced:has([data-rz-nav="sources"])');
    if(!await advanced.evaluate(element=>element.open))await advanced.locator('summary').click();
    await page.locator('#view-settings [data-rz-nav="sources"]').click();
    await page.waitForFunction(()=>state.currentView==='sources'&&!panelLoad.request&&state.dataLoad.sources?.phase==='ready');
    const catalog=await readJSON('/api/v1/sources/offline');
    assert.equal(catalog.offline,true);assert.equal(catalog.read_only,true);assert(Array.isArray(catalog.sources));
    assert(catalog.sources.every(row=>row.offline===true&&row.ready===false));
    await page.locator('[data-source-view="offline"]').click();
    await page.waitForFunction(()=>state.sourceView==='offline'&&!panelLoad.request&&state.dataLoad.sourceOffline?.phase==='ready');
    assert.equal(await page.locator('#sourceOfflineBanner').isVisible(),true);
    for(const id of ['refreshSources','applySourceChanges','discardSourceChanges'])assert.equal(await page.locator('#'+id).isEnabled(),false);
    const refresh=requests.length;await page.locator('#readSourceView').click();
    await page.waitForFunction(()=>!panelLoad.request&&state.dataLoad.sourceOffline?.phase==='ready');
    assert.equal(requests.slice(refresh).filter(row=>row.path==='/api/v1/sources/offline'&&row.method==='GET').length,1);
    await page.locator('[data-source-view="online"]').click();
    await page.waitForFunction(()=>state.sourceView==='online'&&!panelLoad.request&&state.dataLoad.sources?.phase==='ready');
    assert.equal(requests.slice(start).filter(row=>row.method!=='GET').length,0);
    await navTo(page,'overview');
  });
}

export async function runRealHTTPDraftScenarios({page,requests,test,readJSON,writeJSON,uiReceipt,beforeMutation}) {
  await test('all-VLESS real import and deletion ignore filters and protect group members','real Linux admission, HTTP and public readback; no fault injection',async()=>{
    await navTo(page,'nodes');
    const profiles=[1,2,3].map(n=>`vless://00000000-0000-4000-8000-${String(n).padStart(12,'0')}@ui-node-${n}.invalid:443?type=tcp&security=tls&sni=ui-node-${n}.invalid#UI-F${n}`);
    profiles.push('ss://YWVzLTEyOC1nY206dWktZml4dHVyZQ==@ui-ss.invalid:443#UI-SS');
    await page.locator('#nodeOpenImport').click();await page.locator('#nodeQuickImportText').fill(profiles.join('\n'));
    const imported=await uiReceipt('/api/v1/nodes/import','POST',()=>page.locator('#nodeQuickImportSubmit').click());
    assert.equal(imported?.ok,true);assert.equal(imported.accepted_nodes,profiles.length);assert.equal(imported.working_routes_changed,false);
    await page.waitForFunction(()=>state.nodes.nodes.length===4&&!document.getElementById('nodeQuickImportSubmit').disabled);
    await page.locator('#nodeQuickImportClose').click();
    const snapshot=await readJSON('/api/v1/nodes'),vless=snapshot.nodes.filter(node=>String(node.protocol).trim().toLowerCase()==='vless');assert.equal(vless.length,3);
    const member=vless[1],filter=await page.evaluate(id=>nodeDisplayName(state.nodes.nodes.find(node=>node.id===id)),vless[0].id);
    const group=await writeJSON('/api/v1/node-groups','POST',{name:'UI fixture reserve',mode:'fallback',node_ids:[member.id],preferred_node_id:member.id,hold_down_seconds:1800,confirm:'CREATE_NODE_GROUP'});
    assert.equal(group.ok,true);assert.equal(group.working_routes_changed,false);
    await page.evaluate(()=>refreshNodes());await page.locator('#nodeSearch').fill(filter);
    assert.equal(await page.locator('#nodeList [data-node-card]').count(),1);
    await page.locator('#nodeAllVLESSDetails summary').click();assert.match(await page.locator('#nodeCheckAllVLESS').textContent(),/3/);
    const checkStart=requests.length;await page.locator('#nodeCheckAllVLESS').click();await page.locator('#actionDialog').waitFor({state:'visible'});
    assert.match(await page.locator('#actionDialogText').textContent(),/3 из 3 VLESS/);await page.locator('#actionDialog [value="cancel"]').click();
    await page.waitForFunction(()=>!workflowState.bulkBusy);assert.equal(requests.slice(checkStart).filter(row=>row.path==='/api/v1/node-checks'&&row.method==='POST').length,0);
    const preview=await uiReceipt('/api/v1/nodes/delete-batch','POST',()=>page.locator('#nodeDeleteAllVLESS').click());
    await page.waitForFunction(()=>!!workflowState.deletion&&!workflowState.deleteBusy);
    assert.equal(preview.preview,true);assert.equal(preview.scope,'all-vless');assert.equal(preview.candidates.length,2);assert.equal(preview.skipped.length,1);
    assert.equal(preview.working_routes_changed,false);assert.equal(preview.skipped[0].node_id,member.id);
    const commitStart=requests.length;
    const committed=await uiReceipt('/api/v1/nodes/delete-batch','POST',()=>page.locator('#r4DeleteCommit').click());
    assert.equal(committed.complete,true);assert.equal(committed.deleted.length,2);assert.equal(committed.working_routes_changed,false);
    assert.deepEqual([...committed.deleted].sort(),preview.candidates.map(row=>row.node_id).sort());
    await page.waitForFunction(()=>!workflowState.deleteBusy&&!workflowState.deletion);
    assert.equal(requests.slice(commitStart).filter(row=>row.path==='/api/v1/nodes/delete-batch'&&row.method==='POST').length,1);
    await page.locator('#r4DeleteDialog [data-r4-close]').last().click();
    await page.locator('#refreshNodes').click();await page.waitForFunction(()=>state.nodes.nodes.length===2&&!document.getElementById('refreshNodes').disabled);
    const remaining=await readJSON('/api/v1/nodes');assert.equal(remaining.nodes.length,2);assert.equal(remaining.groups.length,1);
    assert(remaining.nodes.some(node=>node.id===member.id));assert.equal(remaining.nodes.filter(node=>node.protocol==='vless').length,1);
    assert.equal(remaining.nodes.filter(node=>node.protocol==='shadowsocks').length,1);
    await page.locator('#nodeSearch').fill('');await navTo(page,'overview');
  });

  await navTo(page,'autopilot');await page.waitForFunction(()=>!document.getElementById('autoQuickSave').disabled);
  const original=(await readJSON('/api/v1/autonomy')).policy;
  await test('duplicate Save submits one actual PUT with independent readback','real HTTP; disabled QA policy tuning only',async()=>{
    const seconds=original.check_seconds===180?181:180;await page.locator('#autoQuickCheck').fill(String(seconds));
    const start=requests.length;
    await uiReceipt('/api/v1/autonomy','PUT',()=>page.evaluate(()=>{const form=document.getElementById('autoQuickForm');form.requestSubmit();form.requestSubmit();}));
    await page.waitForFunction(()=>!document.getElementById('autoQuickSave').disabled&&!document.getElementById('autoQuickRevision').textContent.includes('есть правки'));
    assert.equal(requests.slice(start).filter(row=>row.path==='/api/v1/autonomy'&&row.method==='PUT').length,1);
    const saved=await readJSON('/api/v1/autonomy');assert.equal(saved.policy.check_seconds,seconds);assert.equal(saved.policy.enabled,false);
  });
  await test('stale policy CAS gets actual 409 and retains draft until reset','real second HTTP writer; no request interception',async()=>{
    await page.locator('#autoQuickCheck').fill('240');const previous=(await readJSON('/api/v1/autonomy')).policy;
    await writeJSON('/api/v1/autonomy','PUT',{expected_revision:previous.revision,policy:{...previous,check_seconds:300},confirm:'SAVE_AUTONOMY',release_safe_mode:false});
    assert.equal(await page.locator('#autoQuickSave').isEnabled(),true,'QA fixture advanced passive UI before stale CAS submission');
    await uiReceipt('/api/v1/autonomy','PUT',()=>page.locator('#autoQuickSave').click(),409);
    await page.waitForFunction(()=>document.getElementById('autoQuickMessage').textContent.includes('изменились'));
    assert.equal(await page.locator('#autoQuickCheck').inputValue(),'240');
    const readback=requests.length;await page.locator('#autoQuickRefresh').click();
    await page.waitForFunction(()=>document.getElementById('autoQuickSave').disabled&&document.getElementById('autoQuickMessage').textContent.includes('Ваши поля сохранены'));
    assert.equal(requests.slice(readback).filter(row=>row.path==='/api/v1/autonomy'&&row.method==='PUT').length,0);
    await page.locator('#autoQuickReset').click();await page.waitForFunction(()=>!document.getElementById('autoQuickSave').disabled);
    assert.equal(await page.locator('#autoQuickCheck').inputValue(),'300');
  });
  // Restore known tuning only after every write/readback above succeeded.
  // Failures leave QA disposal to the coordinator; no uncertain mutation replay.
  await beforeMutation();const current=(await readJSON('/api/v1/autonomy')).policy;
  await writeJSON('/api/v1/autonomy','PUT',{expected_revision:current.revision,policy:{...original,revision:current.revision},confirm:'SAVE_AUTONOMY',release_safe_mode:false});
  const restored=(await readJSON('/api/v1/autonomy')).policy;
  assert.deepEqual({...restored,revision:original.revision},original);
  await navTo(page,'overview');
}

export async function runRealHTTPReadScenarios({page,requests,test,readJSON}) {
  const nav=async name=>{await page.locator('.nav[data-view="'+name+'"]').click();await page.waitForFunction(name=>state.currentView===name,name);};
  await test('cold boot and Nodes observers share reads without caching explicit refresh', 'real HTTP read lifecycle', async()=>{
    const cold=Object.fromEntries(['/api/v1/auth/status','/api/v1/status','/api/v1/panel/inventory','/api/v1/services','/api/v1/metrics'].map(path=>[path,requests.filter(request=>request.path===path).length]));
    for(const [path,count] of Object.entries(cold))assert.equal(count,1,'cold boot restarted '+path);
    const start=requests.length;await page.evaluate(()=>setView('nodes'));
    await page.waitForFunction(()=>!panelLoad.request&&!nodeBrowser.polling&&!nodeActivity.pending);
    const paths=['/api/v1/nodes','/api/v1/routes/options','/api/v1/node-feeds'];
    const entered=Object.fromEntries(paths.map(path=>[path,requests.slice(start).filter(request=>request.path===path).length]));
    for(const [path,count] of Object.entries(entered))assert.equal(count,1,'Nodes duplicated '+path);
    const explicit=requests.length;await page.locator('#refreshNodes').click();await page.waitForFunction(()=>!document.getElementById('refreshNodes').disabled);
    for(const path of paths.slice(0,2))assert.equal(requests.slice(explicit).filter(request=>request.path===path).length,1,'explicit refresh reused '+path);
    await nav('overview');await page.waitForFunction(()=>!panelLoad.request);
    return {cold_reads:cold,nodes_reads:entered,explicit_refresh:'fresh GET'};
  });

  await test('fast transitions and repeated refresh retain current workspace', 'real HTTP', async()=>{
    const writes = requests.filter(r=>r.method!=='GET').length;
    await page.evaluate(()=>{for(const name of ['nodes','services','devices','settings','autopilot','overview'])setView(name);for(let i=0;i<4;i++)void refreshAll();});
    await page.waitForFunction(()=>state.currentView==='overview' && !panelLoad.request);
    assert.equal(await page.locator('.view.active').getAttribute('id'),'view-overview');
    assert.equal(requests.filter(r=>r.method!=='GET').length,writes);
    assert.deepEqual(await page.evaluate(()=>state.uiRenderIssues),{});
  });
  await test('connection REST and stream follow the visible view with single-flight readback','real connection HTTP and SSE lifecycle',async()=>{
    const isConnection=request=>['/api/v1/connections','/api/v1/connections/stream'].includes(request.path);
    const hidden=requests.length;await page.evaluate(async()=>{await refreshConnections();startConnectionStream();});
    assert.equal(requests.slice(hidden).filter(isConnection).length,0,'Home admitted hidden connection reads');
    const entered=requests.length;await page.evaluate(()=>setView('connections'));await page.waitForFunction(()=>state.currentView==='connections'&&!panelLoad.request&&!!state.stream);
    assert.equal(requests.slice(entered).filter(request=>request.path==='/api/v1/connections/stream').length,1);
    const readback=requests.length;await page.evaluate(()=>Promise.all([refreshConnections(),refreshConnections()]));
    assert.equal(requests.slice(readback).filter(request=>request.path==='/api/v1/connections').length,1,'duplicate connection readback sent two GETs');
    await nav('nodes');await page.waitForFunction(()=>!panelLoad.request&&!state.stream);
    assert.equal(await page.evaluate(()=>state.connections.live),false,'retained hidden rows claimed a live stream');
    const left=requests.length;await page.evaluate(async()=>{await refreshConnections();startConnectionStream();});
    assert.equal(requests.slice(left).filter(isConnection).length,0,'Nodes admitted hidden connection reads');
    const returned=requests.length;await page.evaluate(()=>setView('connections'));await page.waitForFunction(()=>state.currentView==='connections'&&!panelLoad.request&&!!state.stream);
    assert.equal(requests.slice(returned).filter(request=>request.path==='/api/v1/connections/stream').length,1,'return did not open exactly one fresh stream');
    await nav('overview');await page.waitForFunction(()=>!panelLoad.request&&!state.stream);
    return {hidden_reads:0,visible_streams_per_entry:1,repeated_readback_gets:1};
  });

  await test('component recovery is a read-only journal view on navigation', 'real recovery GET', async()=>{
    const start=requests.length;await nav('engines');
    await page.waitForFunction(()=>document.querySelector('#view-engines [data-component-recovery-panel]').textContent.includes('Незавершённых обновлений нет'));
    const recovery=await readJSON('/api/v1/components/recovery');assert.equal(recovery.recovery_required,false);
    assert.equal(requests.slice(start).filter(request=>request.method!=='GET').length,0);
    assert.equal(await page.evaluate(()=>componentRecoveryFence()),false);
    await nav('overview');await page.waitForFunction(()=>!panelLoad.request);
  });
    await test('engine card steps keep the chosen engine and dirty profile without writes', 'real engine metadata HTTP and local draft', async()=>{
      const start=requests.length;await nav('engines');await page.evaluate(()=>refreshEngineConfigs());
      await page.waitForFunction(()=>!panelLoad.request);
      assert.equal(requests.slice(start).filter(request=>/^\/api\/v1\/engine-configs\/[^/]+\/guided$/.test(request.path)).length,0,'hidden profile reader ran on the cards page');
      const step=async(id,name)=>{const button=page.locator('[data-engine-step="'+name+'"][data-card-engine="'+id+'"]');if(!await button.isVisible())await page.locator('[data-engine-disclosure="'+id+'-flow"] summary').click();await button.click();};
      const summary=page.locator('[data-engine-disclosure="xray-flow"] summary');await summary.click();await summary.focus();
      await page.evaluate(()=>refreshEngineConfigs());
      assert.equal(await page.locator('[data-engine-disclosure="xray-flow"]').evaluate(element=>element.open),true);
      assert.equal(await summary.evaluate(element=>document.activeElement===element),true,'workflow disclosure lost focus on metadata readback');
      await step('xray','profile');
      await page.waitForFunction(()=>state.currentView==='engineconfig' && state.selectedEngine==='xray');
      await page.waitForFunction(()=>document.activeElement?.id==='engineFileSelect');
      const workspaceProgress=await page.locator('#ui3EngineSteps [data-engine-workspace-progress]').evaluateAll(rows=>rows.map(row=>({step:row.dataset.engineWorkspaceProgress,complete:row.classList.contains('confirmed')})));
      assert.deepEqual(workspaceProgress.map(row=>row.step),['install','profile','check','apply']);
      const matchingProgress=await page.evaluate(()=>engineWorkflowPresentation('xray').complete);
      for(const row of workspaceProgress)assert.equal(row.complete,matchingProgress[row.step],'workspace used unrelated runtime/route proof');
      assert.doesNotMatch(await page.locator('#ui3EngineSteps').textContent(),/Процесс|Маршруты/);
      await page.locator('#engineModeExpert').click();await page.waitForFunction(()=>state.engineMode==='expert');
      const draft='{"log":{"loglevel":"warning"}}';await page.locator('#engineEditor').fill(draft);
      await nav('engines');await step('usque','profile');
      await page.locator('#actionDialog').waitFor({state:'visible'});await page.locator('#actionDialog [value="cancel"]').click();
      await page.waitForFunction(()=>!document.getElementById('actionDialog').open);
      assert.equal(await page.evaluate(()=>state.currentView),'engines');assert.equal(await page.evaluate(()=>state.selectedEngine),'xray');
      assert.equal(await page.evaluate(()=>state.engineEditorDirty),true);
      await step('xray','check');
      await page.waitForFunction(()=>state.currentView==='engineconfig' && state.selectedEngine==='xray' && document.activeElement?.id==='r4Validate');
      assert.equal(await page.locator('#engineEditor').inputValue(),draft);assert.equal(await page.evaluate(()=>state.engineEditorDirty),true);
      assert.equal(requests.slice(start).filter(request=>request.method!=='GET').length,0,'card navigation started a configuration/check/package write');
      await page.locator('.engine-tab[data-engine-tab="config"]').click();await page.locator('#engineDiscardDraft').click();
      await page.waitForFunction(()=>!state.engineEditorDirty && !state.engineIntent);
      assert.equal(requests.slice(start).filter(request=>request.method!=='GET').length,0,'discarding a local unstaged draft wrote a file');
      await nav('engines');await page.setViewportSize({width:390,height:844});
      const disclosure=page.locator('[data-engine-disclosure="xray-flow"]');
      if(!await disclosure.evaluate(element=>element.open))await disclosure.locator('summary').click();
      await page.locator('[data-engine-card="xray"]').scrollIntoViewIfNeeded();
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth-document.documentElement.clientWidth),0,'expanded engine workflow overflows the mobile viewport');
      await page.setViewportSize({width:1280,height:900});
      await nav('overview');await page.waitForFunction(()=>!panelLoad.request);
    });
    await test('AI group is a disclosure and keeps members separate across readback', 'real HTTP + three disposable catalog definitions; presentation only', async()=>{
      const start=requests.length;await nav('services');await page.waitForFunction(()=>!panelLoad.request);
      await page.locator('[data-r5-catalog]').click();
      const group=page.locator('#ui3ServiceCatalog [data-rz-group]').filter({has:page.locator('summary strong', {hasText:'ИИ-сервисы'})});
      await group.locator('summary').click();await page.waitForFunction(()=>[...document.querySelectorAll('#ui3ServiceCatalog [data-rz-group]')].some(el=>el.open));
      assert(await group.locator('[data-rz-card]').count()>1);assert.equal(await group.locator('.ui3-status.good').count(),0,'empty fixture AI group claimed working service');
      await group.locator('summary').focus();await page.evaluate(()=>refreshAll());await page.waitForFunction(()=>!panelLoad.request);
      assert.equal(await group.evaluate(el=>el.open),true);assert.equal(await page.evaluate(()=>document.activeElement?.tagName),'SUMMARY');
      await page.locator('#ui3ServiceSearch').fill('ChatGPT');assert.equal(await group.locator('[data-rz-card]').count(),1);
      await page.locator('#ui3ServiceSearch').fill('');assert(await group.locator('[data-rz-card]').count()>1);
      assert.equal(requests.slice(start).filter(request=>request.method!=='GET').length,0);
      await group.locator('summary').click();assert.equal(await group.evaluate(el=>el.open),false);
      await nav('overview');await page.waitForFunction(()=>!panelLoad.request);
    });
    await test('mobile drawer fits, closes with focus and retains bottom navigation', 'real HTTP and browser layout 390 × 844', async()=>{
    await nav('nodes');await page.waitForFunction(()=>!panelLoad.request);
    await page.setViewportSize({width:390,height:844});
    if(await page.evaluate(()=>document.body.classList.contains('console-menu-open')))await page.locator('#consoleCloseMenu').click();
    await page.waitForFunction(()=>document.querySelector('.sidebar').getBoundingClientRect().right<=0);
    const layout=()=>page.evaluate(()=>{
      const root=document.documentElement,sidebar=document.querySelector('.sidebar'),main=document.querySelector('.main'),nav=document.querySelector('.ui3-mobile-nav');
      const rect=element=>{const r=element.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom};};
      return {scrollWidth:root.scrollWidth,clientWidth:root.clientWidth,bodyScrollWidth:document.body.scrollWidth,sidebar:rect(sidebar),main:rect(main),nav:rect(nav),
        sidebarInert:sidebar.inert,brand:rect(sidebar.querySelector('.brand b')),focus:document.activeElement?.id,
        navVisible:[...nav.querySelectorAll('button')].every(button=>{const r=button.getBoundingClientRect();return r.width>0 && r.height>0 && r.top>=0 && r.bottom<=innerHeight && document.elementFromPoint(r.left+r.width/2,r.top+r.height/2)?.closest('.ui3-mobile-nav')===nav;})};
    });
    const closed=await layout();assert(closed.scrollWidth<=closed.clientWidth);assert(closed.bodyScrollWidth<=closed.clientWidth);
    assert(closed.main.left>=0);assert(closed.main.right<=closed.clientWidth);assert(closed.sidebarInert);assert(closed.navVisible,'closed drawer obscures bottom navigation');
    await page.locator('#consoleMenu').click();await page.waitForFunction(()=>Math.abs(document.querySelector('.sidebar').getBoundingClientRect().left)<1);
    const open=await layout();assert(open.scrollWidth<=open.clientWidth);assert(open.bodyScrollWidth<=open.clientWidth);
    assert(open.brand.left>=0 && open.brand.right<=open.sidebar.right,'drawer clips the brand');assert(!open.sidebarInert);assert.equal(open.focus,'consoleCloseMenu');
    assert(open.navVisible,'open drawer obscures bottom navigation');
    await page.keyboard.press('Escape');await page.waitForFunction(()=>document.querySelector('.sidebar').getBoundingClientRect().right<=0);
    assert.equal((await layout()).focus,'consoleMenu');assert.equal(await page.locator('#consoleMenu').getAttribute('aria-expanded'),'false');
    await page.locator('#consoleMenu').click();await page.locator('#consoleCloseMenu').click();
    await page.waitForFunction(()=>document.querySelector('.sidebar').getBoundingClientRect().right<=0);assert.equal((await layout()).focus,'consoleMenu');
    await page.locator('#consoleMenu').click();await page.locator('#consoleMenuBackdrop').click({position:{x:375,y:300}});
    await page.waitForFunction(()=>document.querySelector('.sidebar').getBoundingClientRect().right<=0);assert.equal((await layout()).focus,'consoleMenu');
    await page.locator('#consoleMenu').click();await page.locator('.sidebar .nav[data-view="settings"]').click();
    await page.waitForFunction(()=>state.currentView==='settings' && document.querySelector('.sidebar').getBoundingClientRect().right<=0);
    assert.equal((await layout()).focus,'pageTitle','drawer navigation left focus in the hidden sidebar');
    await page.locator('#consoleMenu').click();await page.locator('.ui3-mobile-nav [data-mobile-nav="nodes"]').click();
    await page.waitForFunction(()=>state.currentView==='nodes' && document.querySelector('.sidebar').getBoundingClientRect().right<=0);
    assert((await layout()).navVisible);
    await page.setViewportSize({width:1280,height:900});
    await nav('overview');await page.waitForFunction(()=>!panelLoad.request);
    return {closed,open,closeMethods:['Escape','close button','backdrop','drawer destination','bottom destination']};
    });

}

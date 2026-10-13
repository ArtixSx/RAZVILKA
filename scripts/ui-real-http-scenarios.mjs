// Reusable actual HTTP/browser scenarios extracted from the Windows gate.
// All requests use the supplied existing QA instance. No response interception.
import assert from 'node:assert/strict';

// Only these static checkpoint IDs may enter the public failure report.
export const realHTTPDiagnosticIDs=Object.freeze([
  'UI_NODE_IMPORT','UI_NODE_IMPORT_READBACK','UI_NODE_GROUP','UI_NODE_FILTER','UI_NODE_CHECK_CANCEL',
  'UI_NODE_DELETE_PREVIEW','UI_NODE_DELETE_COMMIT','UI_NODE_DELETE_SINGLE_COMMIT','UI_NODE_FINAL_REFRESH',
  'UI_NODE_REMAINING_TOTAL','UI_NODE_REMAINING_GROUP','UI_NODE_RETAINED_MEMBER','UI_NODE_REMAINING_VLESS','UI_NODE_REMAINING_SHADOWSOCKS',
  'UI_POLICY_EDITOR_READY','UI_POLICY_DUPLICATE_SAVE_RECEIPT','UI_POLICY_DUPLICATE_SAVE_UI_READBACK',
  'UI_POLICY_DUPLICATE_SAVE_REQUEST_COUNT','UI_POLICY_DUPLICATE_SAVE_API_READBACK',
  'UI_POLICY_CAS_SECOND_WRITER','UI_POLICY_CAS_STALE_EDITOR_READY','UI_POLICY_CAS_RECEIPT','UI_POLICY_CAS_DRAFT_RETAINED',
  'UI_POLICY_CAS_EXPLICIT_READ','UI_POLICY_CAS_READ_NO_REPLAY','UI_POLICY_CAS_RESET',
  'UI_POLICY_RESTORE_DISABLED_TUNING','UI_POLICY_RESTORE_READBACK',
  'UI_SERVICE_ASSIGN_FILTER','UI_SERVICE_ASSIGN_EDITOR','UI_SERVICE_ASSIGN_BUTTON_VISIBLE','UI_SERVICE_ASSIGN_RETURN','UI_SERVICE_ASSIGN_BOOKEND',
  'UI_STRATEGY_LOCAL_FIXTURE','UI_STRATEGY_LOCAL_EDITOR','UI_STRATEGY_LOCAL_BOOKEND',
  'UI_SCOPE_FIXTURE','UI_SCOPE_EDITOR','UI_SCOPE_OBSERVATION','UI_SCOPE_NAVIGATION','UI_SCOPE_BOOKEND',
  'UI_ENGINE_CARD_INITIAL_REFRESH','UI_ENGINE_CARD_FOCUSED_REFRESH','UI_ENGINE_CARD_PROFILE_OPEN','UI_ENGINE_CARD_WORKFLOW_PROGRESS',
  'UI_ENGINE_CARD_EXPERT_DRAFT','UI_ENGINE_CARD_OTHER_CANCEL','UI_ENGINE_CARD_CHECK_RETURN','UI_ENGINE_CARD_DISCARD_DRAFT',
  'UI_ENGINE_CARD_MOBILE_LAYOUT','UI_ENGINE_CARD_RETURN_OVERVIEW'
]);

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

export async function runRealHTTPDraftScenarios({page,requests,test,readJSON,writeJSON,uiReceipt,beforeMutation,diagnose}) {
  await test('all-VLESS real import and deletion ignore filters and protect group members','real Linux admission, HTTP and public readback; no fault injection',async()=>{
    await navTo(page,'nodes');
    const profiles=[1,2,3].map(n=>`vless://00000000-0000-4000-8000-${String(n).padStart(12,'0')}@ui-node-${n}.invalid:443?type=tcp&security=tls&sni=ui-node-${n}.invalid#UI-F${n}`);
    profiles.push('ss://YWVzLTEyOC1nY206dWktZml4dHVyZQ==@ui-ss.invalid:443#UI-SS');
    await diagnose('UI_NODE_IMPORT',async()=>{
      await page.locator('#nodeOpenImport').click();await page.locator('#nodeQuickImportText').fill(profiles.join('\n'));
      const imported=await uiReceipt('/api/v1/nodes/import','POST',()=>page.locator('#nodeQuickImportSubmit').click());
      assert.equal(imported?.ok,true);assert.equal(imported.accepted_nodes,profiles.length);assert.equal(imported.working_routes_changed,false);
    });
    const snapshot=await diagnose('UI_NODE_IMPORT_READBACK',async()=>{
      await page.waitForFunction(()=>state.nodes.nodes.length===4&&!document.getElementById('nodeQuickImportSubmit').disabled);
      await page.locator('#nodeQuickImportClose').click();
      const snapshot=await readJSON('/api/v1/nodes');assert.equal(snapshot.nodes.length,4);
      assert.equal(snapshot.nodes.filter(node=>String(node.protocol).trim().toLowerCase()==='vless').length,3);return snapshot;
    });
    const vless=snapshot.nodes.filter(node=>String(node.protocol).trim().toLowerCase()==='vless');
    const member=vless[1],filter=await page.evaluate(id=>nodeDisplayName(state.nodes.nodes.find(node=>node.id===id)),vless[0].id);
    await diagnose('UI_NODE_GROUP',async()=>{
      const group=await writeJSON('/api/v1/node-groups','POST',{name:'UI fixture reserve',mode:'fallback',node_ids:[member.id],preferred_node_id:member.id,hold_down_seconds:1800,confirm:'CREATE_NODE_GROUP'});
      assert.equal(group.ok,true);assert.equal(group.working_routes_changed,false);
    });
    await diagnose('UI_NODE_FILTER',async()=>{
      await page.evaluate(()=>refreshNodes());await page.locator('#nodeSearch').fill(filter);
      assert.equal(await page.locator('#nodeList [data-node-card]').count(),1);
    });
    await diagnose('UI_NODE_CHECK_CANCEL',async()=>{
      await page.locator('#nodeAllVLESSDetails summary').click();assert.match(await page.locator('#nodeCheckAllVLESS').textContent(),/3/);
      const checkStart=requests.length;await page.locator('#nodeCheckAllVLESS').click();await page.locator('#actionDialog').waitFor({state:'visible'});
      assert.match(await page.locator('#actionDialogText').textContent(),/3 из 3 VLESS/);await page.locator('#actionDialog [value="cancel"]').click();
      await page.waitForFunction(()=>!workflowState.bulkBusy);assert.equal(requests.slice(checkStart).filter(row=>row.path==='/api/v1/node-checks'&&row.method==='POST').length,0);
    });
    const preview=await diagnose('UI_NODE_DELETE_PREVIEW',async()=>{
      const preview=await uiReceipt('/api/v1/nodes/delete-batch','POST',()=>page.locator('#nodeDeleteAllVLESS').click());
      await page.waitForFunction(()=>!!workflowState.deletion&&!workflowState.deleteBusy);
      assert.equal(preview.preview,true);assert.equal(preview.scope,'all-vless');assert.equal(preview.candidates.length,2);assert.equal(preview.skipped.length,1);
      assert.equal(preview.working_routes_changed,false);assert.equal(preview.skipped[0].node_id,member.id);return preview;
    });
    const commitStart=requests.length;
    await diagnose('UI_NODE_DELETE_COMMIT',async()=>{
      const committed=await uiReceipt('/api/v1/nodes/delete-batch','POST',()=>page.locator('#r4DeleteCommit').click());
      assert.equal(committed.complete,true);assert.equal(committed.deleted.length,2);assert.equal(committed.working_routes_changed,false);
      assert.deepEqual([...committed.deleted].sort(),preview.candidates.map(row=>row.node_id).sort());
      await page.waitForFunction(()=>!workflowState.deleteBusy&&!workflowState.deletion);
    });
    await diagnose('UI_NODE_DELETE_SINGLE_COMMIT',()=>assert.equal(requests.slice(commitStart).filter(row=>row.path==='/api/v1/nodes/delete-batch'&&row.method==='POST').length,1));
    const remaining=await diagnose('UI_NODE_FINAL_REFRESH',async()=>{
      await page.locator('#r4DeleteDialog [data-r4-close]').last().click();
      await page.locator('#refreshNodes').click();await page.waitForFunction(()=>state.nodes.nodes.length===2&&!document.getElementById('refreshNodes').disabled);
      return await readJSON('/api/v1/nodes');
    });
    await diagnose('UI_NODE_REMAINING_TOTAL',()=>assert.equal(remaining.nodes.length,2));
    await diagnose('UI_NODE_REMAINING_GROUP',()=>{assert.equal(remaining.groups.length,1);assert(remaining.groups[0].node_ids.includes(member.id));});
    await diagnose('UI_NODE_RETAINED_MEMBER',()=>assert(remaining.nodes.some(node=>node.id===member.id)));
    await diagnose('UI_NODE_REMAINING_VLESS',()=>assert.equal(remaining.nodes.filter(node=>String(node.protocol).trim().toLowerCase()==='vless').length,1));
    await diagnose('UI_NODE_REMAINING_SHADOWSOCKS',()=>assert.equal(remaining.nodes.filter(node=>String(node.protocol).trim().toLowerCase()==='shadowsocks').length,1));
    await page.locator('#nodeSearch').fill('');await navTo(page,'overview');
  });

  const original=await diagnose('UI_POLICY_EDITOR_READY',async()=>{
    await navTo(page,'autopilot');await page.waitForFunction(()=>!document.getElementById('autoQuickSave').disabled);
    return (await readJSON('/api/v1/autonomy')).policy;
  });
  await test('duplicate Save submits one actual PUT with independent readback','real HTTP; disabled QA policy tuning only',async()=>{
    const seconds=original.check_seconds===180?181:180;await page.locator('#autoQuickCheck').fill(String(seconds));
    const start=requests.length;
    await diagnose('UI_POLICY_DUPLICATE_SAVE_RECEIPT',()=>uiReceipt('/api/v1/autonomy','PUT',()=>page.evaluate(()=>{const form=document.getElementById('autoQuickForm');form.requestSubmit();form.requestSubmit();})));
    await diagnose('UI_POLICY_DUPLICATE_SAVE_UI_READBACK',()=>page.waitForFunction(()=>!document.getElementById('autoQuickSave').disabled&&!document.getElementById('autoQuickRevision').textContent.includes('есть правки')));
    await diagnose('UI_POLICY_DUPLICATE_SAVE_REQUEST_COUNT',()=>assert.equal(requests.slice(start).filter(row=>row.path==='/api/v1/autonomy'&&row.method==='PUT').length,1));
    await diagnose('UI_POLICY_DUPLICATE_SAVE_API_READBACK',async()=>{
      const saved=await readJSON('/api/v1/autonomy');assert.equal(saved.policy.check_seconds,seconds);assert.equal(saved.policy.enabled,false);
    });
  });
  await test('stale policy CAS gets actual 409 and retains draft until reset','real second HTTP writer; no request interception',async()=>{
    await page.locator('#autoQuickCheck').fill('240');const previous=(await readJSON('/api/v1/autonomy')).policy;
    await diagnose('UI_POLICY_CAS_SECOND_WRITER',()=>writeJSON('/api/v1/autonomy','PUT',{expected_revision:previous.revision,policy:{...previous,check_seconds:300},confirm:'SAVE_AUTONOMY',release_safe_mode:false}));
    await diagnose('UI_POLICY_CAS_STALE_EDITOR_READY',async()=>assert.equal(await page.locator('#autoQuickSave').isEnabled(),true));
    await diagnose('UI_POLICY_CAS_RECEIPT',()=>uiReceipt('/api/v1/autonomy','PUT',()=>page.locator('#autoQuickSave').click(),409));
    await diagnose('UI_POLICY_CAS_DRAFT_RETAINED',async()=>{
      await page.waitForFunction(()=>document.getElementById('autoQuickMessage').textContent.includes('изменились'));
      assert.equal(await page.locator('#autoQuickCheck').inputValue(),'240');
    });
    const readback=requests.length;
    await diagnose('UI_POLICY_CAS_EXPLICIT_READ',async()=>{
      await page.locator('#autoQuickRefresh').click();
      await page.waitForFunction(()=>document.getElementById('autoQuickSave').disabled&&document.getElementById('autoQuickMessage').textContent.includes('Ваши поля сохранены'));
    });
    await diagnose('UI_POLICY_CAS_READ_NO_REPLAY',()=>assert.equal(requests.slice(readback).filter(row=>row.path==='/api/v1/autonomy'&&row.method==='PUT').length,0));
    await diagnose('UI_POLICY_CAS_RESET',async()=>{
      await page.locator('#autoQuickReset').click();await page.waitForFunction(()=>!document.getElementById('autoQuickSave').disabled);
      assert.equal(await page.locator('#autoQuickCheck').inputValue(),'300');
    });
  });
  // Restore known tuning only after every write/readback above succeeded.
  // Failures leave QA disposal to the coordinator; no uncertain mutation replay.
  await diagnose('UI_POLICY_RESTORE_DISABLED_TUNING',async()=>{
    await beforeMutation();const current=(await readJSON('/api/v1/autonomy')).policy;
    await writeJSON('/api/v1/autonomy','PUT',{expected_revision:current.revision,policy:{...original,revision:current.revision},confirm:'SAVE_AUTONOMY',release_safe_mode:false});
  });
  await diagnose('UI_POLICY_RESTORE_READBACK',async()=>{
    const restored=(await readJSON('/api/v1/autonomy')).policy;
    assert.deepEqual({...restored,revision:original.revision},original);
  });
  await navTo(page,'overview');
}

export async function runRealHTTPReadScenarios({page,requests,test,readJSON,uiRead,recordSharedScope,diagnose}) {
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
  await test('choose service leaves a filtered list for the visible full catalog without writes', 'genuine clicks, engine editor and config GET bookends', async()=>{
    const before=await readJSON('/api/v1/status'),start=requests.length;
    await diagnose('UI_SERVICE_ASSIGN_FILTER',async()=>{
      await navTo(page,'services');
      await page.locator('#ui3ServiceSearch').fill('ui-d12-catalog-filter');
      assert.equal(await page.locator('#ui3ServiceSearch').inputValue(),'ui-d12-catalog-filter');
      await page.waitForFunction(()=>interfaceState.query==='ui-d12-catalog-filter');
    });
    await diagnose('UI_SERVICE_ASSIGN_EDITOR',async()=>{
      await navTo(page,'engines');
      const card=page.locator('#ui3EngineGrid [data-engine-card="xray"]');
      await card.waitFor({state:'visible'});
      const profile=card.locator('[data-engine-step="profile"][data-card-engine="xray"]');
      if(!await profile.isVisible())await card.locator('[data-engine-disclosure="xray-flow"] > summary').click();
      await profile.click();
      await page.waitForFunction(()=>state.currentView==='engineconfig'&&state.selectedEngine==='xray'&&!panelLoad.request
        &&!state.engineIntent&&!state.engineGuidedLoading&&!document.getElementById('engineAssignService').disabled);
    });
    await diagnose('UI_SERVICE_ASSIGN_BUTTON_VISIBLE',async()=>assert.equal(await page.locator('#engineAssignService').isVisible(),true));
    await diagnose('UI_SERVICE_ASSIGN_RETURN',async()=>{
      await page.locator('#engineAssignService').click();
      await page.waitForFunction(()=>state.currentView==='services'&&!panelLoad.request&&interfaceState.filter==='all'
        &&interfaceState.query===''&&interfaceState.category===''&&document.activeElement?.id==='ui3ServiceSearch');
      assert.equal(await page.locator('#ui3ServiceCatalog').isVisible(),true);
      assert.equal(await page.locator('#r5CatalogTools').isVisible(),true);
      assert((await page.locator('#ui3ServiceCatalog [data-rz-card]').count())>0,'the real service catalog did not contain cards');
      assert.equal(await page.locator('#ui3ServiceSearch').inputValue(),'');
    });
    await diagnose('UI_SERVICE_ASSIGN_BOOKEND',async()=>{
      // Restore only local presentation with ordinary clicks so the next
      // existing AI scenario starts from its original selected-services tab.
      await page.locator('#r5CatalogButton').click();
      await page.waitForFunction(()=>interfaceState.filter==='selected'&&!panelLoad.request);
      await navTo(page,'overview');
      const after=await readJSON('/api/v1/status');
      assert.equal(after.revision,before.revision);assert.equal(after.applied_revision,before.applied_revision);
      assert.equal(after.safe_mode,before.safe_mode);assert.equal(after.live_active,before.live_active);
      assert.equal(requests.slice(start).filter(row=>row.method!=='GET').length,0,'navigation or local filtering started a business mutation');
    });
  });
    await test('engine card steps keep the chosen engine and dirty profile without writes', 'real engine metadata HTTP and local draft', async()=>{
      const start=requests.length;
      await diagnose('UI_ENGINE_CARD_INITIAL_REFRESH',async()=>{
        await nav('engines');await page.evaluate(()=>refreshEngineConfigs());
        await page.waitForFunction(()=>!panelLoad.request);
        assert.equal(requests.slice(start).filter(request=>/^\/api\/v1\/engine-configs\/[^/]+\/guided$/.test(request.path)).length,0,'hidden profile reader ran on the cards page');
      });
      const step=async(id,name)=>{const button=page.locator('[data-engine-step="'+name+'"][data-card-engine="'+id+'"]');if(!await button.isVisible())await page.locator('[data-engine-disclosure="'+id+'-flow"] summary').click();await button.click();};
      await diagnose('UI_ENGINE_CARD_FOCUSED_REFRESH',async()=>{
        const summary=page.locator('[data-engine-disclosure="xray-flow"] summary');
        if(!await page.locator('[data-engine-disclosure="xray-flow"]').evaluate(element=>element.open))await summary.click();
        await summary.focus();
        await page.evaluate(()=>refreshEngineConfigs());
        assert.equal(await page.locator('[data-engine-disclosure="xray-flow"]').evaluate(element=>element.open),true);
        assert.equal(await summary.evaluate(element=>document.activeElement===element),true,'workflow disclosure lost focus on metadata readback');
      });
      await diagnose('UI_ENGINE_CARD_PROFILE_OPEN',async()=>{
        await step('xray','profile');
        await page.waitForFunction(()=>state.currentView==='engineconfig' && state.selectedEngine==='xray');
        await page.waitForFunction(()=>document.activeElement?.id==='engineFileSelect');
      });
      await diagnose('UI_ENGINE_CARD_WORKFLOW_PROGRESS',async()=>{
        const workspaceProgress=await page.locator('#ui3EngineSteps [data-engine-workspace-progress]').evaluateAll(rows=>rows.map(row=>({step:row.dataset.engineWorkspaceProgress,complete:row.classList.contains('confirmed')})));
        assert.deepEqual(workspaceProgress.map(row=>row.step),['install','profile','check','apply']);
        const matchingProgress=await page.evaluate(()=>engineWorkflowPresentation('xray').complete);
        for(const row of workspaceProgress)assert.equal(row.complete,matchingProgress[row.step],'workspace used unrelated runtime/route proof');
        assert.doesNotMatch(await page.locator('#ui3EngineSteps').textContent(),/Процесс|Маршруты/);
      });
      const draft='{"log":{"loglevel":"warning"}}';
      await diagnose('UI_ENGINE_CARD_EXPERT_DRAFT',async()=>{
        await page.locator('#engineModeExpert').click();await page.waitForFunction(()=>state.engineMode==='expert');
        await page.locator('#engineEditor').fill(draft);
      });
      await diagnose('UI_ENGINE_CARD_OTHER_CANCEL',async()=>{
        await nav('engines');await step('usque','profile');
        await page.locator('#actionDialog').waitFor({state:'visible'});await page.locator('#actionDialog [value="cancel"]').click();
        await page.waitForFunction(()=>!document.getElementById('actionDialog').open);
        assert.equal(await page.evaluate(()=>state.currentView),'engines');assert.equal(await page.evaluate(()=>state.selectedEngine),'xray');
        assert.equal(await page.evaluate(()=>state.engineEditorDirty),true);
      });
      await diagnose('UI_ENGINE_CARD_CHECK_RETURN',async()=>{
        await step('xray','check');
        await page.waitForFunction(()=>state.currentView==='engineconfig' && state.selectedEngine==='xray' && document.activeElement?.id==='r4Validate');
        assert.equal(await page.locator('#engineEditor').inputValue(),draft);assert.equal(await page.evaluate(()=>state.engineEditorDirty),true);
        assert.equal(requests.slice(start).filter(request=>request.method!=='GET').length,0,'card navigation started a configuration/check/package write');
      });
      await diagnose('UI_ENGINE_CARD_DISCARD_DRAFT',async()=>{
        await page.locator('.engine-tab[data-engine-tab="config"]').click();await page.locator('#engineDiscardDraft').click();
        await page.waitForFunction(()=>!state.engineEditorDirty && !state.engineIntent);
        assert.equal(requests.slice(start).filter(request=>request.method!=='GET').length,0,'discarding a local unstaged draft wrote a file');
      });
      await diagnose('UI_ENGINE_CARD_MOBILE_LAYOUT',async()=>{
        await nav('engines');await page.setViewportSize({width:390,height:844});
        const disclosure=page.locator('[data-engine-disclosure="xray-flow"]');
        if(!await disclosure.evaluate(element=>element.open))await disclosure.locator('summary').click();
        await page.locator('[data-engine-card="xray"]').scrollIntoViewIfNeeded();
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth-document.documentElement.clientWidth),0,'expanded engine workflow overflows the mobile viewport');
        await page.setViewportSize({width:1280,height:900});
      });
      await diagnose('UI_ENGINE_CARD_RETURN_OVERVIEW',async()=>{
        await nav('overview');await page.waitForFunction(()=>!panelLoad.request);
      });
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

  await test('strategy laboratory keeps the manual target editable without a probe or candidates', 'genuine Settings navigation, catalog selects and GET-only bookends', async()=>{
    const start=requests.length;
    const {before,lab,catalog}=await diagnose('UI_STRATEGY_LOCAL_FIXTURE',async()=>{
      const before=await readJSON('/api/v1/status'),lab=await readJSON('/api/v1/strategy-lab'),services=await readJSON('/api/v1/services');
      assert.equal(before.safe_mode,true);assert.equal(before.live_active,false);
      assert.equal(lab.safety?.temporary_scoped_firewall_probe,false);
      assert(Array.isArray(lab.candidates));assert.equal(lab.candidates.length,0);
      assert(Array.isArray(services));const catalog=services.map(service=>service.id);
      assert(catalog.length>1);assert(catalog.every(id=>typeof id==='string'&&id));
      return {before,lab,catalog};
    });
    const original=await diagnose('UI_STRATEGY_LOCAL_EDITOR',async()=>{
      await navTo(page,'settings');
      const advanced=page.locator('#view-settings details.r5-advanced:has([data-rz-nav="strategylab"])');
      if(!await advanced.evaluate(element=>element.open))await advanced.locator('summary').click();
      await page.locator('#view-settings [data-rz-nav="strategylab"]').click();
      await page.waitForFunction(()=>state.currentView==='strategylab'&&!panelLoad.request&&state.dataLoad.strategyLab?.phase==='ready'&&state.dataLoad.services?.phase==='ready');
      assert(requests.slice(start).some(request=>request.method==='GET'&&request.path==='/api/v1/strategy-lab'),'laboratory did not read its real HTTP snapshot');
      assert.equal(await page.locator('#view-strategylab').isVisible(),true);
      assert.match(await page.locator('#strategyResourceBudget').textContent(),/ИЗОЛИРОВАННЫЙ ТЕСТ НЕДОСТУПЕН/);
      assert.equal(await page.locator('#strategyCandidates .strategy-candidate').count(),0);
      assert.equal(await page.locator('#strategyCandidates [data-strategy-manual], #strategyCandidates [data-strategy-probe]').count(),0);
      const target=page.locator('#strategyTarget'),family=page.locator('#strategyFamily');
      assert.equal(await target.isVisible(),true);assert.equal(await family.isVisible(),true);
      assert.equal(await target.isEnabled(),true);assert.equal(await family.isEnabled(),true);
      const options=await target.locator('option').evaluateAll(rows=>rows.map(row=>row.value));
      assert.deepEqual([...options].sort(),[...catalog].sort());
      const original={service:await target.inputValue(),family:await family.inputValue()};
      assert(catalog.includes(original.service));assert(['ipv4','ipv6'].includes(original.family));
      const service=catalog.find(id=>id!==original.service),nextFamily=original.family==='ipv4'?'ipv6':'ipv4';
      await target.selectOption(service);await family.selectOption(nextFamily);
      assert.equal(await target.inputValue(),service);assert.equal(await family.inputValue(),nextFamily);
      assert.equal(await target.isEnabled(),true);assert.equal(await family.isEnabled(),true);
      return original;
    });
    await diagnose('UI_STRATEGY_LOCAL_BOOKEND',async()=>{
      await page.locator('#strategyTarget').selectOption(original.service);
      await page.locator('#strategyFamily').selectOption(original.family);
      await navTo(page,'overview');
      const after=await readJSON('/api/v1/status'),afterLab=await readJSON('/api/v1/strategy-lab');
      assert.equal(after.revision,before.revision);assert.equal(after.applied_revision,before.applied_revision);
      assert.equal(after.safe_mode,before.safe_mode);assert.equal(after.live_active,before.live_active);
      assert.deepEqual(afterLab.candidates,lab.candidates);assert.deepEqual(afterLab.selections,lab.selections);assert.deepEqual(afterLab.evidence,lab.evidence);
      assert.equal(requests.slice(start).filter(request=>request.method!=='GET').length,0,'ordinary laboratory selection started a business mutation');
    });
  });

  await test('shared home scope read-only editor with separate first-setup or saved-reference outcome','real policy/options GETs and genuine read-only navigation',async()=>{
    const start=requests.length;
    const before=await diagnose('UI_SCOPE_FIXTURE',async()=>{
      const review=await readJSON('/api/v1/networkpolicy/review'),exclusions=await readJSON('/api/v1/networkpolicy/exclusions'),status=await readJSON('/api/v1/status');
      // ROOT seeds this saved intent through the real review API before the
      // browser starts. It is neither an observed segment nor route authority.
      assert.equal(review.live_applied,false);
      if(review.policy!==null){assert.equal(review.policy.traffic.mode,'selected_services');assert.equal(review.policy.clients.mode,'lan_except');assert.equal(review.policy.clients.segment_ids?.length,1);assert(review.policy.clients.excluded_device_ids?.length>0);}
      else assert.equal(review.consent,null);
      assert.equal(exclusions.live_applied,false);assert.equal(exclusions.scope_configured,review.policy!==null);assert.equal(exclusions.revision,review.revision);assert.equal(exclusions.policy_revision,review.policy?.revision||0);
      assert.equal(status.safe_mode,true);assert.equal(status.live_active,false);
      return {review,exclusions,status};
    });
    const savedSegments=before.review.policy?.clients.segment_ids||[],savedNegatives=before.review.policy?.clients.excluded_device_ids||[];
    let scopeFacts;
    await diagnose('UI_SCOPE_EDITOR',async()=>{
      const attempted=await page.evaluate(()=>listScopeEditor.optionsAttempted),entered=requests.length;
      await navTo(page,'devices');
      await page.waitForFunction(()=>state.dataLoad.networkPolicyReview?.phase==='ready'&&!listScopeEditor.optionsRead);
      assert.equal(await page.locator('#listScopeContent').count(),1);assert.equal(await page.locator('#listScopeContent').isVisible(),true);
      assert.equal(await page.locator('#listScopeContent [data-scope-field="mode"]').inputValue(),'lan_except');
      const selected=await page.locator('#listScopeContent [data-scope-list="segment_ids"]:checked').evaluateAll(inputs=>inputs.map(input=>input.dataset.scopeId));
      assert.deepEqual(selected,savedSegments);
      const excluded=await page.locator('#listScopeContent [data-scope-list="excluded_device_ids"]:checked').evaluateAll(inputs=>inputs.map(input=>input.dataset.scopeId));
      assert.deepEqual([...excluded].sort(),[...savedNegatives].sort());
      assert.equal(requests.slice(entered).filter(r=>r.path==='/api/v1/networkpolicy/scope-options').length,attempted?0:1);
      assert.equal(await page.locator('#listScopeContent [data-scope-save]').isEnabled(),false);
      if(before.review.policy===null)assert.match(await page.locator('#listScopeContent').textContent(),/Общая область пока не настроена/);
    });
    await diagnose('UI_SCOPE_OBSERVATION',async()=>{
      const refreshed=requests.length;
      const options=await uiRead('/api/v1/networkpolicy/scope-options',()=>page.locator('#listScopeContent [data-scope-refresh]').click());
      await page.waitForFunction(()=>!listScopeEditor.optionsRead&&state.dataLoad.homeScope?.phase==='ready');
      assert.equal(options.schema,1);assert.equal(options.ok,true);assert.equal(options.effect_authorized,false);assert.equal(options.live_applied,false);
      assert(['available','partial','unavailable'].includes(options.state));assert.equal(options.revision,before.review.revision);assert.equal(options.policy_revision,before.review.policy?.revision||0);
      assert(Array.isArray(options.segments)&&Array.isArray(options.devices)&&Array.isArray(options.retained_device_ids));
      const unobserved=savedNegatives.filter(id=>options.devices.some(row=>row.id===id&&['not_observed','unknown','unavailable'].includes(row.state)&&row.selection_candidate===false));
      if(before.review.policy!==null)assert(unobserved.length>0,'saved policy fixture lacks an unobserved negative identity');
      for(const id of unobserved)assert(options.retained_device_ids.includes(id));
      const rows=await page.locator('#listScopeContent [data-scope-list="excluded_device_ids"]').evaluateAll(inputs=>inputs.map(input=>({id:input.dataset.scopeId,checked:input.checked,visible:!!input.getClientRects().length,text:input.closest('label').textContent})));
      for(const id of unobserved){const row=rows.find(row=>row.id===id);assert(row?.checked&&row.visible);assert.match(row.text,/не наблюдается|наблюдение не подтверждено/i);}
      const text=await page.locator('#listScopeContent').textContent();
      if(options.state==='partial')assert.match(text,/Наблюдение неполное/);
      if(options.state==='unavailable')assert.match(text,/Домашние сегменты не подтверждены свежим чтением/);
      assert.equal(requests.slice(refreshed).filter(r=>r.path==='/api/v1/networkpolicy/scope-options').length,1);
      scopeFacts={branch:before.review.policy===null?'first-setup':'saved-policy',saved_segment_count:savedSegments.length,saved_excluded_device_count:savedNegatives.length,
        unobserved_excluded_device_count:unobserved.length,retained_ids_checked:before.review.policy!==null,
        observation_state:options.state,observation_code:options.code,effect_authorized:options.effect_authorized,live_applied:options.live_applied};
      // Zero observed devices and unsupported Linux observation are legitimate
      // responses. Saved negative IDs must remain visible in either branch.
    });
    await diagnose('UI_SCOPE_NAVIGATION',async()=>{
      const left=requests.length;
      await page.locator('#listScopeContent button[data-rz-nav="exclusions"]').click();
      await page.waitForFunction(()=>state.currentView==='exclusions'&&!panelLoad.request);
      assert.equal(await page.locator('#resourceExclusionsContent').isVisible(),true);assert.match(await page.locator('#resourceExclusionsContent').textContent(),/Сайты без обхода/);
      assert.equal(await page.locator('#listScopeContent').count(),1);assert.equal(await page.locator('#listScopeContent').isVisible(),false);
      await navTo(page,'devices');await page.evaluate(()=>refreshAll());await page.waitForFunction(()=>!panelLoad.request&&!listScopeEditor.optionsRead);
      assert.equal(requests.slice(left).filter(r=>r.path==='/api/v1/networkpolicy/scope-options').length,0,'ordinary reads repeated the expensive observation');
      assert.equal(await page.locator('#listScopeContent').isVisible(),true);
      const excluded=await page.locator('#listScopeContent [data-scope-list="excluded_device_ids"]:checked').evaluateAll(inputs=>inputs.map(input=>input.dataset.scopeId));
      assert.deepEqual([...excluded].sort(),[...savedNegatives].sort());
    });
    await diagnose('UI_SCOPE_BOOKEND',async()=>{
      const review=await readJSON('/api/v1/networkpolicy/review'),exclusions=await readJSON('/api/v1/networkpolicy/exclusions'),status=await readJSON('/api/v1/status');
      assert.deepEqual(review,before.review);assert.deepEqual(exclusions,before.exclusions);
      assert.equal(status.revision,before.status.revision);assert.equal(status.applied_revision,before.status.applied_revision);
      assert.equal(status.safe_mode,true);assert.equal(status.live_active,false);
      assert.equal(requests.slice(start).filter(r=>r.method!=='GET').length,0,'shared scope read/navigation caused a mutation');
      await navTo(page,'overview');
      assert.equal(requests.slice(start).filter(r=>r.method!=='GET').length,0,'return navigation caused a mutation');
      recordSharedScope(scopeFacts);
    });
  });

}

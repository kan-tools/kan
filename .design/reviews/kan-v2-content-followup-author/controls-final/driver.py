from pathlib import Path
import subprocess,hashlib,json,os
root=Path.cwd();out=root/'.local-state'/os.environ.get('KAN_CONTROLS_DIR','content-followup-controls');out.mkdir(exist_ok=False)
os.environ.update(CARGO_TARGET_DIR='/Users/m/code/kan-tools/kan/.worktrees/kan-v2-library-resilience/.local-state/target',CARGO_BUILD_JOBS='4',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0',CARGO_INCREMENTAL='0',RUST_TEST_THREADS='4',KAN_CRYPTO_ORACLE_PYTHON='/Users/m/code/kan-tools/kan/.worktrees/kan-v2-encryption/.local-state/crypto-oracle-env/bin/python',KAN_TLS_ORACLE_PYTHON='/opt/homebrew/bin/python3',GIT_CONFIG_COUNT='1',GIT_CONFIG_KEY_0='commit.gpgsign',GIT_CONFIG_VALUE_0='false')
C='src/evidence_content.rs';P='src/evidence_interpretation.rs';W='evidence_content::worker_tests::cancelling_real_content_keeps_worker_admission_until_exit_and_stops_after_first_item';A='evidence_content::tests::aggregate_work_is_charged_across_interpretation_and_all_item_mappings'
cases=[
('acquisition-cap-removed',C,'if bytes > INPUT {','if false && bytes > INPUT {','lib','evidence_content::worker_tests::acquisition_cap_stops_before_fetching_the_next_selected_record'),
('overall-deadline-removed',C,'        tokio::time::timeout(DEADLINE, work)\n            .await\n            .map_err(|_| ContentError::Limited)?','        work.await','lib','evidence_content::worker_tests::overall_content_deadline_covers_acquisition_work_after_a_verified_read'),
('error-shape-silent',P,'if !value.get("error").is_some_and(Value::is_object) {','if false {','evidence_interpretation_followups','malformed_error_and_tool_result_shapes_have_resolving_pointers_and_reasons'),
('tool-result-shape-silent',P,'if kind == Kind::ToolResult\n        && !value','if false && kind == Kind::ToolResult\n        && !value','evidence_interpretation_followups','malformed_error_and_tool_result_shapes_have_resolving_pointers_and_reasons'),
('empty-key-promoted',P,'let text = (!key.is_empty())','let text = true','evidence_interpretation_followups','citations_and_unknown_deltas_do_not_promote_an_empty_json_key_to_text'),
('busy-misclassified','src/evidence_library.rs','StatusCode::TOO_MANY_REQUESTS','StatusCode::SERVICE_UNAVAILABLE','lib','evidence_content::worker_tests::busy_content_http_response_is_distinct_and_retry_succeeds_after_capacity_returns'),
('early-permit-release',C,'let _permit = permit;','drop(permit);','lib',W),
('worker-ignores-cancel',C,'render(acquired, wire, format, cancelled, deadline, after_item)','render(acquired, wire, format, Arc::new(AtomicBool::new(false)), deadline, after_item)','lib',W),
('three-workers','src/evidence_reader.rs','tokio::sync::Semaphore::new(2)','tokio::sync::Semaphore::new(3)','evidence_reader','content_cancelling_acquisition_releases_admission_and_does_not_cache_a_grant'),
('citation-budget-reset',C,'    budget.citations = budget\n        .citations\n        .checked_sub(citations.len())\n        .ok_or(Failure::Unavailable)?;','', 'lib',A),
('item-budget-reset',C,'    budget.items = budget\n        .items\n        .checked_sub(document.items.len())\n        .ok_or(Failure::Unavailable)?;','', 'lib',A),
('output-budget-reset',C,'    budget.output = budget\n        .output\n        .checked_sub(document.output_bytes)\n        .ok_or(Failure::Unavailable)?;','', 'lib',A),
('serialized-cap-unwired',C,'bounded_json(&value, OUTPUT, &budget)','bounded_json(&value, usize::MAX, &budget)','lib','evidence_content::tests::serialized_content_cap_is_independent_of_normalized_output'),
('mapping-byte-charge-removed',C,'budget.charge_scan(mapping.scanned_bytes)?;','', 'lib',A),
('repeated-stream-validation',C,'        let citations = map_citations(&mapping, item.region.clone(), budget)?;','        let mut limits=budget.limits()?; limits.items=2*PAGE_LIMIT; let again=provider::validate_mapping(stream,inputs,limits).map_err(|_|Failure::Unavailable)?; budget.charge_scan(again.scanned_bytes)?;\n        let citations = map_citations(&mapping, item.region.clone(), budget)?;','evidence_reader','content_handles_realistic_multiturn_history_and_streams_without_repeated_source_scans'),
('limit-misclassified','src/evidence_library.rs','StatusCode::UNPROCESSABLE_ENTITY','StatusCode::SERVICE_UNAVAILABLE','evidence_reader','content_http_routes_share_authority_and_return_exact_coordinates'),
('unknown-field-sticky',P,'            unknown_field = false;','', 'evidence_interpretation_followups','unknown_sse_field_reason_is_local_to_its_event'),
]
originals={f:Path(f).read_text() for _,f,*_ in cases}
(out/'identity.json').write_text(json.dumps({'head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'files':{f:hashlib.sha256(s.encode()).hexdigest() for f,s in originals.items()},'status':subprocess.check_output(['git','status','--porcelain'],text=True)},indent=2))
try:
 for name,f,old,new,target,test in cases:
  original=originals[f];assert original.count(old)==1,(name,original.count(old));Path(f).write_text(original.replace(old,new))
  cmd=['cargo','test','--features','v2-crypto']+(['--lib'] if target=='lib' else ['--test',target])+[test,'--','--exact']
  r=subprocess.run(cmd,capture_output=True,text=True,timeout=180);log=r.stdout+r.stderr;(out/(name+'.txt')).write_text('$ '+' '.join(cmd)+'\n'+log+'\nexit='+str(r.returncode))
  assert r.returncode and 'could not compile' not in log and ' ... FAILED' in log and 'panicked at' in log,name
  print('DEMONSTRATED',name,flush=True);Path(f).write_text(original)
finally:
 for f,s in originals.items():Path(f).write_text(s)
for cmd in [['cargo','test','--features','v2-crypto','--test','evidence_reader','content_'],['cargo','test','--features','v2-crypto','--lib','evidence_content'],['cargo','test','--features','v2-crypto','--test','evidence_interpretation_followups']]:
 r=subprocess.run(cmd,capture_output=True,text=True,timeout=180);(out/('restored-'+cmd[-1].replace(':','-')+'.txt')).write_text(r.stdout+r.stderr+'\nexit='+str(r.returncode));assert r.returncode==0
print('Restored suites pass.',flush=True)

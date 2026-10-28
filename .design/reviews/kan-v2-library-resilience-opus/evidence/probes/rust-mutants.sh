#!/bin/zsh
# Sequential Rust mutants (one heavy job at a time, -j4, this export target only).
set -u
cd "${0:A:h}/../.."
export CARGO_TARGET_DIR=$PWD/target CARGO_BUILD_JOBS=4
M=review-evidence/probes/mutate.py
L=src/evidence_library.rs
R=src/evidence_reader.rs
CAT="catalog_keeps_healthy_scopes_and_recovers_without_disclosing_failed_sources catalog_verification_failure_is_not_an_empty_authorized_inventory"
B="connection_admission_execution_and_deadlines_are_bounded cancelling_connection_releases_socket_and_execution_permits"
LB="evidence_library::budget_tests::connection_admission_execution_and_deadlines_are_bounded evidence_library::budget_tests::cancelling_connection_releases_socket_and_execution_permits"

# Catalog semantics
python3 $M R01-lost-partial-flag $L 'Err(_) => partial = true,' 'Err(_) => {}' evidence_reader ${=CAT}
python3 $M R02-fail-whole-catalog $L 'Err(_) => partial = true,' 'Err(e) => return Err(e),' evidence_reader ${=CAT}
python3 $M R03-denial-marks-partial $L 'Err(Failure::AccessLimited) => {}' 'Err(Failure::AccessLimited) => partial = true,' evidence_reader ${=CAT} library_http_authority_is_separate_and_denial_does_not_reveal_scope_existence
python3 $M R04-sequential-checks $L 'configured.chunks(4)' 'configured.chunks(1)' evidence_reader ${=CAT}
python3 $M R05-drop-fourth-in-group $L 'catalog_entry(reader, group.get(3))' 'catalog_entry(reader, None)' evidence_reader ${=CAT}
python3 $M R06-coverage-always-complete $L '"coverage":if partial {"partial"} else {"complete"}' '"coverage":"complete"' evidence_reader ${=CAT}
python3 $M R07-claim-search-capability $L '"capabilities":["snapshot-inventory","source-ranges","provenance"]' '"capabilities":["snapshot-inventory","source-ranges","provenance","semantic-search"]' evidence_reader catalog_verification_failure_is_not_an_empty_authorized_inventory
python3 $M R08-leak-failure-count $L '"coverage":if partial {"partial"} else {"complete"},' '"coverage":if partial {"partial"} else {"complete"},"failed":configured.len()-scopes.len(),' evidence_reader ${=CAT}

# Upstream / body deadlines
python3 $M R10-upstream-deadline-30s $R 'std::time::Duration::from_secs(5),' 'std::time::Duration::from_secs(30),' evidence_reader catalog_keeps_healthy_scopes_and_recovers_without_disclosing_failed_sources
python3 $M R11-upstream-deadline-6s $R 'std::time::Duration::from_secs(5),' 'std::time::Duration::from_secs(6),' evidence_reader catalog_keeps_healthy_scopes_and_recovers_without_disclosing_failed_sources
python3 $M R12-timeout-is-denial $R '.map_err(|_| Failure::Unavailable)?
        .map_err(|failure|' '.map_err(|_| Failure::AccessLimited)?
        .map_err(|failure|' evidence_reader ${=CAT}
python3 $M R13-body-deadline-4s $L 'Duration::from_secs(3),
        Limited::new' 'Duration::from_secs(4),
        Limited::new' evidence_reader library_body_read_deadline_returns_an_explicit_timeout
python3 $M R14-body-deadline-1s $L 'Duration::from_secs(3),
        Limited::new' 'Duration::from_secs(1),
        Limited::new' evidence_reader library_body_read_deadline_returns_an_explicit_timeout

# Budget helper bounds
python3 $M R20-sockets-13 $L 'sockets: Arc::new(Semaphore::new(12)),' 'sockets: Arc::new(Semaphore::new(13)),' lib ${=LB}
python3 $M R21-requests-5 $L 'requests: Arc::new(Semaphore::new(4)),' 'requests: Arc::new(Semaphore::new(5)),' lib ${=LB}
python3 $M R22-queue-7s $L 'Duration::from_secs(6),
                self.requests' 'Duration::from_secs(7),
                self.requests' lib ${=LB}
python3 $M R23-whole-36s $L 'tokio::time::timeout(Duration::from_secs(35), connection)' 'tokio::time::timeout(Duration::from_secs(36), connection)' lib ${=LB}
python3 $M R24-whole-excludes-queue $L 'let connection = async {
            let Ok(Ok(_request)) = tokio::time::timeout(
                Duration::from_secs(6),
                self.requests.clone().acquire_owned(),
            )
            .await
            else {
                return;
            };
            work.await;
        };
        let _ = tokio::time::timeout(Duration::from_secs(35), connection).await;' 'let Ok(Ok(_request)) = tokio::time::timeout(
                Duration::from_secs(6),
                self.requests.clone().acquire_owned(),
            )
            .await
            else {
                return;
            };
        let _ = tokio::time::timeout(Duration::from_secs(35), work).await;' lib ${=LB}
python3 $M R25-socket-permit-leaks $L 'let _socket = permit;' 'std::mem::forget(permit);' lib ${=LB}

# Live wrapper binding: does serve() actually use the tested helper/bounds?
python3 $M R30-serve-bypasses-run $L 'budget.run(permit, connection(stream, host, token, reader)).await;' 'let _p = permit; connection(stream, host, token, reader).await;' evidence_reader library_queues_a_browser_request_behind_four_idle_connections catalog_keeps_healthy_scopes_and_recovers_without_disclosing_failed_sources
python3 $M R31-serve-unbounded-sockets $L 'let budget = ConnectionBudget::new();
    let mut tasks' 'let budget = ConnectionBudget { sockets: Arc::new(Semaphore::new(4096)), requests: Arc::new(Semaphore::new(4)) };
    let mut tasks' evidence_reader library_queues_a_browser_request_behind_four_idle_connections library_http_authority_is_separate_and_denial_does_not_reveal_scope_existence
python3 $M R32-header-timeout-30s $L '.header_read_timeout(Duration::from_secs(5));' '.header_read_timeout(Duration::from_secs(30));' evidence_reader library_queues_a_browser_request_behind_four_idle_connections

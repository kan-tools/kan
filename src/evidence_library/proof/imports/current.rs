//! Native current-codec interpretation over explicitly selected control evidence.
//! Resolver conclusions are relative to that set, never a claim of global currency.
use super::{bounded, invalid, ContentError, Value, View};
use crate::{
    claim::{
        codec::{self, DecodedClaim, SupportedClaim, VerificationContext},
        view::{self, ClaimAuthor, ClaimSource, ClaimSubjectId, ClaimTrustBase, CurrentEvaluation},
    },
    identity::{
        self,
        control::{ControlEvent, IdentityVersion, PreservedControlEvent},
        did_kan,
        did_kan_update::{self, DidKanResolution},
        governance,
        scope_inception::{self, ScopeInception},
        IdentityStateStanding, ScopeAdmission,
    },
};
use atproto_dasl::{Cid, Ipld};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
pub(super) struct Control {
    pub preserved: PreservedControlEvent,
    pub sources: Vec<Value>,
}
fn payload<T: serde::de::DeserializeOwned>(event: &ControlEvent) -> Option<T> {
    bounded(&atproto_dasl::to_vec(&event.payload).ok()?).ok()
}
fn subject(value: &ClaimSubjectId) -> Value {
    match value {
        ClaimSubjectId::Scoped { scope, path } => json!({"scope":scope.to_string(),"path":path}),
        ClaimSubjectId::V1Local(path) => json!({"legacy_local":path}),
        ClaimSubjectId::V1Anchor(anchor) => json!({"legacy_anchor":anchor}),
    }
}
fn same_did(event: &ControlEvent, did: &str) -> bool {
    matches!(&event.payload,Ipld::Map(m) if m.get("did")==Some(&Ipld::String(did.to_owned())))
}
struct Scope {
    roots: Vec<String>,
    authority: Option<identity::capability::GovernanceAuthority>,
    admission: ScopeAdmission,
    value: Value,
}
fn scope(
    inception: &ScopeInception,
    event: &ControlEvent,
    typed: &[ControlEvent],
    active: &[did_kan_update::ResolvedDidKanState],
) -> Scope {
    let candidates = typed
        .iter()
        .filter(|e| {
            e.domain == governance::GOVERNANCE_DOMAIN
                && e.event_type == governance::GOVERNANCE_EVENT_TYPE
                && payload::<governance::GovernanceEvent>(e)
                    .is_some_and(|g| inception.scope_id().ok() == Some(g.scope))
        })
        .cloned()
        .collect::<Vec<_>>();
    let resolved = governance::resolve(inception, event, &candidates);
    match resolved {
        governance::GovernanceResolution::Active(state) => {
            let authority = inception.scope_id().ok().and_then(|id| {
                identity::capability::GovernanceAuthority::from_active(id, &state).ok()
            });
            Scope {
                roots: state.governance_roots.clone(),
                authority,
                admission: ScopeAdmission::Admitted,
                value: json!({"state":"active-relative-to-selected-evidence","resolution":state}),
            }
        }
        governance::GovernanceResolution::NonActive(state) => {
            // The native workspace also supports an inception signed by the exact
            // active did:kan controller. Do not extend this shortcut over updates.
            let verified = candidates.is_empty()
                && active.iter().any(|a| {
                    inception
                        .proved_event_with_did_kan_state(a, event.proofs.clone())
                        .ok()
                        .as_ref()
                        == Some(event)
                });
            if verified {
                return Scope {
                    roots: inception.governance_roots.clone(),
                    authority: None,
                    admission: ScopeAdmission::Admitted,
                    value: json!({"state":"verified-did-kan-inception","coverage":"Native inception-only authority; no unsupported governance updates inferred."}),
                };
            }
            let admission = match state.standing {
                governance::NonActiveGovernanceStanding::Contested => ScopeAdmission::Contested,
                governance::NonActiveGovernanceStanding::Invalid => ScopeAdmission::Unadmitted,
                _ => ScopeAdmission::Unknown,
            };
            Scope {
                roots: Vec::new(),
                authority: None,
                admission,
                value: json!({"state":"unresolved","resolution":state}),
            }
        }
    }
}
pub(super) fn inspect(
    entries: &[(String, Cid)],
    blocks: &BTreeMap<String, (&[u8], usize)>,
    controls: &[Control],
    options: &View,
) -> Result<Value, ContentError> {
    let typed = controls
        .iter()
        .filter_map(|c| c.preserved.typed())
        .collect::<Vec<_>>();
    let supported_payload = |e: &ControlEvent| match (e.domain.as_str(), e.event_type.as_str()) {
        (did_kan::GENESIS_DOMAIN, did_kan::GENESIS_EVENT_TYPE) => {
            payload::<did_kan::DidKanGenesis>(e).is_some()
        }
        (did_kan_update::UPDATE_DOMAIN, did_kan_update::UPDATE_EVENT_TYPE) => {
            payload::<did_kan_update::DidKanUpdate>(e).is_some()
        }
        (scope_inception::INCEPTION_DOMAIN, scope_inception::INCEPTION_EVENT_TYPE) => {
            payload::<ScopeInception>(e).is_some()
        }
        (governance::GOVERNANCE_DOMAIN, governance::GOVERNANCE_EVENT_TYPE) => {
            payload::<governance::GovernanceEvent>(e).is_some()
        }
        (identity::capability::DELEGATION_DOMAIN, identity::capability::DELEGATION_EVENT_TYPE) => {
            payload::<identity::capability::Delegation>(e).is_some()
        }
        (identity::capability::REVOCATION_DOMAIN, identity::capability::REVOCATION_EVENT_TYPE) => {
            payload::<identity::capability::Revocation>(e).is_some()
        }
        _ => false,
    };
    let unsupported = controls.iter().any(|c| !c.preserved.is_supported())
        || typed.iter().any(|e| !supported_payload(e));
    let mut identities = Vec::new();
    let mut active = Vec::new();
    let mut identity_candidates = BTreeMap::<String, Vec<DidKanResolution>>::new();
    for event in typed.iter().filter(|e| {
        e.domain == did_kan::GENESIS_DOMAIN && e.event_type == did_kan::GENESIS_EVENT_TYPE
    }) {
        let Some(genesis) = payload::<did_kan::DidKanGenesis>(event) else {
            continue;
        };
        let Ok(did) = genesis.did() else {
            continue;
        };
        let candidates = typed
            .iter()
            .filter(|e| {
                e.domain == did_kan_update::UPDATE_DOMAIN
                    && e.event_type == did_kan_update::UPDATE_EVENT_TYPE
                    && same_did(e, &did)
            })
            .cloned()
            .collect::<Vec<_>>();
        let resolution = did_kan_update::resolve(&genesis, event, &candidates);
        let list = identity_candidates.entry(did).or_default();
        if !list.contains(&resolution) {
            list.push(resolution);
        }
    }
    for (did, resolutions) in identity_candidates {
        if resolutions.len() != 1 || unsupported {
            identities
                .push(json!({"did":did,"state":"incomplete-or-conflicting-control-evidence"}));
            continue;
        }
        match resolutions.into_iter().next().ok_or_else(invalid)? {
            DidKanResolution::Active(state) => {
                identities.push(json!({"did":did,"state":"active-relative-to-selected-evidence","resolution":state}));
                active.push(*state);
            }
            DidKanResolution::NonActive(state) => {
                identities.push(json!({"did":did,"state":"unresolved","resolution":state}))
            }
        }
    }
    let mut scopes = BTreeMap::new();
    for event in typed.iter().filter(|e| {
        e.domain == scope_inception::INCEPTION_DOMAIN
            && e.event_type == scope_inception::INCEPTION_EVENT_TYPE
    }) {
        let Some(inception) = payload::<ScopeInception>(event) else {
            continue;
        };
        let Ok(id) = inception.scope_id() else {
            continue;
        };
        let mut result = scope(&inception, event, &typed, &active);
        if unsupported {
            result.admission = ScopeAdmission::Unknown;
            result.roots.clear();
            result.authority = None;
            result.value = json!({"state":"unsupported-selected-control-evidence"});
        }
        if let Some(previous) = scopes.get_mut(&id.to_string()) {
            let previous: &mut Scope = previous;
            if previous.value != result.value {
                previous.admission = ScopeAdmission::Unknown;
                previous.roots.clear();
                previous.authority = None;
                previous.value = json!({"state":"conflicting-control-proof-variants"});
            }
        } else {
            scopes.insert(id.to_string(), result);
        }
    }
    let verification = VerificationContext::ResolvedIdentities { did_kan: &active };
    let mut decoded = BTreeMap::new();
    let mut positions = BTreeMap::new();
    let mut excluded = Vec::new();
    let mut authors = BTreeSet::new();
    for (path, cid) in entries {
        if !path.starts_with("tools.kan.claim/") && !path.starts_with("dev.kan.claim/") {
            continue;
        }
        let (bytes, index) = blocks[&cid.to_string()];
        let shape = bounded::<Ipld>(bytes).ok();
        let current = matches!(&shape,Some(Ipld::Map(m)) if m.get("codec")==Some(&Ipld::String(codec::V2_CODEC.to_owned())));
        if !current {
            continue;
        }
        let record = match codec::decode_record(bytes, verification) {
            Ok(r) => r,
            Err(_) => {
                excluded.push(json!({"block":cid.to_string(),"after":index,"state":"signature-or-identity-unresolved","reason":"Current claim could not be verified against the selected exact identity state; raw bytes remain inspectable."}));
                continue;
            }
        };
        let DecodedClaim::Supported(SupportedClaim::Claim(claim)) = &record.claim else {
            continue;
        };
        let id = claim.id().map_err(|_| invalid())?.cid().to_string();
        authors.insert(claim.content().author().principal().to_owned());
        if decoded.get(&id).is_some_and(|old| old != &record) {
            return Err(invalid());
        }
        positions.insert(id.clone(), json!({"block":cid.to_string(),"after":index}));
        decoded.insert(id, record);
    }
    if authors.len() > 128 {
        return Err(ContentError::Limited);
    }
    let trust = ClaimTrustBase::local(
        options
            .principals
            .iter()
            .cloned()
            .map(ClaimAuthor::Principal),
    );
    let claims = view::project(decoded.into_values(), &trust, |claim| {
        let standing = match claim.content().author().identity_version() {
            IdentityVersion::Static => IdentityStateStanding::Static,
            IdentityVersion::Event(_) => IdentityStateStanding::Active,
            _ => IdentityStateStanding::Unknown,
        };
        let scope_invocation=match claim.content().author().identity_version() {
            IdentityVersion::Static=>true,
            IdentityVersion::Event(id)=>{
                let checkpoint=typed.iter().any(|e|e.logical_cid().ok().as_ref()==Some(id) && (e.domain==did_kan::GENESIS_DOMAIN || matches!(&e.payload,Ipld::Map(m) if m.get("mode")==Some(&Ipld::String("recovery".into())))));
                !checkpoint && active.iter().filter(|s|s.did==claim.content().author().principal()).any(|s|s.verification_methods.iter().any(|m|m.id==claim.content().author().verification_method()&&m.purposes.contains(&did_kan::VerificationPurpose::CapabilityInvocation)))
            }
            _=>false,
        };
        let admission = scopes.get(&claim.content().scope().to_string()).map_or(
            ScopeAdmission::Unknown,
            |scope| {
                if scope.admission != ScopeAdmission::Admitted {
                    return scope.admission;
                }
                let author = claim.content().author().principal();
                if scope.roots.iter().any(|root| root == author)
                    && claim.content().delegation().is_none()
                {
                    return ScopeAdmission::Admitted;
                }
                let (Some(authority), Some(head)) =
                    (&scope.authority, claim.content().delegation())
                else {
                    return ScopeAdmission::Unknown;
                };
                let candidates=typed.iter().filter(|e| e.domain==identity::capability::DELEGATION_DOMAIN || e.domain==identity::capability::REVOCATION_DOMAIN).cloned().collect::<Vec<_>>();
                let evidence = identity::capability::resolve(authority, &candidates);
                if !evidence.invalid.is_empty()
                    || !evidence.unsupported.is_empty()
                    || !evidence.missing_references.is_empty() || !evidence.orphans.is_empty()
                {
                    return ScopeAdmission::Unknown;
                }
                let Some(delegation)=evidence.delegations.iter().find(|d|&d.event==head.cid()) else {return ScopeAdmission::Unknown;};
                if delegation.delegate!=author {return ScopeAdmission::Unadmitted;}
                let path = evidence.evaluate(
                    authority,
                    head.cid(),
                    identity::capability::CLAIM_WRITE,
                    claim.content().subject().as_str(),
                    None,
                );
                identity::scope_admission(identity::AdmissionFacts {
                    scope_scoped: true,
                    cryptographic_validity: identity::CryptographicValidity::Valid,
                    identity_standing: standing,
                    identity_checkpoint: false,
                    governance: identity::GovernanceResolution::Active,
                    trusted_time: path.trusted_time,
                    revocation: path.revocation,
                    capability: path.capability,
                })
            },
        );
        CurrentEvaluation {
            identity_state_standing: standing,
            scope_admission: if scope_invocation {admission} else {ScopeAdmission::Unadmitted},
        }
    })
    .map_err(|_| invalid())?;
    let folded = crate::fold::claim_view::fold(claims.clone(), None);
    let total = folded.classes.len();
    let mut classes = Vec::new();
    let mut size = 0;
    let render = |c: &view::ClaimView| {
        let ClaimSource::Claim(claim) = c.source() else {
            return Value::Null;
        };
        json!({"id":c.claim_id().to_string(),"content":claim.content(),"judgments":c.judgments(),"source":positions.get(&c.claim_id().to_string())})
    };
    for class in folded
        .classes
        .into_iter()
        .skip(options.current_after)
        .take(100)
    {
        let effective = class.effective_claims();
        let state = crate::fold::claim_view_state::classify(&effective, &[]);
        use crate::fold::claim_view_state::StateView;
        let status = match &state {
            StateView::Unclassified => json!({"kind":"unclassified"}),
            StateView::Settled { value, .. } => json!({"kind":"settled","value":value}),
            StateView::Confirmed { value, .. } => json!({"kind":"confirmed","value":value}),
            StateView::Contested { .. } => json!({"kind":"contested"}),
        };
        let mut live = state
            .live_cids()
            .into_iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>();
        live.sort();
        let value = json!({"subjects":class.subjects.iter().map(subject).collect::<Vec<_>>(),"status":status,"live_status_claims":live,"claims":class.claims.iter().map(&render).collect::<Vec<_>>(),"witnesses":class.witnesses.iter().map(|w|json!({"claim":w.claim_cid.to_string(),"from":subject(&w.from),"to":subject(&w.to),"source":positions.get(&w.claim_cid.to_string())})).collect::<Vec<_>>()});
        size += serde_json::to_vec(&value).map_err(|_| invalid())?.len();
        if size > 2 * 1024 * 1024 {
            if classes.is_empty() {
                return Err(ContentError::Limited);
            }
            break;
        }
        classes.push(value);
    }
    let next = options.current_after + classes.len();
    let value = json!({"version":"kan-current-claim-view/1","coverage":"Relative to this imported HEAD and explicitly selected control records. This does not establish global history completeness, trusted wall-clock time or network freshness. Native identity, governance, capability and fold rules apply; unsupported or absent authority remains unresolved. No legacy subject mapping is inferred.","authors":authors,"trust":options.principals,"verified_claims":claims.len(),"excluded_by_trust":claims.iter().filter(|c|matches!(c.judgments().view_trust,identity::ViewTrust::Excluded)).count(),"unresolved":excluded,"identities":identities,"scopes":scopes.into_iter().map(|(id,s)|json!({"scope":id,"authority":s.value})).collect::<Vec<_>>(),"controls":controls.iter().map(|c|json!({"id":c.preserved.logical_cid().ok().map(|id|id.to_string()),"supported":c.preserved.is_supported(),"sources":c.sources})).collect::<Vec<_>>(),"classes":classes,"total_classes":total,"next":(next<total).then_some(next)});
    if serde_json::to_vec(&value).map_err(|_| invalid())?.len() > 2 * 1024 * 1024 {
        return Err(ContentError::Limited);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        claim::{
            CanonicalSet, Claim, ClaimBody, ClaimContent, ClaimSigningInput, RecordedAt,
            StatusValue, SubjectPath, UniqueSequence,
        },
        identity::{
            authorship::Author,
            control::{self, Proof},
            did_kan_state::{DidKanState, IdentityOperation},
            did_kan_update::DidKanUpdate,
            enrollment::DailyDeviceEnrollment,
            system::CredentialReference,
        },
        sign::Identity,
    };
    fn proof(signer: &Identity, input: &control::SigningInput) -> Proof {
        let did = signer.did();
        Proof {
            method: format!("{did}#{}", did.strip_prefix("did:key:").unwrap()),
            controller_state: IdentityVersion::Static,
            alg: "P256".into(),
            sig: signer.sign(&input.canonical_bytes().unwrap()).unwrap(),
        }
    }
    #[test]
    fn current_import_identity_resolution_requires_invocation_and_excludes_recovery_checkpoints() {
        for (invocation, recovery_checkpoint) in [(true, false), (false, false), (true, true)] {
            let recovery = Identity::generate();
            let daily = Identity::generate();
            let enrollment = DailyDeviceEnrollment::new(
                [77; 32],
                "daily".into(),
                &recovery,
                CredentialReference::OwnerOnlyFile {
                    path: "unused-recovery.key".into(),
                },
                &daily,
                CredentialReference::OwnerOnlyFile {
                    path: "unused-daily.key".into(),
                },
            )
            .unwrap();
            let genesis = enrollment.genesis();
            let mut method = enrollment.daily_method().clone();
            if !invocation {
                method
                    .purposes
                    .retain(|p| *p != did_kan::VerificationPurpose::CapabilityInvocation);
            }
            let state0 = DidKanState::from_genesis(genesis).unwrap();
            let update = DidKanUpdate::administration(
                &state0,
                vec![IdentityOperation::AddMethod {
                    method: method.clone(),
                }],
            )
            .unwrap();
            let event = update
                .proved_event(vec![proof(&recovery, &update.signing_input().unwrap())])
                .unwrap();
            let mut events = vec![event];
            if recovery_checkpoint {
                let restored = DidKanUpdate::recovery(
                    update.resulting_state(),
                    &state0,
                    vec![IdentityOperation::SetMethodPurposes {
                        id: method.id.clone(),
                        purposes: method.purposes.clone(),
                    }],
                    vec![],
                )
                .unwrap();
                events.push(
                    restored
                        .proved_event(vec![proof(&recovery, &restored.signing_input().unwrap())])
                        .unwrap(),
                );
            }
            let DidKanResolution::Active(state) =
                did_kan_update::resolve(genesis, enrollment.genesis_event(), &events)
            else {
                panic!("fixture identity must resolve");
            };
            let inception = ScopeInception::new(
                [78; 32],
                vec!["imported".into()],
                vec![state.did.clone()],
                vec![],
            )
            .unwrap();
            let input = inception.signing_input().unwrap();
            let scope_event = inception
                .proved_event_with_did_kan_state(
                    &state,
                    vec![Proof {
                        method: method.id.clone(),
                        controller_state: IdentityVersion::Event(state.active_event.clone()),
                        alg: "P256".into(),
                        sig: daily.sign(&input.canonical_bytes().unwrap()).unwrap(),
                    }],
                )
                .unwrap();
            let content = ClaimContent::new(
                Author::new(
                    state.did.clone(),
                    method.id.clone(),
                    IdentityVersion::Event(state.active_event.clone()),
                )
                .unwrap(),
                inception.scope_id().unwrap(),
                None,
                SubjectPath::new("process/status".into()).unwrap(),
                CanonicalSet::new(vec![]).unwrap(),
                ClaimBody::Status {
                    value: StatusValue::Blocked,
                },
                CanonicalSet::new(vec![]).unwrap(),
                UniqueSequence::new(vec![]).unwrap(),
                RecordedAt::new(100).unwrap(),
            )
            .unwrap();
            let message = ClaimSigningInput::new(&content.id().unwrap())
                .canonical_bytes()
                .unwrap();
            let claim =
                Claim::verify_active_did_kan(content, daily.sign(&message).unwrap(), &state)
                    .unwrap();
            let bytes = codec::encode_claim(&claim, "3jzfcijpj2z2a").unwrap();
            let cid = Cid::from(atproto_repo::compute_cid(&bytes));
            let entries = vec![("tools.kan.claim/status".into(), cid.clone())];
            let blocks = BTreeMap::from([(cid.to_string(), (bytes.as_slice(), 0))]);
            let controls = std::iter::once(enrollment.genesis_event().clone())
                .chain(events)
                .chain(std::iter::once(scope_event))
                .map(|event| Control {
                    preserved: control::decode_preserving(&event.canonical_bytes().unwrap())
                        .unwrap(),
                    sources: vec![json!({"fixture":"explicit-control"})],
                })
                .collect::<Vec<_>>();
            let options = View {
                principals: vec![state.did.clone()],
                ..View::default()
            };
            let missing = inspect(&entries, &blocks, &[], &options).unwrap();
            assert_eq!(missing["verified_claims"], 0);
            assert_eq!(missing["unresolved"].as_array().unwrap().len(), 1);
            let result = inspect(&entries, &blocks, &controls, &options).unwrap();
            assert_eq!(result["verified_claims"], 1, "{result}");
            let expected = if invocation && !recovery_checkpoint {
                "admitted"
            } else {
                "unadmitted"
            };
            let judgments = &result["classes"][0]["claims"][0]["judgments"];
            assert_eq!(judgments["cryptographicValidity"], "valid");
            assert_eq!(judgments["scopeAdmission"], expected, "{result}");
            assert_eq!(
                result["classes"][0]["status"]["kind"],
                if invocation && !recovery_checkpoint {
                    "settled"
                } else {
                    "unclassified"
                }
            );
        }
    }
}

//! RFC 2 target continuity over an explicitly selected imported repository.
//! Locator bindings and trust are consumer inputs, never new identity authority.
use super::{invalid, ContentError, Value, View};
use crate::{
    claim::view::{ClaimSource, ClaimView},
    uri::{
        EvidenceSelection, KanAuthority, ResolutionRequest, Resource, Route, ScopeSelector,
        TrustSelector,
    },
};
use serde_json::json;
use std::collections::BTreeMap;

pub(super) fn validate(options: &View) -> Result<(), ContentError> {
    if options.uri.as_ref().is_some_and(|u| u.len() > 32768)
        || options.scope_aliases.len() > 128
        || options.scope_aliases.keys().any(|k| k.len() > 256)
        || options.scope_aliases.values().any(|v| {
            v.len() > 256
                || v.parse::<crate::identity::scope_inception::ScopeId>()
                    .is_err()
        })
    {
        return Err(invalid());
    }
    let Some(uri) = &options.uri else {
        return Ok(());
    };
    let request = ResolutionRequest::parse(uri).map_err(|_| invalid())?;
    // Network routing, wall-clock evaluation and replay selectors cannot be
    // silently satisfied by whichever imported file the caller selected.
    if !matches!(
        request.route(),
        Route::Kan(KanAuthority::Local { port: None })
    ) || request.evidence() != &EvidenceSelection::default()
        || request.evaluation().at.is_some()
        || !matches!(
            request.resource(),
            Resource::Claim(_) | Resource::ScopeIdentity
        )
        || request.scope().is_none()
    {
        return Err(invalid());
    }
    principals(options)?;
    Ok(())
}

pub(super) fn principals(options: &View) -> Result<Vec<String>, ContentError> {
    let Some(uri) = &options.uri else {
        return Ok(options.principals.clone());
    };
    let request = ResolutionRequest::parse(uri).map_err(|_| invalid())?;
    let Some(trust) = &request.evaluation().trust else {
        return Ok(options.principals.clone());
    };
    trust
        .selectors()
        .iter()
        .map(|selector| match selector {
            TrustSelector::Principal { did, weight } if weight.as_str() == "1" => Ok(did.clone()),
            _ => Err(invalid()), // local roles/weighted folds require their original context
        })
        .collect()
}

pub(super) fn resolve(
    options: &View,
    claims: &[ClaimView],
    scopes: &[Value],
    positions: &BTreeMap<String, Value>,
) -> Result<Value, ContentError> {
    let Some(uri) = &options.uri else {
        return Ok(Value::Null);
    };
    validate(options)?;
    let request = ResolutionRequest::parse(uri).map_err(|_| invalid())?;
    let scope = match request.scope().ok_or_else(invalid)? {
        ScopeSelector::Direct(scope) => *scope,
        ScopeSelector::Named(name) => options
            .scope_aliases
            .get(name.as_str())
            .ok_or_else(invalid)?
            .parse::<crate::identity::scope_inception::ScopeId>()
            .map_err(|_| invalid())?,
    };
    let authority = scopes.iter().find(|s| s["scope"] == scope.to_string());
    let resource = match request.resource() {
        Resource::Claim(id) => claims.iter().find_map(|c| {
            if c.claim_id()!=id { return None; }
            let content=match c.source() {
                ClaimSource::Claim(claim) if claim.content().scope()==scope => json!(claim.content()),
                // Historical claims retain their original unscoped bytes. An
                // explicit selected inception provides the requested scope context.
                ClaimSource::V1(claim) if authority.is_some() => json!(claim.content),
                _ => return None,
            };
            Some(json!({"kind":"claim","codec":c.codec(),"id":id.to_string(),"content":content,"judgments":c.judgments(),"source":positions.get(&id.to_string())}))
        }),
        Resource::ScopeIdentity => authority.cloned().map(|a| json!({"kind":"scope-identity","identifier":scope,"authority":a["authority"]})),
        _ => return Err(invalid()),
    };
    Ok(
        json!({"request":request.canonical_uri(),"target":{"scope":scope,"kind":request.resource().kind_name()},"state":if resource.is_some(){"resolved"}else{"not-found-at-selected-evidence"},"resource":resource,"locator_bindings":options.scope_aliases,"trust":principals(options)?,"coverage":"Only this imported HEAD and selected control evidence. Locator bindings are explicit caller inputs; access, signed identity, scope admission and view trust remain separate."}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_aliases_roundtrip_as_canonical_json_text_and_reject_invalid_ids() {
        let mut bytes = [7; 34];
        bytes[0] = 0x12;
        bytes[1] = 0x20;
        let scope = crate::identity::scope_inception::ScopeId::from_bytes(bytes).unwrap();
        let input = json!({"uri":"kan://local/project/identity/scope", "scope_aliases":{"project":scope.to_string()}});
        let view: View = serde_json::from_value(input.clone()).unwrap();
        validate(&view).unwrap();
        let saved = serde_json::to_value(&view).unwrap();
        assert_eq!(saved["scope_aliases"], input["scope_aliases"]);
        let replay: View = serde_json::from_value(saved).unwrap();
        let result = resolve(
            &replay,
            &[],
            &[json!({"scope":scope.to_string(),"authority":{"state":"test"}})],
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(result["state"], "resolved");
        assert_eq!(result["locator_bindings"], input["scope_aliases"]);
        for invalid_id in ["not-a-scope".to_owned(), scope.to_string().to_uppercase()] {
            let bad: View =
                serde_json::from_value(json!({"scope_aliases":{"project":invalid_id}})).unwrap();
            assert!(validate(&bad).is_err());
        }
        // The binary signed-object codec is not an alternate JSON API grammar.
        assert!(
            serde_json::from_value::<View>(json!({"scope_aliases":{"project":scope}})).is_err()
        );
        let mut missing = view;
        missing.scope_aliases.clear();
        assert!(resolve(&missing, &[], &[], &BTreeMap::new()).is_err());
    }
}

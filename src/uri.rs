//! RFC 2 URI request types and access-free syntactic canonicalization.
//!
//! Parsing this module's [`ResolutionRequest`] never opens a workspace,
//! resolves a locator, reads a credential, or performs network access.  It is
//! the typed request boundary shared by the later local, hosted, Git, and
//! ATProto resolvers.

use std::{collections::BTreeMap, fmt, str::FromStr};

use atproto_dasl::Cid;

use crate::identity::{control::IdentityVersion, scope_inception::ScopeId};

pub mod local;

/// A scheme and authority pair whose invalid cross-scheme combinations cannot
/// be represented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Kan(KanAuthority),
    Git(GitAuthority),
    At(AtAuthority),
}

impl Route {
    pub fn scheme(&self) -> Scheme {
        match self {
            Self::Kan(_) => Scheme::Kan,
            Self::Git(_) => Scheme::KanGit,
            Self::At(_) => Scheme::KanAt,
        }
    }

    /// The semantic authority name, excluding Git transport user and port.
    pub fn authority_name(&self) -> String {
        match self {
            Self::Kan(KanAuthority::Local { .. })
            | Self::Git(GitAuthority {
                host: GitHost::Local,
                ..
            }) => "local".to_string(),
            Self::Kan(KanAuthority::Host { host, .. })
            | Self::Git(GitAuthority {
                host: GitHost::Dns(host),
                ..
            }) => host.clone(),
            Self::Kan(KanAuthority::Did(principal)) | Self::At(AtAuthority::Did(principal)) => {
                principal.to_string()
            }
            Self::At(AtAuthority::Handle(handle)) => handle.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Kan,
    KanGit,
    KanAt,
}

impl fmt::Display for Scheme {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Kan => "kan",
            Self::KanGit => "kan+git",
            Self::KanAt => "kan+at",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KanAuthority {
    Local { port: Option<u16> },
    Host { host: String, port: Option<u16> },
    Did(PrincipalId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitAuthority {
    pub host: GitHost,
    pub port: Option<u16>,
    pub transport_user: Option<String>,
    pub transport: GitTransport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitHost {
    Local,
    Dns(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitTransport {
    Local,
    Https,
    Ssh,
}

impl fmt::Display for GitTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Local => "local",
            Self::Https => "https",
            Self::Ssh => "ssh",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtAuthority {
    Handle(String),
    Did(PrincipalId),
}

/// A principal identifier split at the URI structural boundary. The
/// method-specific identifier is exactly one decoded path segment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrincipalId {
    method: String,
    method_specific_id: String,
}

impl PrincipalId {
    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn method_specific_id(&self) -> &str {
        &self.method_specific_id
    }

    fn from_path(method: String, method_specific_id: String) -> Result<Self, ParseError> {
        if method.is_empty()
            || !method.bytes().all(|byte| byte.is_ascii_lowercase())
            || method_specific_id.is_empty()
        {
            return Err(ParseError::NonCanonicalIdentifier);
        }
        Ok(Self {
            method,
            method_specific_id,
        })
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "did:{}:{}", self.method, self.method_specific_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeSelector {
    Named(ScopeLocator),
    Direct(ScopeId),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeLocator(String);

impl ScopeLocator {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ScopeLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resource {
    Claim(Cid),
    Subject(SubjectSelector),
    ScopeIdentity,
    AuthorityIdentity,
    PrincipalIdentity(PrincipalId),
}

impl Resource {
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Claim(_) => "claim",
            Self::Subject(_) => "subject",
            Self::ScopeIdentity => "scope-identity",
            Self::AuthorityIdentity => "authority-identity",
            Self::PrincipalIdentity(_) => "principal-identity",
        }
    }

    pub fn key(&self) -> Option<String> {
        match self {
            Self::Claim(cid) => Some(cid.to_string()),
            Self::Subject(subject) => Some(subject.to_string()),
            Self::PrincipalIdentity(principal) => Some(principal.to_string()),
            Self::ScopeIdentity | Self::AuthorityIdentity => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectSelector {
    Path(SubjectPath),
    PreservedV1Cid(Cid),
}

impl fmt::Display for SubjectSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(path) => fmt::Display::fmt(path, formatter),
            Self::PreservedV1Cid(cid) => write!(formatter, "@cid:{cid}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubjectPath(Vec<String>);

impl SubjectPath {
    pub fn segments(&self) -> &[String] {
        &self.0
    }
}

impl fmt::Display for SubjectPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0.join("/"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EvidenceSelection {
    pub sources: Vec<String>,
    pub service: Option<String>,
    pub commit: Option<String>,
    pub git_ref: Option<String>,
    pub snapshot: Option<String>,
    pub version: Option<IdentityVersion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EvaluationInputs {
    pub trust: Option<TrustSelection>,
    pub at: Option<u64>,
}

/// A closed trust input carried by one resolution request.
///
/// Composite order is intentional. Two local selectors can resolve to the
/// same principal, and the later selector supplies that principal's weight;
/// sorting here would therefore change the requested fold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustSelection {
    One(TrustSelector),
    Composite(Vec<TrustSelector>),
}

impl TrustSelection {
    /// Compile the released repeatable CLI/MCP surface into one request value.
    pub fn from_specs(specs: &[String]) -> Result<Option<Self>, ParseError> {
        if specs.is_empty() {
            return Ok(None);
        }
        let selectors = specs
            .iter()
            .map(|spec| parse_trust_selector(spec))
            .collect::<Result<Vec<_>, _>>()?;
        unique_trust_selectors(&selectors)?;
        Ok(Some(if selectors.len() == 1 {
            Self::One(selectors.into_iter().next().expect("one selector"))
        } else {
            Self::Composite(selectors)
        }))
    }

    pub fn selectors(&self) -> &[TrustSelector] {
        match self {
            Self::One(selector) => std::slice::from_ref(selector),
            Self::Composite(selectors) => selectors,
        }
    }

    /// Legacy local spellings consumed by `Workspace` after request parsing.
    pub fn specs(&self) -> Vec<String> {
        self.selectors().iter().map(ToString::to_string).collect()
    }

    fn parse(value: &str) -> Result<Self, ParseError> {
        let Some(json) = value.strip_prefix("@set:") else {
            return Ok(Self::One(parse_trust_selector(value)?));
        };
        let members: Vec<String> =
            serde_json::from_str(json).map_err(|_| ParseError::InvalidSelector)?;
        if members.len() < 2 {
            return Err(ParseError::InvalidSelector);
        }
        let selectors = members
            .iter()
            .map(|member| parse_trust_selector(member))
            .collect::<Result<Vec<_>, _>>()?;
        unique_trust_selectors(&selectors)?;
        Ok(Self::Composite(selectors))
    }

    pub fn canonical_text(&self) -> String {
        match self {
            Self::One(selector) => selector.to_string(),
            Self::Composite(selectors) => {
                let members: Vec<String> = selectors.iter().map(ToString::to_string).collect();
                format!(
                    "@set:{}",
                    serde_json::to_string(&members).expect("trust selector strings serialize")
                )
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TrustSelector {
    ConfiguredFrame(String),
    CurrentActor(TrustWeight),
    NamedRole { name: String, weight: TrustWeight },
    Principal { did: String, weight: TrustWeight },
}

impl fmt::Display for TrustSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfiguredFrame(name) => formatter.write_str(name),
            Self::CurrentActor(weight) => write_weighted(formatter, "me", weight),
            Self::NamedRole { name, weight } => {
                write_weighted(formatter, &format!("role:{name}"), weight)
            }
            Self::Principal { did, weight } => write_weighted(formatter, did, weight),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrustWeight(String);

impl TrustWeight {
    fn parse(value: Option<&str>) -> Result<Self, ParseError> {
        let Some(value) = value else {
            return Ok(Self("1".to_string()));
        };
        let parsed: f64 = value
            .trim()
            .parse()
            .map_err(|_| ParseError::InvalidSelector)?;
        if !parsed.is_finite() || !(0.0..=1.0).contains(&parsed) {
            return Err(ParseError::InvalidSelector);
        }
        let canonical = if parsed == 0.0 {
            "0".to_string()
        } else if parsed == 1.0 {
            "1".to_string()
        } else {
            parsed.to_string()
        };
        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn write_weighted(
    formatter: &mut fmt::Formatter<'_>,
    principal: &str,
    weight: &TrustWeight,
) -> fmt::Result {
    formatter.write_str(principal)?;
    if weight.as_str() != "1" {
        write!(formatter, "={}", weight.as_str())?;
    }
    Ok(())
}

fn parse_trust_selector(value: &str) -> Result<TrustSelector, ParseError> {
    let value = value.trim();
    if value.is_empty() || value.starts_with('@') || value.chars().any(char::is_control) {
        return Err(ParseError::InvalidSelector);
    }
    let (name, raw_weight) = value
        .split_once('=')
        .map_or((value, None), |(name, weight)| (name.trim(), Some(weight)));
    if name == "me" {
        return Ok(TrustSelector::CurrentActor(TrustWeight::parse(raw_weight)?));
    }
    if let Some(role) = name.strip_prefix("role:") {
        if role.is_empty() {
            return Err(ParseError::InvalidSelector);
        }
        return Ok(TrustSelector::NamedRole {
            name: role.to_string(),
            weight: TrustWeight::parse(raw_weight)?,
        });
    }
    if let Some(did) = name.strip_prefix("did:") {
        let Some((method, identifier)) = did.split_once(':') else {
            return Err(ParseError::NonCanonicalIdentifier);
        };
        if method.is_empty()
            || !method.bytes().all(|byte| byte.is_ascii_lowercase())
            || identifier.is_empty()
        {
            return Err(ParseError::NonCanonicalIdentifier);
        }
        return Ok(TrustSelector::Principal {
            did: name.to_string(),
            weight: TrustWeight::parse(raw_weight)?,
        });
    }
    if raw_weight.is_some() {
        return Err(ParseError::InvalidSelector);
    }
    Ok(TrustSelector::ConfiguredFrame(name.to_string()))
}

fn unique_trust_selectors(selectors: &[TrustSelector]) -> Result<(), ParseError> {
    let mut seen = std::collections::HashSet::new();
    if selectors
        .iter()
        .all(|selector| seen.insert(selector.clone()))
    {
        Ok(())
    } else {
        Err(ParseError::DuplicateParameter)
    }
}

/// The complete typed identity of one resolution operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionRequest {
    route: Route,
    scope: Option<ScopeSelector>,
    resource: Resource,
    evidence: EvidenceSelection,
    evaluation: EvaluationInputs,
}

impl ResolutionRequest {
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        Parser::new(input)?.parse()
    }

    /// Compile local application shorthand without giving CLI or MCP layers
    /// a second path grammar or query encoder.
    pub fn local_subject(
        scope: ScopeId,
        subject: &str,
        trust: Option<&TrustSelection>,
    ) -> Result<Self, ParseError> {
        let encoded_subject = subject
            .split('/')
            .map(encode_segment)
            .collect::<Vec<_>>()
            .join("/");
        let mut uri = format!("kan://local/@id:{scope}/subject/{encoded_subject}");
        if let Some(trust) = trust {
            uri.push_str("?trust=");
            uri.push_str(&encode_query(&trust.canonical_text()));
        }
        Self::parse(&uri)
    }

    pub fn local_scope_identity(
        scope: ScopeId,
        trust: Option<&TrustSelection>,
    ) -> Result<Self, ParseError> {
        let mut uri = format!("kan://local/@id:{scope}/identity/scope");
        if let Some(trust) = trust {
            uri.push_str("?trust=");
            uri.push_str(&encode_query(&trust.canonical_text()));
        }
        Self::parse(&uri)
    }

    pub fn canonical_uri(&self) -> String {
        let mut output = self.canonical_base();
        let query = self.canonical_query();
        if !query.is_empty() {
            output.push('?');
            output.push_str(&query);
        }
        output
    }

    pub fn route(&self) -> &Route {
        &self.route
    }

    pub fn scope(&self) -> Option<&ScopeSelector> {
        self.scope.as_ref()
    }

    pub fn resource(&self) -> &Resource {
        &self.resource
    }

    pub fn evidence(&self) -> &EvidenceSelection {
        &self.evidence
    }

    pub fn evaluation(&self) -> &EvaluationInputs {
        &self.evaluation
    }

    pub fn requested_scope(&self) -> Option<ScopeId> {
        match self.scope {
            Some(ScopeSelector::Direct(id)) => Some(id),
            Some(ScopeSelector::Named(_)) | None => None,
        }
    }

    pub fn scope_locator(&self) -> Option<&ScopeLocator> {
        match &self.scope {
            Some(ScopeSelector::Named(locator)) => Some(locator),
            Some(ScopeSelector::Direct(_)) | None => None,
        }
    }

    pub fn git_repository_path(&self) -> Option<String> {
        if !matches!(self.route, Route::Git(_)) {
            return None;
        }
        self.scope_locator()
            .map(|locator| locator.as_str().replace(':', "/"))
    }

    fn canonical_base(&self) -> String {
        let mut output = self.route.scheme().to_string();
        output.push_str("://");
        match &self.route {
            Route::Kan(authority) => match authority {
                KanAuthority::Local { port } => append_host(&mut output, "local", *port),
                KanAuthority::Host { host, port } => append_host(&mut output, host, *port),
                KanAuthority::Did(_) => output.push_str("did"),
            },
            Route::Git(authority) => {
                if let Some(user) = &authority.transport_user {
                    output.push_str(&encode_transport_user(user));
                    output.push('@');
                }
                match &authority.host {
                    GitHost::Local => append_host(&mut output, "local", authority.port),
                    GitHost::Dns(host) => append_host(&mut output, host, authority.port),
                }
            }
            Route::At(AtAuthority::Handle(handle)) => output.push_str(handle),
            Route::At(AtAuthority::Did(_)) => output.push_str("did"),
        }

        let mut segments = Vec::new();
        match &self.route {
            Route::Kan(KanAuthority::Did(principal)) | Route::At(AtAuthority::Did(principal)) => {
                segments.push(encode_segment(principal.method()));
                segments.push(encode_segment(principal.method_specific_id()));
            }
            _ => {}
        }

        if let Some(scope) = &self.scope {
            segments.push(match scope {
                ScopeSelector::Named(locator) => encode_segment(locator.as_str()),
                ScopeSelector::Direct(id) => format!("@id:{id}"),
            });
        }

        let did_authority = matches!(
            self.route,
            Route::Kan(KanAuthority::Did(_)) | Route::At(AtAuthority::Did(_))
        );
        match &self.resource {
            Resource::AuthorityIdentity => segments.push("identity".to_string()),
            Resource::PrincipalIdentity(_) if did_authority && self.scope.is_none() => {
                segments.push("identity".to_string());
            }
            Resource::Claim(cid) => {
                segments.push("claim".to_string());
                segments.push(cid.to_string());
            }
            Resource::Subject(SubjectSelector::Path(path)) => {
                segments.push("subject".to_string());
                segments.extend(path.segments().iter().map(|value| encode_segment(value)));
            }
            Resource::Subject(SubjectSelector::PreservedV1Cid(cid)) => {
                segments.push("subject".to_string());
                segments.push(format!("@cid:{cid}"));
            }
            Resource::ScopeIdentity => {
                segments.push("identity".to_string());
                segments.push("scope".to_string());
            }
            Resource::PrincipalIdentity(principal) => {
                segments.extend([
                    "identity".to_string(),
                    "principal".to_string(),
                    "did".to_string(),
                    encode_segment(principal.method()),
                    encode_segment(principal.method_specific_id()),
                ]);
            }
        }
        output.push('/');
        output.push_str(&segments.join("/"));
        output
    }

    fn canonical_query(&self) -> String {
        let mut pairs = Vec::new();
        let mut sources: Vec<_> = self
            .evidence
            .sources
            .iter()
            .map(|source| encode_query(source))
            .collect();
        sources.sort();
        pairs.extend(sources.into_iter().map(|source| format!("source={source}")));
        if let Some(service) = &self.evidence.service {
            pairs.push(format!("service={}", encode_query(service)));
        }
        if let Some(commit) = &self.evidence.commit {
            pairs.push(format!("commit={}", encode_query(commit)));
        } else if let Some(git_ref) = &self.evidence.git_ref {
            pairs.push(format!("ref={}", encode_query(git_ref)));
        } else if let Some(snapshot) = &self.evidence.snapshot {
            pairs.push(format!("snapshot={}", encode_query(snapshot)));
        }
        if let Some(version) = &self.evidence.version {
            pairs.push(format!("version={}", encode_query(&version_text(version))));
        }
        if let Some(trust) = &self.evaluation.trust {
            pairs.push(format!("trust={}", encode_query(&trust.canonical_text())));
        }
        if let Some(at) = self.evaluation.at {
            pairs.push(format!("at={at}"));
        }
        pairs.join("&")
    }
}

impl FromStr for ResolutionRequest {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("unsupported-scheme")]
    UnsupportedScheme,
    #[error("malformed-uri")]
    MalformedUri,
    #[error("fragment-not-supported")]
    FragmentNotSupported,
    #[error("userinfo-forbidden")]
    UserinfoForbidden,
    #[error("credential-in-userinfo")]
    CredentialInUserinfo,
    #[error("invalid-path-segment")]
    InvalidPathSegment,
    #[error("encoded-separator")]
    EncodedSeparator,
    #[error("invalid-utf8")]
    InvalidUtf8,
    #[error("invalid-percent-encoding")]
    InvalidPercentEncoding,
    #[error("unsupported-selector")]
    UnsupportedSelector,
    #[error("invalid-selector")]
    InvalidSelector,
    #[error("non-canonical-identifier")]
    NonCanonicalIdentifier,
    #[error("unsupported-parameter")]
    UnsupportedParameter,
    #[error("duplicate-parameter")]
    DuplicateParameter,
    #[error("conflicting-snapshot-selectors")]
    ConflictingSnapshotSelectors,
    #[error("inapplicable-parameter")]
    InapplicableParameter,
}

impl ParseError {
    pub fn code(self) -> &'static str {
        match self {
            Self::UnsupportedScheme => "unsupported-scheme",
            Self::MalformedUri => "malformed-uri",
            Self::FragmentNotSupported => "fragment-not-supported",
            Self::UserinfoForbidden => "userinfo-forbidden",
            Self::CredentialInUserinfo => "credential-in-userinfo",
            Self::InvalidPathSegment => "invalid-path-segment",
            Self::EncodedSeparator => "encoded-separator",
            Self::InvalidUtf8 => "invalid-utf8",
            Self::InvalidPercentEncoding => "invalid-percent-encoding",
            Self::UnsupportedSelector => "unsupported-selector",
            Self::InvalidSelector => "invalid-selector",
            Self::NonCanonicalIdentifier => "non-canonical-identifier",
            Self::UnsupportedParameter => "unsupported-parameter",
            Self::DuplicateParameter => "duplicate-parameter",
            Self::ConflictingSnapshotSelectors => "conflicting-snapshot-selectors",
            Self::InapplicableParameter => "inapplicable-parameter",
        }
    }
}

struct Parser<'a> {
    scheme: Scheme,
    raw_authority: &'a str,
    raw_path: &'a str,
    raw_query: Option<&'a str>,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Result<Self, ParseError> {
        let Some(colon) = input.find(':') else {
            return Err(ParseError::UnsupportedScheme);
        };
        let scheme = match input[..colon].to_ascii_lowercase().as_str() {
            "kan" => Scheme::Kan,
            "kan+git" => Scheme::KanGit,
            "kan+at" => Scheme::KanAt,
            _ => return Err(ParseError::UnsupportedScheme),
        };
        if input.contains('#') {
            return Err(ParseError::FragmentNotSupported);
        }
        let after_scheme = input
            .get(colon + 1..)
            .and_then(|rest| rest.strip_prefix("//"))
            .ok_or(ParseError::MalformedUri)?;
        let slash = after_scheme.find('/').ok_or(ParseError::MalformedUri)?;
        let raw_authority = &after_scheme[..slash];
        if raw_authority.is_empty() {
            return Err(ParseError::MalformedUri);
        }
        let path_and_query = &after_scheme[slash + 1..];
        let (raw_path, raw_query) = match path_and_query.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (path_and_query, None),
        };
        if raw_path.is_empty() {
            return Err(ParseError::InvalidPathSegment);
        }
        Ok(Self {
            scheme,
            raw_authority,
            raw_path,
            raw_query,
        })
    }

    fn parse(self) -> Result<ResolutionRequest, ParseError> {
        let (host, port, user) = parse_authority(self.raw_authority, self.scheme)?;
        let parts = self
            .raw_path
            .split('/')
            .map(decode_segment)
            .collect::<Result<Vec<_>, _>>()?;
        let did_route = host == "did" && matches!(self.scheme, Scheme::Kan | Scheme::KanAt);
        let (route, scope, resource_parts) = if did_route {
            if port.is_some() || user.is_some() || parts.len() < 3 {
                return Err(ParseError::InvalidPathSegment);
            }
            let principal = PrincipalId::from_path(parts[0].clone(), parts[1].clone())?;
            let route = match self.scheme {
                Scheme::Kan => Route::Kan(KanAuthority::Did(principal.clone())),
                Scheme::KanAt => Route::At(AtAuthority::Did(principal.clone())),
                Scheme::KanGit => unreachable!("did_route excludes kan+git"),
            };
            if parts[2..] == ["identity"] {
                (route, None, PrincipalParts::Freestanding(principal))
            } else {
                if matches!(self.scheme, Scheme::Kan) {
                    return Err(ParseError::InvalidPathSegment);
                }
                if parts.len() < 4 {
                    return Err(ParseError::InvalidPathSegment);
                }
                let scope = parse_scope(&parts[2], self.scheme)?;
                (route, Some(scope), PrincipalParts::Path(&parts[3..]))
            }
        } else {
            let route = route(self.scheme, host, port, user)?;
            if parts == ["identity"] {
                (route, None, PrincipalParts::Path(&parts))
            } else {
                if parts.len() < 2 {
                    return Err(ParseError::InvalidPathSegment);
                }
                let scope = parse_scope(&parts[0], self.scheme)?;
                (route, Some(scope), PrincipalParts::Path(&parts[1..]))
            }
        };

        let resource = match resource_parts {
            PrincipalParts::Freestanding(principal) => Resource::PrincipalIdentity(principal),
            PrincipalParts::Path(parts) => parse_resource(parts)?,
        };
        let (evidence, evaluation) =
            parse_query(self.raw_query, self.scheme, scope.is_some(), &resource)?;
        Ok(ResolutionRequest {
            route,
            scope,
            resource,
            evidence,
            evaluation,
        })
    }
}

enum PrincipalParts<'a> {
    Freestanding(PrincipalId),
    Path(&'a [String]),
}

fn route(
    scheme: Scheme,
    host: String,
    port: Option<u16>,
    user: Option<String>,
) -> Result<Route, ParseError> {
    Ok(match scheme {
        Scheme::Kan => {
            if user.is_some() {
                return Err(ParseError::UserinfoForbidden);
            }
            if host == "local" {
                Route::Kan(KanAuthority::Local { port })
            } else {
                Route::Kan(KanAuthority::Host { host, port })
            }
        }
        Scheme::KanGit => {
            let transport = if user.is_some() {
                GitTransport::Ssh
            } else if host == "local" {
                GitTransport::Local
            } else {
                GitTransport::Https
            };
            let host = if host == "local" {
                GitHost::Local
            } else {
                GitHost::Dns(host)
            };
            Route::Git(GitAuthority {
                host,
                port,
                transport_user: user,
                transport,
            })
        }
        Scheme::KanAt => {
            if user.is_some() || port.is_some() || !valid_at_handle(&host) {
                return Err(ParseError::MalformedUri);
            }
            Route::At(AtAuthority::Handle(host))
        }
    })
}

fn parse_authority(
    raw: &str,
    scheme: Scheme,
) -> Result<(String, Option<u16>, Option<String>), ParseError> {
    let (raw_user, host_port) = match raw.rsplit_once('@') {
        Some((user, host)) => {
            if !matches!(scheme, Scheme::KanGit) {
                return Err(ParseError::UserinfoForbidden);
            }
            if user.is_empty() || user.contains('@') {
                return Err(ParseError::MalformedUri);
            }
            let user = decode_query_component(user)?;
            if user.contains(':') {
                return Err(ParseError::CredentialInUserinfo);
            }
            (Some(user), host)
        }
        None => (None, raw),
    };
    if host_port.contains('@') {
        return Err(ParseError::MalformedUri);
    }
    let (host, port) = if host_port.starts_with('[') {
        let end = host_port.find(']').ok_or(ParseError::MalformedUri)?;
        let host = &host_port[..=end];
        let remainder = &host_port[end + 1..];
        let port = if remainder.is_empty() {
            None
        } else {
            Some(parse_port(
                remainder
                    .strip_prefix(':')
                    .ok_or(ParseError::MalformedUri)?,
            )?)
        };
        (host.to_ascii_lowercase(), port)
    } else if let Some((host, raw_port)) = host_port.rsplit_once(':') {
        if host.contains(':') {
            return Err(ParseError::MalformedUri);
        }
        (host.to_ascii_lowercase(), Some(parse_port(raw_port)?))
    } else {
        (host_port.to_ascii_lowercase(), None)
    };
    if host.is_empty() || host.contains('%') || host.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(ParseError::MalformedUri);
    }
    Ok((host, port, raw_user))
}

fn parse_port(value: &str) -> Result<u16, ParseError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ParseError::MalformedUri);
    }
    value.parse().map_err(|_| ParseError::MalformedUri)
}

fn valid_at_handle(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn parse_scope(value: &str, scheme: Scheme) -> Result<ScopeSelector, ParseError> {
    if let Some(id) = value.strip_prefix("@id:") {
        return ScopeId::from_str(id)
            .map(ScopeSelector::Direct)
            .map_err(|_| ParseError::NonCanonicalIdentifier);
    }
    if value.starts_with('@') {
        return Err(ParseError::UnsupportedSelector);
    }
    let dot_allowed = matches!(scheme, Scheme::KanGit);
    if value.split(':').any(|label| {
        label.is_empty()
            || !label.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'~')
                    || (dot_allowed && byte == b'.')
            })
    }) {
        return Err(ParseError::NonCanonicalIdentifier);
    }
    Ok(ScopeSelector::Named(ScopeLocator(value.to_string())))
}

fn parse_resource(parts: &[String]) -> Result<Resource, ParseError> {
    match parts {
        [identity] if identity == "identity" => Ok(Resource::AuthorityIdentity),
        [claim, cid] if claim == "claim" => parse_cid(cid).map(Resource::Claim),
        [subject, tail @ ..] if subject == "subject" && !tail.is_empty() => {
            parse_subject(tail).map(Resource::Subject)
        }
        [identity, scope] if identity == "identity" && scope == "scope" => {
            Ok(Resource::ScopeIdentity)
        }
        [identity, authority] if identity == "identity" && authority == "authority" => {
            Ok(Resource::AuthorityIdentity)
        }
        [identity, principal, did, method, method_specific_id]
            if identity == "identity" && principal == "principal" && did == "did" =>
        {
            PrincipalId::from_path(method.clone(), method_specific_id.clone())
                .map(Resource::PrincipalIdentity)
        }
        _ => Err(ParseError::InvalidPathSegment),
    }
}

fn parse_subject(parts: &[String]) -> Result<SubjectSelector, ParseError> {
    if let Some(cid) = parts[0].strip_prefix("@cid:") {
        if parts.len() != 1 {
            return Err(ParseError::InvalidSelector);
        }
        return parse_cid(cid).map(SubjectSelector::PreservedV1Cid);
    }
    if parts[0].starts_with('@') {
        return Err(ParseError::UnsupportedSelector);
    }
    if parts.iter().skip(1).any(|part| part.starts_with('@')) {
        return Err(ParseError::InvalidSelector);
    }
    Ok(SubjectSelector::Path(SubjectPath(parts.to_vec())))
}

fn parse_cid(value: &str) -> Result<Cid, ParseError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(ParseError::NonCanonicalIdentifier);
    }
    let cid = Cid::from_str(value).map_err(|_| ParseError::NonCanonicalIdentifier)?;
    if cid.to_string() != value {
        return Err(ParseError::NonCanonicalIdentifier);
    }
    Ok(cid)
}

fn parse_query(
    raw: Option<&str>,
    scheme: Scheme,
    scoped: bool,
    resource: &Resource,
) -> Result<(EvidenceSelection, EvaluationInputs), ParseError> {
    let Some(raw) = raw else {
        return Ok(Default::default());
    };
    if raw.is_empty() {
        return Err(ParseError::MalformedUri);
    }
    let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for pair in raw.split('&') {
        let (raw_name, raw_value) = pair.split_once('=').ok_or(ParseError::MalformedUri)?;
        let name = decode_query_component(raw_name)?;
        let value = decode_query_component(raw_value)?;
        if value.is_empty() {
            return Err(ParseError::MalformedUri);
        }
        if !matches!(
            name.as_str(),
            "source" | "service" | "commit" | "ref" | "snapshot" | "version" | "trust" | "at"
        ) {
            return Err(ParseError::UnsupportedParameter);
        }
        let existing = values.entry(name.clone()).or_default();
        if (!existing.is_empty() && name != "source") || existing.contains(&value) {
            return Err(ParseError::DuplicateParameter);
        }
        existing.push(value);
    }

    let snapshot_selectors = ["commit", "ref", "snapshot"]
        .into_iter()
        .filter(|name| values.contains_key(*name))
        .count();
    if snapshot_selectors > 1 {
        return Err(ParseError::ConflictingSnapshotSelectors);
    }
    if values.contains_key("ref") && !matches!(scheme, Scheme::KanGit)
        || values.contains_key("snapshot") && !matches!(scheme, Scheme::Kan)
        || values.contains_key("commit") && matches!(scheme, Scheme::Kan)
        || values.contains_key("version") && !matches!(resource, Resource::PrincipalIdentity(_))
        || (values.contains_key("trust") || values.contains_key("at"))
            && (!scoped || matches!(resource, Resource::AuthorityIdentity))
    {
        return Err(ParseError::InapplicableParameter);
    }
    if matches!(scheme, Scheme::KanAt)
        && values.get("source").is_some_and(|sources| {
            sources
                .iter()
                .any(|source| !matches!(source.as_str(), "appview" | "pds"))
        })
    {
        return Err(ParseError::InapplicableParameter);
    }
    if values.contains_key("service")
        && !(matches!(scheme, Scheme::KanAt)
            && values
                .get("source")
                .is_some_and(|sources| sources.iter().any(|source| source == "appview")))
    {
        return Err(ParseError::InapplicableParameter);
    }

    let one = |name: &str| values.get(name).and_then(|values| values.first()).cloned();
    let commit = one("commit");
    if matches!(scheme, Scheme::KanGit) {
        if let Some(commit) = &commit {
            if !matches!(commit.len(), 40 | 64)
                || !commit
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(ParseError::NonCanonicalIdentifier);
            }
        }
        if let Some(git_ref) = one("ref") {
            if !git_ref.starts_with("refs/") {
                return Err(ParseError::NonCanonicalIdentifier);
            }
        }
    }
    if matches!(scheme, Scheme::KanAt) {
        if let Some(commit) = &commit {
            parse_cid(commit)?;
        }
    }
    if let Some(service) = one("service") {
        validate_service_selector(&service)?;
    }
    let at = one("at")
        .map(|value| {
            if value != "0"
                && (value.starts_with('0') || !value.bytes().all(|byte| byte.is_ascii_digit()))
            {
                return Err(ParseError::NonCanonicalIdentifier);
            }
            value
                .parse::<u64>()
                .map_err(|_| ParseError::NonCanonicalIdentifier)
        })
        .transpose()?;
    let version = one("version")
        .map(|value| parse_version(&value))
        .transpose()?;
    let mut sources = values.get("source").cloned().unwrap_or_default();
    sources.sort();
    Ok((
        EvidenceSelection {
            sources,
            service: one("service"),
            commit,
            git_ref: one("ref"),
            snapshot: one("snapshot"),
            version,
        },
        EvaluationInputs {
            trust: one("trust")
                .map(|value| TrustSelection::parse(&value))
                .transpose()?,
            at,
        },
    ))
}

fn parse_version(value: &str) -> Result<IdentityVersion, ParseError> {
    if value == "static" {
        return Ok(IdentityVersion::Static);
    }
    if let Some(cid) = value.strip_prefix("event:") {
        return parse_cid(cid).map(IdentityVersion::Event);
    }
    if let Some(id) = value.strip_prefix("versionId:") {
        if id.is_empty() {
            return Err(ParseError::NonCanonicalIdentifier);
        }
        return Ok(IdentityVersion::VersionId(id.to_string()));
    }
    if let Some(cid) = value.strip_prefix("documentCid:") {
        return parse_cid(cid).map(IdentityVersion::DocumentCid);
    }
    Err(ParseError::NonCanonicalIdentifier)
}

fn validate_service_selector(value: &str) -> Result<(), ParseError> {
    let Some((did, fragment)) = value.split_once('#') else {
        return Err(ParseError::NonCanonicalIdentifier);
    };
    let Some(rest) = did.strip_prefix("did:") else {
        return Err(ParseError::NonCanonicalIdentifier);
    };
    let Some((method, identifier)) = rest.split_once(':') else {
        return Err(ParseError::NonCanonicalIdentifier);
    };
    if method.is_empty()
        || !method.bytes().all(|byte| byte.is_ascii_lowercase())
        || identifier.is_empty()
        || fragment.is_empty()
        || fragment.contains('#')
    {
        return Err(ParseError::NonCanonicalIdentifier);
    }
    Ok(())
}

fn version_text(version: &IdentityVersion) -> String {
    match version {
        IdentityVersion::Static => "static".to_string(),
        IdentityVersion::Event(cid) => format!("event:{cid}"),
        IdentityVersion::VersionId(id) => format!("versionId:{id}"),
        IdentityVersion::DocumentCid(cid) => format!("documentCid:{cid}"),
    }
}

fn decode_segment(raw: &str) -> Result<String, ParseError> {
    let decoded = percent_decode(raw)?;
    if decoded.is_empty() || matches!(decoded.as_str(), "." | "..") || decoded.contains('\0') {
        return Err(ParseError::InvalidPathSegment);
    }
    if decoded.contains('/') {
        return Err(ParseError::EncodedSeparator);
    }
    Ok(decoded)
}

fn decode_query_component(raw: &str) -> Result<String, ParseError> {
    let decoded = percent_decode(raw)?;
    if decoded.contains('\0') {
        return Err(ParseError::MalformedUri);
    }
    Ok(decoded)
}

fn percent_decode(raw: &str) -> Result<String, ParseError> {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(ParseError::InvalidPercentEncoding);
            }
            let high = hex(bytes[index + 1]).ok_or(ParseError::InvalidPercentEncoding)?;
            let low = hex(bytes[index + 2]).ok_or(ParseError::InvalidPercentEncoding)?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| ParseError::InvalidUtf8)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode_segment(value: &str) -> String {
    percent_encode(value, |byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
            )
    })
}

fn encode_transport_user(value: &str) -> String {
    percent_encode(value, |byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
            )
    })
}

fn encode_query(value: &str) -> String {
    percent_encode(value, |byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
                    | b'/'
                    | b'?'
            )
    })
}

fn percent_encode(value: &str, safe: impl Fn(u8) -> bool) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if safe(byte) {
            output.push(byte as char);
        } else {
            output.push('%');
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    output
}

fn append_host(output: &mut String, host: &str, port: Option<u16>) {
    output.push_str(host);
    if let Some(port) = port {
        output.push(':');
        output.push_str(&port.to_string());
    }
}

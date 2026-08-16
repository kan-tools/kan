//! Invertible `tools.kan.claim` projection for RFC 2 migration.

use std::str::FromStr;

use atproto_dasl::Cid;
use serde::{Deserialize, Serialize};

use crate::{
    cid::content_cid,
    claim::{
        Anchor, ArtifactRef, AuthorId, Claim, ClaimBody, ClaimContent, Layer, RelationKind,
        StatusValue, SubjectKind, SubjectRef,
    },
    sign,
};

pub const CODEC: &str = "kan-claim-v1";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_RECORD_BYTES: usize = 1_000_000;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("unsupported claim codec: {0}")]
    UnsupportedClaimCodec(String),
    #[error("claim content is not invertible: {0}")]
    NonInvertible(String),
    #[error("claim is outside the tools.kan.claim Lexicon: {0}")]
    LexiconConstraint(String),
    #[error("claim CID is invalid")]
    InvalidCid,
    #[error("claim CID does not match reconstructed content")]
    CidMismatch,
    #[error("claim signature does not verify")]
    BadSignature,
    #[error("CID computation failed: {0}")]
    Cid(String),
}

/// Typed envelope corresponding to the normative `tools.kan.claim` record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Record {
    pub claim_cid: String,
    pub codec: String,
    pub content: Content,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    pub rev: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Content {
    pub author: Author,
    pub workspace: AnchorValue,
    pub subject: SubjectValue,
    pub body: Body,
    pub cites: Vec<CidLink>,
    pub artifacts: Vec<ArtifactValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidLink {
    pub link: String,
}
impl Serialize for CidLink {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            use serde::ser::SerializeMap;
            let mut map = serializer.serialize_map(Some(1))?;
            map.serialize_entry("$link", &self.link)?;
            map.end()
        } else {
            Cid::from_str(&self.link)
                .map_err(serde::ser::Error::custom)?
                .serialize(serializer)
        }
    }
}
impl<'de> Deserialize<'de> for CidLink {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            #[derive(Deserialize)]
            struct JsonLink {
                #[serde(rename = "$link")]
                link: String,
            }
            JsonLink::deserialize(deserializer).map(|value| Self { link: value.link })
        } else {
            Cid::deserialize(deserializer).map(Into::into)
        }
    }
}
impl From<Cid> for CidLink {
    fn from(value: Cid) -> Self {
        Self {
            link: value.to_string(),
        }
    }
}
impl TryFrom<CidLink> for Cid {
    type Error = Error;
    fn try_from(value: CidLink) -> Result<Self, Error> {
        Cid::from_str(&value.link).map_err(|_| Error::NonInvertible("invalid CID link".into()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Author {
    pub did: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "option_bytes"
    )]
    pub agent: Option<Vec<u8>>,
}

mod option_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => serde_bytes::serialize(v, s),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<serde_bytes::ByteBuf>::deserialize(d).map(|v| v.map(|b| b.into_vec()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpanValue {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "$type", rename_all_fields = "camelCase")]
pub enum AnchorValue {
    #[serde(rename = "tools.kan.defs#workspaceAnchor")]
    Workspace { genesis_cid: String },
    #[serde(rename = "tools.kan.defs#commitAnchor")]
    Commit { sha: String },
    #[serde(rename = "tools.kan.defs#blobAnchor")]
    Blob { cid: CidLink },
    #[serde(rename = "tools.kan.defs#fileAtAnchor")]
    FileAt { path: String, sha: String },
    #[serde(rename = "tools.kan.defs#lineRangeAtAnchor")]
    LineRangeAt {
        path: String,
        sha: String,
        span: SpanValue,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "$type", rename_all_fields = "camelCase")]
pub enum SubjectValue {
    #[serde(rename = "tools.kan.defs#localSubject")]
    Local { rkey: String },
    #[serde(rename = "tools.kan.defs#anchorSubject")]
    Anchor { anchor: AnchorValue },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "$type", rename_all_fields = "camelCase")]
pub enum ArtifactValue {
    #[serde(rename = "tools.kan.defs#commitArtifact")]
    Commit { sha: String },
    #[serde(rename = "tools.kan.defs#fileAtArtifact")]
    FileAt { path: String, sha: String },
    #[serde(rename = "tools.kan.defs#lineRangeAtArtifact")]
    LineRangeAt {
        path: String,
        sha: String,
        span: SpanValue,
    },
    #[serde(rename = "tools.kan.defs#toolOutputArtifact")]
    ToolOutput { cid: CidLink },
}

fn path_text(path: std::path::PathBuf) -> Result<String, Error> {
    path.into_os_string()
        .into_string()
        .map_err(|_| Error::NonInvertible("non-UTF-8 path".into()))
}
impl TryFrom<Anchor> for AnchorValue {
    type Error = Error;
    fn try_from(v: Anchor) -> Result<Self, Error> {
        Ok(match v {
            Anchor::Workspace(genesis_cid) => Self::Workspace { genesis_cid },
            Anchor::Commit(sha) => Self::Commit { sha },
            Anchor::Blob(cid) => Self::Blob { cid: cid.into() },
            Anchor::FileAt(path, sha) => Self::FileAt {
                path: path_text(path)?,
                sha,
            },
            Anchor::LineRangeAt(path, sha, span) => Self::LineRangeAt {
                path: path_text(path)?,
                sha,
                span: SpanValue {
                    start: span.start,
                    end: span.end,
                },
            },
        })
    }
}
impl TryFrom<AnchorValue> for Anchor {
    type Error = Error;
    fn try_from(v: AnchorValue) -> Result<Self, Error> {
        Ok(match v {
            AnchorValue::Workspace { genesis_cid } => Self::Workspace(genesis_cid),
            AnchorValue::Commit { sha } => Self::Commit(sha),
            AnchorValue::Blob { cid } => Self::Blob(cid.try_into()?),
            AnchorValue::FileAt { path, sha } => Self::FileAt(path.into(), sha),
            AnchorValue::LineRangeAt { path, sha, span } => Self::LineRangeAt(
                path.into(),
                sha,
                crate::claim::Span {
                    start: span.start,
                    end: span.end,
                },
            ),
        })
    }
}
impl TryFrom<SubjectRef> for SubjectValue {
    type Error = Error;
    fn try_from(v: SubjectRef) -> Result<Self, Error> {
        Ok(match v {
            SubjectRef::Local(rkey) => Self::Local { rkey },
            SubjectRef::Anchor(anchor) => Self::Anchor {
                anchor: anchor.try_into()?,
            },
        })
    }
}
impl TryFrom<SubjectValue> for SubjectRef {
    type Error = Error;
    fn try_from(v: SubjectValue) -> Result<Self, Error> {
        Ok(match v {
            SubjectValue::Local { rkey } => Self::Local(rkey),
            SubjectValue::Anchor { anchor } => Self::Anchor(anchor.try_into()?),
        })
    }
}
impl TryFrom<ArtifactRef> for ArtifactValue {
    type Error = Error;
    fn try_from(v: ArtifactRef) -> Result<Self, Error> {
        Ok(match v {
            ArtifactRef::Commit(sha) => Self::Commit { sha },
            ArtifactRef::FileAt(path, sha) => Self::FileAt {
                path: path_text(path)?,
                sha,
            },
            ArtifactRef::LineRangeAt(path, sha, span) => Self::LineRangeAt {
                path: path_text(path)?,
                sha,
                span: SpanValue {
                    start: span.start,
                    end: span.end,
                },
            },
            ArtifactRef::ToolOutput(cid) => Self::ToolOutput { cid: cid.into() },
        })
    }
}
impl TryFrom<ArtifactValue> for ArtifactRef {
    type Error = Error;
    fn try_from(v: ArtifactValue) -> Result<Self, Error> {
        Ok(match v {
            ArtifactValue::Commit { sha } => Self::Commit(sha),
            ArtifactValue::FileAt { path, sha } => Self::FileAt(path.into(), sha),
            ArtifactValue::LineRangeAt { path, sha, span } => Self::LineRangeAt(
                path.into(),
                sha,
                crate::claim::Span {
                    start: span.start,
                    end: span.end,
                },
            ),
            ArtifactValue::ToolOutput { cid } => Self::ToolOutput(cid.try_into()?),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "$type", rename_all_fields = "camelCase")]
pub enum Body {
    #[serde(rename = "tools.kan.defs#subjectBody")]
    Subject {
        title: String,
        subject_kind: SubjectKindValue,
    },
    #[serde(rename = "tools.kan.defs#observationBody")]
    Observation { text: String },
    #[serde(rename = "tools.kan.defs#planBody")]
    Plan { text: String },
    #[serde(rename = "tools.kan.defs#decisionBody")]
    Decision { text: String },
    #[serde(rename = "tools.kan.defs#blockerBody")]
    Blocker { text: String },
    #[serde(rename = "tools.kan.defs#resolutionBody")]
    Resolution { text: String },
    #[serde(rename = "tools.kan.defs#resultBody")]
    Result { text: String },
    #[serde(rename = "tools.kan.defs#statusBody")]
    Status { value: StatusValueWire },
    #[serde(rename = "tools.kan.defs#relationBody")]
    Relation {
        kind: RelationKindValue,
        target: SubjectValue,
    },
    #[serde(rename = "tools.kan.defs#retractionBody")]
    Retraction { supersedes: CidLink },
    #[serde(rename = "tools.kan.defs#rejectsBody")]
    Rejects { claim: CidLink },
    #[serde(rename = "tools.kan.defs#publicationBody")]
    Publication { layer: LayerValue },
    #[serde(rename = "tools.kan.defs#roleDeclarationBody")]
    RoleDeclaration { did: String, name: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubjectKindValue {
    Issue,
    Idea,
    Question,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StatusValueWire {
    Open,
    InProgress,
    Blocked,
    Resolved,
    Closed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelationKindValue {
    SameAs,
    Blocks,
    About,
    ManifestsAt,
    DependsOn,
    Accepts,
    InTensionWith,
    Supersedes,
    Refutes,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LayerValue {
    GitTree,
}

impl From<SubjectKind> for SubjectKindValue {
    fn from(v: SubjectKind) -> Self {
        match v {
            SubjectKind::Issue => Self::Issue,
            SubjectKind::Idea => Self::Idea,
            SubjectKind::Question => Self::Question,
        }
    }
}
impl From<SubjectKindValue> for SubjectKind {
    fn from(v: SubjectKindValue) -> Self {
        match v {
            SubjectKindValue::Issue => Self::Issue,
            SubjectKindValue::Idea => Self::Idea,
            SubjectKindValue::Question => Self::Question,
        }
    }
}
impl From<StatusValue> for StatusValueWire {
    fn from(v: StatusValue) -> Self {
        match v {
            StatusValue::Open => Self::Open,
            StatusValue::InProgress => Self::InProgress,
            StatusValue::Blocked => Self::Blocked,
            StatusValue::Resolved => Self::Resolved,
            StatusValue::Closed => Self::Closed,
        }
    }
}
impl From<StatusValueWire> for StatusValue {
    fn from(v: StatusValueWire) -> Self {
        match v {
            StatusValueWire::Open => Self::Open,
            StatusValueWire::InProgress => Self::InProgress,
            StatusValueWire::Blocked => Self::Blocked,
            StatusValueWire::Resolved => Self::Resolved,
            StatusValueWire::Closed => Self::Closed,
        }
    }
}
impl From<RelationKind> for RelationKindValue {
    fn from(v: RelationKind) -> Self {
        match v {
            RelationKind::SameAs => Self::SameAs,
            RelationKind::Blocks => Self::Blocks,
            RelationKind::About => Self::About,
            RelationKind::ManifestsAt => Self::ManifestsAt,
            RelationKind::DependsOn => Self::DependsOn,
            RelationKind::Accepts => Self::Accepts,
            RelationKind::InTensionWith => Self::InTensionWith,
            RelationKind::Supersedes => Self::Supersedes,
            RelationKind::Refutes => Self::Refutes,
        }
    }
}
impl From<RelationKindValue> for RelationKind {
    fn from(v: RelationKindValue) -> Self {
        match v {
            RelationKindValue::SameAs => Self::SameAs,
            RelationKindValue::Blocks => Self::Blocks,
            RelationKindValue::About => Self::About,
            RelationKindValue::ManifestsAt => Self::ManifestsAt,
            RelationKindValue::DependsOn => Self::DependsOn,
            RelationKindValue::Accepts => Self::Accepts,
            RelationKindValue::InTensionWith => Self::InTensionWith,
            RelationKindValue::Supersedes => Self::Supersedes,
            RelationKindValue::Refutes => Self::Refutes,
        }
    }
}
impl From<Layer> for LayerValue {
    fn from(_: Layer) -> Self {
        Self::GitTree
    }
}
impl From<LayerValue> for Layer {
    fn from(_: LayerValue) -> Self {
        Self::GitTree
    }
}

impl TryFrom<ClaimBody> for Body {
    type Error = Error;
    fn try_from(value: ClaimBody) -> Result<Self, Error> {
        Ok(match value {
            ClaimBody::Subject {
                title,
                subject_kind,
            } => Self::Subject {
                title,
                subject_kind: subject_kind.into(),
            },
            ClaimBody::Observation { text } => Self::Observation { text },
            ClaimBody::Plan { text } => Self::Plan { text },
            ClaimBody::Decision { text } => Self::Decision { text },
            ClaimBody::Blocker { text } => Self::Blocker { text },
            ClaimBody::Resolution { text } => Self::Resolution { text },
            ClaimBody::Result { text } => Self::Result { text },
            ClaimBody::Status { value } => Self::Status {
                value: value.into(),
            },
            ClaimBody::Relation { kind, target } => Self::Relation {
                kind: kind.into(),
                target: target.try_into()?,
            },
            ClaimBody::Retraction { supersedes } => Self::Retraction {
                supersedes: supersedes.into(),
            },
            ClaimBody::Rejects { claim } => Self::Rejects {
                claim: claim.into(),
            },
            ClaimBody::Publication { layer } => Self::Publication {
                layer: layer.into(),
            },
            ClaimBody::RoleDeclaration { did, name } => Self::RoleDeclaration { did, name },
            ClaimBody::Unknown { kind, .. } => return Err(Error::UnsupportedClaimCodec(kind)),
        })
    }
}

impl TryFrom<Body> for ClaimBody {
    type Error = Error;
    fn try_from(value: Body) -> Result<Self, Error> {
        Ok(match value {
            Body::Subject {
                title,
                subject_kind,
            } => Self::Subject {
                title,
                subject_kind: subject_kind.into(),
            },
            Body::Observation { text } => Self::Observation { text },
            Body::Plan { text } => Self::Plan { text },
            Body::Decision { text } => Self::Decision { text },
            Body::Blocker { text } => Self::Blocker { text },
            Body::Resolution { text } => Self::Resolution { text },
            Body::Result { text } => Self::Result { text },
            Body::Status { value } => Self::Status {
                value: value.into(),
            },
            Body::Relation { kind, target } => Self::Relation {
                kind: kind.into(),
                target: target.try_into()?,
            },
            Body::Retraction { supersedes } => Self::Retraction {
                supersedes: supersedes.try_into()?,
            },
            Body::Rejects { claim } => Self::Rejects {
                claim: claim.try_into()?,
            },
            Body::Publication { layer } => Self::Publication {
                layer: layer.into(),
            },
            Body::RoleDeclaration { did, name } => Self::RoleDeclaration { did, name },
        })
    }
}

impl Content {
    pub fn from_claim(value: ClaimContent) -> Result<Self, Error> {
        Ok(Self {
            author: Author {
                did: value.author.did,
                agent: value.author.agent,
            },
            workspace: value.workspace.try_into()?,
            subject: value.subject.try_into()?,
            body: value.body.try_into()?,
            cites: value.cites.into_iter().map(Into::into).collect(),
            artifacts: value
                .artifacts
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            recorded_at: value.recorded_at,
        })
    }
    pub fn into_claim(self) -> Result<ClaimContent, Error> {
        Ok(ClaimContent {
            author: AuthorId {
                did: self.author.did,
                agent: self.author.agent,
            },
            workspace: self.workspace.try_into()?,
            subject: self.subject.try_into()?,
            body: self.body.try_into()?,
            cites: self
                .cites
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            artifacts: self
                .artifacts
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            recorded_at: self.recorded_at,
        })
    }

    fn validate_lexicon(&self) -> Result<(), Error> {
        validate_did("content.author.did", &self.author.did)?;
        validate_bytes("content.author.agent", self.author.agent.as_deref(), 128)?;
        validate_anchor("content.workspace", &self.workspace)?;
        validate_subject("content.subject", &self.subject)?;
        validate_body("content.body", &self.body)?;
        validate_len("content.cites", self.cites.len(), 10_000)?;
        for (index, cite) in self.cites.iter().enumerate() {
            validate_cid_link(&format!("content.cites[{index}]"), cite)?;
        }
        validate_len("content.artifacts", self.artifacts.len(), 10_000)?;
        for (index, artifact) in self.artifacts.iter().enumerate() {
            validate_artifact(&format!("content.artifacts[{index}]"), artifact)?;
        }
        if self
            .recorded_at
            .is_some_and(|value| value > MAX_SAFE_INTEGER)
        {
            return constraint("content.recordedAt exceeds the interoperable integer range");
        }
        Ok(())
    }
}

impl Record {
    pub fn from_claim(claim: Claim, rev: String) -> Result<Self, Error> {
        if rev.is_empty() {
            return Err(Error::NonInvertible("empty rev".into()));
        }
        let claim_cid = content_cid(&claim.content).map_err(|e| Error::Cid(e.to_string()))?;
        let record = Self {
            claim_cid: claim_cid.to_string(),
            codec: CODEC.into(),
            content: Content::from_claim(claim.content)?,
            signature: claim.sig,
            rev,
        };
        record.validate_lexicon()?;
        Ok(record)
    }

    /// Invert the projection, require the original CID, and verify its signature.
    pub fn verify(self) -> Result<Claim, Error> {
        self.validate_lexicon()?;
        if self.codec != CODEC {
            return Err(Error::UnsupportedClaimCodec(self.codec));
        }
        if self.rev.is_empty() {
            return Err(Error::NonInvertible("empty rev".into()));
        }
        let stated = Cid::from_str(&self.claim_cid).map_err(|_| Error::InvalidCid)?;
        let content = self.content.into_claim()?;
        let actual = content_cid(&content).map_err(|e| Error::Cid(e.to_string()))?;
        if actual != stated {
            return Err(Error::CidMismatch);
        }
        if !sign::verify(&content.author.did, &stated.to_bytes(), &self.signature) {
            return Err(Error::BadSignature);
        }
        Ok(Claim {
            content,
            sig: self.signature,
        })
    }

    fn validate_lexicon(&self) -> Result<(), Error> {
        if self.codec != CODEC {
            return Err(Error::UnsupportedClaimCodec(self.codec.clone()));
        }
        Cid::from_str(&self.claim_cid).map_err(|_| Error::InvalidCid)?;
        validate_tid(&self.rev)?;
        validate_bytes("signature", Some(&self.signature), 256)?;
        self.content.validate_lexicon()?;
        let encoded = atproto_dasl::to_vec(self)
            .map_err(|error| Error::NonInvertible(format!("record encoding failed: {error}")))?;
        if encoded.len() > MAX_RECORD_BYTES {
            return constraint(format!(
                "encoded record is {} bytes; maximum is {MAX_RECORD_BYTES}",
                encoded.len()
            ));
        }
        Ok(())
    }
}

fn constraint<T>(message: impl Into<String>) -> Result<T, Error> {
    Err(Error::LexiconConstraint(message.into()))
}

fn validate_utf8(path: &str, value: &str, maximum: usize) -> Result<(), Error> {
    if value.len() > maximum {
        return constraint(format!(
            "{path} is {} UTF-8 bytes; maximum is {maximum}",
            value.len()
        ));
    }
    Ok(())
}

fn validate_len(path: &str, actual: usize, maximum: usize) -> Result<(), Error> {
    if actual > maximum {
        return constraint(format!("{path} has {actual} items; maximum is {maximum}"));
    }
    Ok(())
}

fn validate_bytes(path: &str, value: Option<&[u8]>, maximum: usize) -> Result<(), Error> {
    if let Some(value) = value {
        validate_len(path, value.len(), maximum)?;
    }
    Ok(())
}

fn validate_did(path: &str, value: &str) -> Result<(), Error> {
    if value.len() > 2048 {
        return constraint(format!("{path} is not a DID"));
    }
    let Some(rest) = value.strip_prefix("did:") else {
        return constraint(format!("{path} is not a DID"));
    };
    let Some((method, identifier)) = rest.split_once(':') else {
        return constraint(format!("{path} is not a DID"));
    };
    if method.is_empty()
        || identifier.is_empty()
        || !method.bytes().all(|byte| byte.is_ascii_lowercase())
        || !identifier.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'%')
        })
        || !identifier
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return constraint(format!("{path} is not a DID"));
    }
    Ok(())
}

fn validate_tid(value: &str) -> Result<(), Error> {
    if value.len() != 13
        || !value
            .as_bytes()
            .first()
            .is_some_and(|byte| matches!(byte, b'2'..=b'7' | b'a'..=b'j'))
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'2'..=b'7' | b'a'..=b'z'))
    {
        return constraint("rev is not an ATProto TID");
    }
    Ok(())
}

fn validate_cid_link(path: &str, value: &CidLink) -> Result<(), Error> {
    Cid::from_str(&value.link)
        .map(|_| ())
        .map_err(|_| Error::LexiconConstraint(format!("{path} is not a CID link")))
}

fn validate_anchor(path: &str, value: &AnchorValue) -> Result<(), Error> {
    match value {
        AnchorValue::Workspace { genesis_cid } => {
            validate_utf8(&format!("{path}.genesisCid"), genesis_cid, 512)
        }
        AnchorValue::Commit { sha } => validate_utf8(&format!("{path}.sha"), sha, 128),
        AnchorValue::Blob { cid } => validate_cid_link(&format!("{path}.cid"), cid),
        AnchorValue::FileAt { path: file, sha }
        | AnchorValue::LineRangeAt {
            path: file, sha, ..
        } => {
            validate_utf8(&format!("{path}.path"), file, 4096)?;
            validate_utf8(&format!("{path}.sha"), sha, 128)
        }
    }
}

fn validate_subject(path: &str, value: &SubjectValue) -> Result<(), Error> {
    match value {
        SubjectValue::Local { rkey } => validate_utf8(&format!("{path}.rkey"), rkey, 4096),
        SubjectValue::Anchor { anchor } => validate_anchor(&format!("{path}.anchor"), anchor),
    }
}

fn validate_artifact(path: &str, value: &ArtifactValue) -> Result<(), Error> {
    match value {
        ArtifactValue::Commit { sha } => validate_utf8(&format!("{path}.sha"), sha, 128),
        ArtifactValue::FileAt { path: file, sha }
        | ArtifactValue::LineRangeAt {
            path: file, sha, ..
        } => {
            validate_utf8(&format!("{path}.path"), file, 4096)?;
            validate_utf8(&format!("{path}.sha"), sha, 128)
        }
        ArtifactValue::ToolOutput { cid } => validate_cid_link(&format!("{path}.cid"), cid),
    }
}

fn validate_body(path: &str, value: &Body) -> Result<(), Error> {
    match value {
        Body::Subject { title, .. } => validate_utf8(&format!("{path}.title"), title, 8192),
        Body::Observation { text }
        | Body::Plan { text }
        | Body::Decision { text }
        | Body::Blocker { text }
        | Body::Resolution { text }
        | Body::Result { text } => validate_utf8(&format!("{path}.text"), text, 900_000),
        Body::Relation { target, .. } => validate_subject(&format!("{path}.target"), target),
        Body::RoleDeclaration { did, name } => {
            validate_did(&format!("{path}.did"), did)?;
            validate_utf8(&format!("{path}.name"), name, 128)
        }
        Body::Retraction { supersedes } => {
            validate_cid_link(&format!("{path}.supersedes"), supersedes)
        }
        Body::Rejects { claim } => validate_cid_link(&format!("{path}.claim"), claim),
        Body::Status { .. } | Body::Publication { .. } => Ok(()),
    }
}

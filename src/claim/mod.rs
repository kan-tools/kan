//! Current claim domain and the byte-exact released v1 compatibility model.

use std::{fmt, num::NonZeroU32};

use atproto_dasl::{Cid, Ipld};
use serde::{de, de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};

use crate::identity::{authorship::Author, scope_inception::ScopeId};

pub mod codec;
pub mod v1;

pub const CODEC: &str = "kan-claim-v2";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

macro_rules! cid_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(Cid);

        impl $name {
            pub fn new(cid: Cid) -> Self {
                Self(cid)
            }

            pub fn cid(&self) -> &Cid {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.0.serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Cid::deserialize(deserializer).map(Self)
            }
        }
    };
}

cid_id!(ClaimId);
cid_id!(DelegationId);
cid_id!(IdentityEventId);
cid_id!(GovernanceEventId);
cid_id!(RevocationId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RecordedAt(u64);

impl RecordedAt {
    pub fn new(micros: u64) -> Result<Self, Error> {
        if micros > MAX_SAFE_INTEGER {
            return Err(Error::RecordedAt(micros));
        }
        Ok(Self(micros))
    }

    pub fn micros(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for RecordedAt {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(u64::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

macro_rules! bounded_text {
    ($name:ident, $max:expr, $label:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: String) -> Result<Self, Error> {
                let length = value.len();
                if length == 0 || length > $max {
                    return Err(Error::BoundedText {
                        field: $label,
                        length,
                        maximum: $max,
                    });
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
            }
        }
    };
}

bounded_text!(Title, 8_192, "title");
bounded_text!(NarrativeText, 900_000, "narrative text");

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct SubjectPath(String);

impl SubjectPath {
    pub fn new(value: String) -> Result<Self, Error> {
        if value.is_empty() || value.len() > 4_096 || value.contains('\0') || value.contains('@') {
            return Err(Error::SubjectPath(value));
        }
        if value
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        {
            return Err(Error::SubjectPath(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SubjectPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RoleName(String);

impl RoleName {
    pub fn new(value: String) -> Result<Self, Error> {
        if value.is_empty()
            || value.len() > 128
            || value.contains('/')
            || value.contains('\\')
            || value.contains('\0')
            || value == "."
            || value == ".."
        {
            return Err(Error::RoleName(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RoleName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Did(String);

impl Did {
    pub fn new(value: String) -> Result<Self, Error> {
        crate::identity::did_kan::validate_did(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Did {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalSet<T>(Vec<T>);

impl<T: Clone + Serialize> CanonicalSet<T> {
    pub fn new(values: Vec<T>) -> Result<Self, Error> {
        let mut keyed = values
            .into_iter()
            .map(|value| Ok((atproto_dasl::to_vec(&value)?, value)))
            .collect::<Result<Vec<_>, atproto_dasl::EncodeError>>()?;
        keyed.sort_by(|left, right| left.0.cmp(&right.0));
        if keyed.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(Error::DuplicateCollectionValue);
        }
        Ok(Self(keyed.into_iter().map(|(_, value)| value).collect()))
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
}

impl<T: Serialize> Serialize for CanonicalSet<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for CanonicalSet<T>
where
    T: Deserialize<'de> + Serialize,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let values = Vec::<T>::deserialize(deserializer)?;
        let keys = values
            .iter()
            .map(atproto_dasl::to_vec)
            .collect::<Result<Vec<_>, _>>()
            .map_err(de::Error::custom)?;
        if keys
            .windows(2)
            .any(|pair| pair[0].as_slice() >= pair[1].as_slice())
        {
            return Err(de::Error::custom("canonical set is not sorted and unique"));
        }
        Ok(Self(values))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniqueSequence<T>(Vec<T>);

impl<T: Serialize> UniqueSequence<T> {
    pub fn new(values: Vec<T>) -> Result<Self, Error> {
        let keys = values
            .iter()
            .map(atproto_dasl::to_vec)
            .collect::<Result<Vec<_>, _>>()?;
        for (index, key) in keys.iter().enumerate() {
            if keys[..index].contains(key) {
                return Err(Error::DuplicateCollectionValue);
            }
        }
        Ok(Self(values))
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
}

impl<T: Serialize> Serialize for UniqueSequence<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for UniqueSequence<T>
where
    T: Deserialize<'de> + Serialize,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let values = Vec::<T>::deserialize(deserializer)?;
        let keys = values
            .iter()
            .map(atproto_dasl::to_vec)
            .collect::<Result<Vec<_>, _>>()
            .map_err(de::Error::custom)?;
        for (index, key) in keys.iter().enumerate() {
            if keys[..index].contains(key) {
                return Err(de::Error::custom("unique sequence contains a duplicate"));
            }
        }
        Ok(Self(values))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopedSubjectRef {
    pub scope: ScopeId,
    pub subject: SubjectPath,
}

/// Explicit decoder for closed `kind` unions. Serde's generic internally
/// tagged enum buffer turns DAG-CBOR tag-42 CIDs into plain bytes before the
/// selected arm sees them; decoding each field independently retains its
/// semantic CID type.
struct TaggedFields {
    kind: String,
    fields: std::collections::BTreeMap<String, Ipld>,
}

impl TaggedFields {
    fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let Ipld::Map(mut fields) = Ipld::deserialize(deserializer)? else {
            return Err(de::Error::custom("tagged union is not a map"));
        };
        let Some(Ipld::String(kind)) = fields.remove("kind") else {
            return Err(de::Error::custom("tagged union has no string kind"));
        };
        Ok(Self { kind, fields })
    }

    fn take<T: DeserializeOwned, E: de::Error>(&mut self, name: &'static str) -> Result<T, E> {
        let value = self
            .fields
            .remove(name)
            .ok_or_else(|| E::custom(format!("tagged union is missing {name}")))?;
        let bytes = atproto_dasl::to_vec(&value).map_err(E::custom)?;
        atproto_dasl::from_reader(&bytes[..]).map_err(E::custom)
    }

    fn finish<E: de::Error>(&self) -> Result<(), E> {
        if self.fields.is_empty() {
            Ok(())
        } else {
            Err(E::custom(format!(
                "tagged union has unknown field {}",
                self.fields.keys().next().expect("map is nonempty")
            )))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum ControlRef {
    IdentityEvent { event: IdentityEventId },
    GovernanceEvent { event: GovernanceEventId },
    Delegation { delegation: DelegationId },
    Revocation { revocation: RevocationId },
}

impl<'de> Deserialize<'de> for ControlRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut fields = TaggedFields::deserialize(deserializer)?;
        let value = match fields.kind.as_str() {
            "identity-event" => Self::IdentityEvent {
                event: fields.take("event")?,
            },
            "governance-event" => Self::GovernanceEvent {
                event: fields.take("event")?,
            },
            "delegation" => Self::Delegation {
                delegation: fields.take("delegation")?,
            },
            "revocation" => Self::Revocation {
                revocation: fields.take("revocation")?,
            },
            _ => return Err(de::Error::custom("unknown control reference kind")),
        };
        fields.finish()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum ResourceRef {
    Scope { scope: ScopeId },
    Subject { subject: ScopedSubjectRef },
    Claim { claim: ClaimId },
    Principal { principal: Did },
    Control { control: ControlRef },
    Artifact { artifact: ArtifactRef },
}

impl<'de> Deserialize<'de> for ResourceRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut fields = TaggedFields::deserialize(deserializer)?;
        let value = match fields.kind.as_str() {
            "scope" => Self::Scope {
                scope: fields.take("scope")?,
            },
            "subject" => Self::Subject {
                subject: fields.take("subject")?,
            },
            "claim" => Self::Claim {
                claim: fields.take("claim")?,
            },
            "principal" => Self::Principal {
                principal: fields.take("principal")?,
            },
            "control" => Self::Control {
                control: fields.take("control")?,
            },
            "artifact" => Self::Artifact {
                artifact: fields.take("artifact")?,
            },
            _ => return Err(de::Error::custom("unknown resource reference kind")),
        };
        fields.finish()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubjectKind {
    Issue,
    Idea,
    Question,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StatusValue {
    Open,
    InProgress,
    Blocked,
    Resolved,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelationKind {
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
pub enum LineageRelationship {
    Created,
    Invoked,
}

macro_rules! digest {
    ($name:ident, $length:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; $length]);

        impl $name {
            pub fn new(bytes: [u8; $length]) -> Self {
                Self(bytes)
            }

            pub fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
                let found = bytes.len();
                let bytes = bytes.into_vec().try_into().map_err(|_| {
                    de::Error::custom(format!("digest has {found} bytes; expected {}", $length))
                })?;
                Ok(Self(bytes))
            }
        }
    };
}

digest!(Sha1Digest, 20);
digest!(Sha256Digest, 32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum GitObjectId {
    Sha1 { digest: Sha1Digest },
    Sha256 { digest: Sha256Digest },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GitPath(Vec<u8>);

impl GitPath {
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.is_empty()
            || bytes.contains(&0)
            || bytes.first() == Some(&b'/')
            || bytes.last() == Some(&b'/')
            || bytes
                .split(|byte| *byte == b'/')
                .any(|segment| segment.is_empty() || segment == b"." || segment == b"..")
        {
            return Err(Error::GitPath);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for GitPath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for GitPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(serde_bytes::ByteBuf::deserialize(deserializer)?.into_vec())
            .map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    deny_unknown_fields,
    try_from = "LineRangeWire"
)]
pub struct LineRange {
    first: NonZeroU32,
    last: NonZeroU32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LineRangeWire {
    first: NonZeroU32,
    last: NonZeroU32,
}

impl TryFrom<LineRangeWire> for LineRange {
    type Error = Error;

    fn try_from(value: LineRangeWire) -> Result<Self, Self::Error> {
        Self::new(value.first, value.last)
    }
}

impl LineRange {
    pub fn new(first: NonZeroU32, last: NonZeroU32) -> Result<Self, Error> {
        if first > last {
            return Err(Error::LineRange);
        }
        Ok(Self { first, last })
    }

    pub fn first(self) -> NonZeroU32 {
        self.first
    }

    pub fn last(self) -> NonZeroU32 {
        self.last
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum ArtifactRef {
    GitCommit {
        commit: GitObjectId,
    },
    Blob {
        cid: Cid,
    },
    FileAt {
        path: GitPath,
        commit: GitObjectId,
    },
    LineRangeAt {
        path: GitPath,
        commit: GitObjectId,
        lines: LineRange,
    },
    ToolOutput {
        cid: Cid,
    },
}

impl<'de> Deserialize<'de> for ArtifactRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut fields = TaggedFields::deserialize(deserializer)?;
        let value = match fields.kind.as_str() {
            "git-commit" => Self::GitCommit {
                commit: fields.take("commit")?,
            },
            "blob" => Self::Blob {
                cid: fields.take("cid")?,
            },
            "file-at" => Self::FileAt {
                path: fields.take("path")?,
                commit: fields.take("commit")?,
            },
            "line-range-at" => Self::LineRangeAt {
                path: fields.take("path")?,
                commit: fields.take("commit")?,
                lines: fields.take("lines")?,
            },
            "tool-output" => Self::ToolOutput {
                cid: fields.take("cid")?,
            },
            _ => return Err(de::Error::custom("unknown artifact reference kind")),
        };
        fields.finish()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    deny_unknown_fields,
    try_from = "PublicationTargetWire"
)]
pub struct PublicationTarget {
    uri: String,
    scope: ScopeId,
    subject: SubjectPath,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationTargetWire {
    uri: String,
    scope: ScopeId,
    subject: SubjectPath,
}

impl TryFrom<PublicationTargetWire> for PublicationTarget {
    type Error = Error;

    fn try_from(value: PublicationTargetWire) -> Result<Self, Self::Error> {
        Self::new(value.uri, value.scope, value.subject)
    }
}

impl PublicationTarget {
    pub fn new(uri: String, scope: ScopeId, subject: SubjectPath) -> Result<Self, Error> {
        if !["kan://", "kan+git://", "kan+at://"]
            .iter()
            .any(|prefix| uri.starts_with(prefix))
            || !uri.contains("/subject/")
            || uri.contains('#')
            || uri.split_once('?').is_some_and(|(_, query)| {
                query.split('&').any(|part| {
                    matches!(
                        part.split_once('=').map(|(name, _)| name),
                        Some("trust" | "at" | "commit" | "ref" | "snapshot")
                    )
                })
            })
        {
            return Err(Error::PublicationTarget(uri));
        }
        Ok(Self {
            uri,
            scope,
            subject,
        })
    }

    fn matches(&self, scope: ScopeId, subject: &SubjectPath) -> bool {
        self.scope == scope && &self.subject == subject
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum ClaimBody {
    Subject {
        title: Title,
        subject_kind: SubjectKind,
    },
    Observation {
        text: NarrativeText,
    },
    Plan {
        text: NarrativeText,
    },
    Decision {
        text: NarrativeText,
    },
    Blocker {
        text: NarrativeText,
    },
    Resolution {
        text: NarrativeText,
    },
    Result {
        text: NarrativeText,
    },
    Status {
        value: StatusValue,
    },
    Relation {
        relation: RelationKind,
        target: ScopedSubjectRef,
    },
    Retraction {
        claim: ClaimId,
    },
    Rejection {
        claim: ClaimId,
    },
    PublicationIntent {
        target: PublicationTarget,
    },
    Lineage {
        child: Did,
        relationship: LineageRelationship,
    },
    RoleNaming {
        principal: Did,
        name: RoleName,
    },
}

impl<'de> Deserialize<'de> for ClaimBody {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut fields = TaggedFields::deserialize(deserializer)?;
        let value = match fields.kind.as_str() {
            "subject" => Self::Subject {
                title: fields.take("title")?,
                subject_kind: fields.take("subjectKind")?,
            },
            "observation" => Self::Observation {
                text: fields.take("text")?,
            },
            "plan" => Self::Plan {
                text: fields.take("text")?,
            },
            "decision" => Self::Decision {
                text: fields.take("text")?,
            },
            "blocker" => Self::Blocker {
                text: fields.take("text")?,
            },
            "resolution" => Self::Resolution {
                text: fields.take("text")?,
            },
            "result" => Self::Result {
                text: fields.take("text")?,
            },
            "status" => Self::Status {
                value: fields.take("value")?,
            },
            "relation" => Self::Relation {
                relation: fields.take("relation")?,
                target: fields.take("target")?,
            },
            "retraction" => Self::Retraction {
                claim: fields.take("claim")?,
            },
            "rejection" => Self::Rejection {
                claim: fields.take("claim")?,
            },
            "publication-intent" => Self::PublicationIntent {
                target: fields.take("target")?,
            },
            "lineage" => Self::Lineage {
                child: fields.take("child")?,
                relationship: fields.take("relationship")?,
            },
            "role-naming" => Self::RoleNaming {
                principal: fields.take("principal")?,
                name: fields.take("name")?,
            },
            _ => return Err(de::Error::custom("unknown current claim body kind")),
        };
        fields.finish()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    deny_unknown_fields,
    try_from = "ClaimContentWire"
)]
pub struct ClaimContent {
    author: Author,
    scope: ScopeId,
    delegation: Option<DelegationId>,
    subject: SubjectPath,
    referents: CanonicalSet<ResourceRef>,
    body: ClaimBody,
    cites: CanonicalSet<ClaimId>,
    artifacts: UniqueSequence<ArtifactRef>,
    recorded_at: RecordedAt,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClaimContentWire {
    author: Author,
    scope: ScopeId,
    delegation: Option<DelegationId>,
    subject: SubjectPath,
    referents: CanonicalSet<ResourceRef>,
    body: ClaimBody,
    cites: CanonicalSet<ClaimId>,
    artifacts: UniqueSequence<ArtifactRef>,
    recorded_at: RecordedAt,
}

impl TryFrom<ClaimContentWire> for ClaimContent {
    type Error = Error;

    fn try_from(value: ClaimContentWire) -> Result<Self, Self::Error> {
        Self::new(
            value.author,
            value.scope,
            value.delegation,
            value.subject,
            value.referents,
            value.body,
            value.cites,
            value.artifacts,
            value.recorded_at,
        )
    }
}

impl ClaimContent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        author: Author,
        scope: ScopeId,
        delegation: Option<DelegationId>,
        subject: SubjectPath,
        referents: CanonicalSet<ResourceRef>,
        body: ClaimBody,
        cites: CanonicalSet<ClaimId>,
        artifacts: UniqueSequence<ArtifactRef>,
        recorded_at: RecordedAt,
    ) -> Result<Self, Error> {
        author.validate()?;
        if let ClaimBody::PublicationIntent { target } = &body {
            if !target.matches(scope, &subject) {
                return Err(Error::PublicationTargetMismatch);
            }
        }
        Ok(Self {
            author,
            scope,
            delegation,
            subject,
            referents,
            body,
            cites,
            artifacts,
            recorded_at,
        })
    }

    pub fn author(&self) -> &Author {
        &self.author
    }

    pub fn scope(&self) -> ScopeId {
        self.scope
    }

    pub fn subject(&self) -> &SubjectPath {
        &self.subject
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(atproto_dasl::to_vec(self)?)
    }

    pub fn id(&self) -> Result<ClaimId, Error> {
        Ok(ClaimId::new(crate::cid::content_cid(self)?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimSignature(Vec<u8>);

impl ClaimSignature {
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > 256 {
            return Err(Error::SignatureLength(bytes.len()));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for ClaimSignature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for ClaimSignature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(serde_bytes::ByteBuf::deserialize(deserializer)?.into_vec())
            .map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaimSigningInput {
    codec: String,
    claim: Cid,
}

impl ClaimSigningInput {
    pub fn new(claim: &ClaimId) -> Self {
        Self {
            codec: CODEC.to_string(),
            claim: claim.cid().clone(),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(atproto_dasl::to_vec(self)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    content: ClaimContent,
    signature: ClaimSignature,
}

impl Claim {
    /// Construct a current claim with the exact static identity named by its
    /// content. A selected key can never silently substitute for the author.
    pub fn sign_static(
        content: ClaimContent,
        identity: &crate::sign::Identity,
    ) -> Result<Self, Error> {
        let principal = identity.did();
        let fingerprint = principal
            .strip_prefix("did:key:")
            .ok_or_else(|| Error::SignerMismatch(principal.clone()))?;
        let expected_method = format!("{principal}#{fingerprint}");
        let author = content.author();
        if author.principal() != principal
            || author.verification_method() != expected_method
            || !matches!(
                author.identity_version(),
                crate::identity::control::IdentityVersion::Static
            )
        {
            return Err(Error::SignerMismatch(principal));
        }
        let id = content.id()?;
        let input = ClaimSigningInput::new(&id).canonical_bytes()?;
        let signature = identity.sign(&input)?;
        Self::from_verified_parts(content, signature)
    }

    pub fn verify_static(content: ClaimContent, signature: Vec<u8>) -> Result<Self, Error> {
        let author = content.author();
        if !matches!(
            author.identity_version(),
            crate::identity::control::IdentityVersion::Static
        ) {
            return Err(Error::UnsupportedIdentityResolver(
                author.principal().to_string(),
            ));
        }
        let id = content.id()?;
        let input = ClaimSigningInput::new(&id).canonical_bytes()?;
        if !crate::sign::verify(author.principal(), &input, &signature) {
            return Err(Error::BadSignature);
        }
        Self::from_verified_parts(content, signature)
    }

    pub fn verify_active_did_kan(
        content: ClaimContent,
        signature: Vec<u8>,
        state: &crate::identity::did_kan_update::ResolvedDidKanState,
    ) -> Result<Self, Error> {
        let id = content.id()?;
        let input = ClaimSigningInput::new(&id).canonical_bytes()?;
        let verification = content
            .author()
            .verify_active_did_kan_message(&input, &signature, state);
        if verification.cryptographic_validity != crate::identity::CryptographicValidity::Valid {
            return Err(Error::BadSignature);
        }
        Self::from_verified_parts(content, signature)
    }

    pub fn content(&self) -> &ClaimContent {
        &self.content
    }

    pub fn signature(&self) -> &ClaimSignature {
        &self.signature
    }

    pub fn id(&self) -> Result<ClaimId, Error> {
        self.content.id()
    }

    pub(crate) fn from_verified_parts(
        content: ClaimContent,
        signature: Vec<u8>,
    ) -> Result<Self, Error> {
        Ok(Self {
            content,
            signature: ClaimSignature::new(signature)?,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("recordedAt {0} is outside the ATProto interoperable integer range")]
    RecordedAt(u64),
    #[error("{field} has {length} UTF-8 bytes; expected 1..={maximum}")]
    BoundedText {
        field: &'static str,
        length: usize,
        maximum: usize,
    },
    #[error("invalid current subject path: {0}")]
    SubjectPath(String),
    #[error("invalid role name: {0}")]
    RoleName(String),
    #[error("canonical collection contains a duplicate")]
    DuplicateCollectionValue,
    #[error("invalid repository-relative Git path")]
    GitPath,
    #[error("line range must be one-based, inclusive, and ordered")]
    LineRange,
    #[error("invalid publication target: {0}")]
    PublicationTarget(String),
    #[error("publication target does not resolve to the containing claim subject")]
    PublicationTargetMismatch,
    #[error("claim signature has {0} bytes; expected 1..=256")]
    SignatureLength(usize),
    #[error("selected signing identity `{0}` does not exactly match the claim author")]
    SignerMismatch(String),
    #[error("claim signature does not verify over its kan-claim-v2 signing input")]
    BadSignature,
    #[error("no identity resolver is available for current claim author `{0}`")]
    UnsupportedIdentityResolver(String),
    #[error(transparent)]
    Signing(#[from] crate::sign::Error),
    #[error(transparent)]
    Identity(#[from] crate::identity::did_kan::Error),
    #[error(transparent)]
    Author(#[from] crate::identity::authorship::Error),
    #[error(transparent)]
    Cid(#[from] crate::cid::Error),
    #[error(transparent)]
    Encode(#[from] atproto_dasl::EncodeError),
}

//! Explicit compiler from released CLI write intents to current claim content.

use std::num::NonZeroU32;

use super::{
    v1, ArtifactRef, CanonicalSet, ClaimBody, ClaimContent, ClaimId, Did, GitObjectId, GitPath,
    LineRange, NarrativeText, RecordedAt, RelationKind, RoleName, ScopedSubjectRef, Sha1Digest,
    Sha256Digest, StatusValue, SubjectKind, SubjectPath, Title, UniqueSequence,
};
use crate::identity::{authorship::Author, scope_inception::ScopeId};

#[allow(clippy::too_many_arguments)]
pub fn compile_write_intent(
    author: Author,
    scope: ScopeId,
    subject: v1::SubjectRef,
    body: v1::ClaimBody,
    cites: Vec<atproto_dasl::Cid>,
    artifacts: Vec<v1::ArtifactRef>,
    recorded_at: u64,
) -> Result<ClaimContent, Error> {
    let subject = local_subject(subject, "claim subject")?;
    let body = compile_body(scope, body)?;
    let cites = CanonicalSet::new(cites.into_iter().map(ClaimId::new).collect())?;
    let artifacts = UniqueSequence::new(
        artifacts
            .into_iter()
            .map(compile_artifact)
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    Ok(ClaimContent::new(
        author,
        scope,
        None,
        subject,
        CanonicalSet::new(vec![])?,
        body,
        cites,
        artifacts,
        RecordedAt::new(recorded_at)?,
    )?)
}

fn compile_body(scope: ScopeId, body: v1::ClaimBody) -> Result<ClaimBody, Error> {
    Ok(match body {
        v1::ClaimBody::Subject {
            title,
            subject_kind,
        } => ClaimBody::Subject {
            title: Title::new(title)?,
            subject_kind: match subject_kind {
                v1::SubjectKind::Issue => SubjectKind::Issue,
                v1::SubjectKind::Idea => SubjectKind::Idea,
                v1::SubjectKind::Question => SubjectKind::Question,
            },
        },
        v1::ClaimBody::Observation { text } => ClaimBody::Observation {
            text: NarrativeText::new(text)?,
        },
        v1::ClaimBody::Plan { text } => ClaimBody::Plan {
            text: NarrativeText::new(text)?,
        },
        v1::ClaimBody::Decision { text } => ClaimBody::Decision {
            text: NarrativeText::new(text)?,
        },
        v1::ClaimBody::Blocker { text } => ClaimBody::Blocker {
            text: NarrativeText::new(text)?,
        },
        v1::ClaimBody::Resolution { text } => ClaimBody::Resolution {
            text: NarrativeText::new(text)?,
        },
        v1::ClaimBody::Result { text } => ClaimBody::Result {
            text: NarrativeText::new(text)?,
        },
        v1::ClaimBody::Status { value } => ClaimBody::Status {
            value: match value {
                v1::StatusValue::Open => StatusValue::Open,
                v1::StatusValue::InProgress => StatusValue::InProgress,
                v1::StatusValue::Blocked => StatusValue::Blocked,
                v1::StatusValue::Resolved => StatusValue::Resolved,
                v1::StatusValue::Closed => StatusValue::Closed,
            },
        },
        v1::ClaimBody::Relation { kind, target } => ClaimBody::Relation {
            relation: match kind {
                v1::RelationKind::SameAs => RelationKind::SameAs,
                v1::RelationKind::Blocks => RelationKind::Blocks,
                v1::RelationKind::About => RelationKind::About,
                v1::RelationKind::ManifestsAt => RelationKind::ManifestsAt,
                v1::RelationKind::DependsOn => RelationKind::DependsOn,
                v1::RelationKind::Accepts => RelationKind::Accepts,
                v1::RelationKind::InTensionWith => RelationKind::InTensionWith,
                v1::RelationKind::Supersedes => RelationKind::Supersedes,
                v1::RelationKind::Refutes => RelationKind::Refutes,
            },
            target: ScopedSubjectRef {
                scope,
                subject: local_subject(target, "relation target")?,
            },
        },
        v1::ClaimBody::Retraction { supersedes } => ClaimBody::Retraction {
            claim: ClaimId::new(supersedes),
        },
        v1::ClaimBody::Rejects { claim } => ClaimBody::Rejection {
            claim: ClaimId::new(claim),
        },
        v1::ClaimBody::RoleDeclaration { did, name } => ClaimBody::RoleNaming {
            principal: Did::new(did)?,
            name: RoleName::new(name)?,
        },
        v1::ClaimBody::Publication { .. } => {
            return Err(Error::Unsupported(UnsupportedIntent::PublicationNeedsUri))
        }
        v1::ClaimBody::Unknown { kind, .. } => {
            return Err(Error::Unsupported(UnsupportedIntent::UnknownBody(kind)))
        }
    })
}

fn local_subject(subject: v1::SubjectRef, position: &'static str) -> Result<SubjectPath, Error> {
    match subject {
        v1::SubjectRef::Local(path) => Ok(SubjectPath::new(path)?),
        v1::SubjectRef::Anchor(_) => Err(Error::Unsupported(UnsupportedIntent::AnchorSubject {
            position,
        })),
    }
}

fn compile_artifact(artifact: v1::ArtifactRef) -> Result<ArtifactRef, Error> {
    Ok(match artifact {
        v1::ArtifactRef::Commit(commit) => ArtifactRef::GitCommit {
            commit: git_object_id(&commit)?,
        },
        v1::ArtifactRef::FileAt(path, commit) => ArtifactRef::FileAt {
            path: git_path(path)?,
            commit: git_object_id(&commit)?,
        },
        v1::ArtifactRef::LineRangeAt(path, commit, lines) => ArtifactRef::LineRangeAt {
            path: git_path(path)?,
            commit: git_object_id(&commit)?,
            lines: LineRange::new(
                NonZeroU32::new(lines.start).ok_or(Error::ZeroLine)?,
                NonZeroU32::new(lines.end).ok_or(Error::ZeroLine)?,
            )?,
        },
        v1::ArtifactRef::ToolOutput(cid) => ArtifactRef::ToolOutput { cid },
    })
}

fn git_path(path: std::path::PathBuf) -> Result<GitPath, Error> {
    let path = path
        .into_os_string()
        .into_string()
        .map_err(|_| Error::GitPath)?;
    Ok(GitPath::new(path.into_bytes())?)
}

fn git_object_id(value: &str) -> Result<GitObjectId, Error> {
    let bytes = decode_hex(value).ok_or_else(|| Error::GitObjectId(value.to_string()))?;
    match bytes.len() {
        20 => Ok(GitObjectId::Sha1 {
            digest: Sha1Digest::new(bytes.try_into().expect("length checked")),
        }),
        32 => Ok(GitObjectId::Sha256 {
            digest: Sha256Digest::new(bytes.try_into().expect("length checked")),
        }),
        _ => Err(Error::GitObjectId(value.to_string())),
    }
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some(((high << 4) | low) as u8)
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnsupportedIntent {
    #[error("anchor subject at {position} has no current path representation")]
    AnchorSubject { position: &'static str },
    #[error(
        "publication requires URI-native subject addressing, which is deferred to the local URI milestone"
    )]
    PublicationNeedsUri,
    #[error("unknown released claim body `{0}` has no current representation")]
    UnknownBody(String),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Claim(#[from] super::Error),
    #[error("released write intent is not representable as a current claim: {0}")]
    Unsupported(UnsupportedIntent),
    #[error("git object id is not a full SHA-1 or SHA-256 hex digest: {0}")]
    GitObjectId(String),
    #[error("git artifact path is not representable as a UTF-8 repository-relative path")]
    GitPath,
    #[error("line ranges are one-based in current claims")]
    ZeroLine,
}

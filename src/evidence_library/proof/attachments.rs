//! Decoded attachment export from currently authorized, reconstructed evidence.
use super::Readers;
use crate::{
    evidence_assembly as assembly,
    evidence_content::ContentError,
    evidence_reader::proof::{Pin, Source, Token},
    evidence_service::{self as service, Failure},
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    Request,
    Response,
}
pub(in crate::evidence_library) struct Export {
    pub bytes: Vec<u8>,
    pub metadata: Value,
}
const MAX: usize = 40 * 1024 * 1024;
fn decode_base64(text: &str) -> Result<Vec<u8>, Failure> {
    fn digit(b: u8) -> Result<u32, Failure> {
        Ok(match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(Failure::Invalid),
        })
    }
    if !text.len().is_multiple_of(4) || text.len() > 32 * 1024 * 1024 {
        return Err(Failure::Invalid);
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for (i, c) in text.as_bytes().as_chunks::<4>().0.iter().enumerate() {
        let padding = if c[2] == b'=' {
            if c[3] != b'=' {
                return Err(Failure::Invalid);
            }
            2
        } else if c[3] == b'=' {
            1
        } else {
            0
        };
        if padding > 0 && (i + 1) * 4 != text.len() {
            return Err(Failure::Invalid);
        }
        let a = digit(c[0])?;
        let b = digit(c[1])?;
        let d = if padding < 2 { digit(c[2])? } else { 0 };
        let e = if padding == 0 { digit(c[3])? } else { 0 };
        if (padding == 2 && b & 15 != 0) || (padding == 1 && d & 3 != 0) {
            return Err(Failure::Invalid);
        }
        let n = (a << 18) | (b << 12) | (d << 6) | e;
        out.push((n >> 16) as u8);
        if padding < 2 {
            out.push((n >> 8) as u8);
        }
        if padding == 0 {
            out.push(n as u8);
        }
    }
    Ok(out)
}
impl Readers {
    pub(in crate::evidence_library) async fn attachment(
        &self,
        source: &str,
        pin: &Pin,
        selections: &[Token],
        direction: Direction,
        pointer: &str,
    ) -> Result<Export, ContentError> {
        if selections.is_empty()
            || selections.len() > 1024
            || pointer.len() > 1024
            || !pointer.starts_with('/')
        {
            return Err(Failure::Invalid.into());
        }
        let permit = self
            .workers
            .clone()
            .try_acquire_many_owned(2)
            .map_err(|_| ContentError::Busy)?;
        let reader = self.selected(source)?;
        let scope = reader.binding().owner_binding()?.scope;
        let work = async {
            let mut rows = Vec::new();
            let mut total = 0;
            let mut offset = 0;
            let mut seen = std::collections::BTreeSet::new();
            while offset < selections.len() {
                let end = (offset + crate::evidence_proof_service::READ_BATCH_LIMIT)
                    .min(selections.len());
                let sources = reader.sources_prefix(pin, &selections[offset..end]).await?;
                if sources.is_empty() {
                    return Err(Failure::Missing.into());
                }
                offset += sources.len();
                for source in sources {
                    let Source::Available {
                        record,
                        writer,
                        plaintext,
                        ..
                    } = source
                    else {
                        return Err(Failure::Missing.into());
                    };
                    if !seen.insert(record.sequence.clone()) {
                        return Err(Failure::Invalid.into());
                    }
                    total += plaintext.len();
                    if total > MAX {
                        return Err(ContentError::Limited);
                    }
                    rows.push((record, writer, plaintext));
                }
            }
            let pointer = pointer.to_owned();
            let exported=tokio::task::spawn_blocking(move || -> Result<Export,ContentError> {
                let _permit=permit;
                let inputs:Vec<_>=rows.iter().map(|(_,writer,bytes)|assembly::Input{scope,writer,payload:assembly::Payload::Available(bytes)}).collect();
                let cancelled=Arc::new(AtomicBool::new(false));
                let assembled=assembly::assemble(&inputs,assembly::Limits{occurrences:1024,input_bytes:MAX as u64,scan_bytes:512*1024*1024,assembled_bytes:MAX as u64,duration:Duration::from_secs(60),cancelled:cancelled.clone()}).map_err(|_|ContentError::Limited)?;
                if assembled.groups.len()!=1 {return Err(Failure::Invalid.into());}
                let group=&assembled.groups[0];
                let stream=match direction {Direction::Request=>&group.request,Direction::Response=>&group.response};
                let bytes=stream.contiguous.as_deref().ok_or(Failure::Missing)?;
                if !stream.issues.is_empty()||stream.expected_bytes.is_some_and(|n|n!=bytes.len() as u64) {return Err(Failure::Missing.into());}
                // Strict duplicate-key rejection: the exported interpretation
                // must not choose a different field from the source renderer.
                let crate::evidence_reconstruction::Unique(value)=serde_json::from_slice(bytes).map_err(|_|Failure::Invalid)?;
                let block=value.pointer(&pointer).ok_or(Failure::Invalid)?;
                if !matches!(block["type"].as_str(),Some("image"|"document"))||block["source"]["type"]!="base64" {return Err(Failure::Invalid.into());}
                let media=block["source"]["media_type"].as_str().ok_or(Failure::Invalid)?;
                if media.is_empty()||media.len()>128||!media.bytes().all(|b|b.is_ascii_graphic()) {return Err(Failure::Invalid.into());}
                let output=decode_base64(block["source"]["data"].as_str().ok_or(Failure::Invalid)?)?;
                let cites=crate::evidence_interpretation::map_region(stream,&inputs,0..bytes.len(),crate::evidence_interpretation::Limits{
                    input_bytes:MAX,items:4096,output_bytes:MAX as u64,scan_bytes:512*1024*1024,citations:32768,duration:Duration::from_secs(60),cancelled
                }).map_err(|_|ContentError::Limited)?;
                let metadata=json!({"version":"kan-attachment/1","decoded_sha256":service::hex(&Sha256::digest(&output)),"decoded_bytes":output.len().to_string(),"media_type":media,"pointer":pointer,
                    "interpretation":"base64 decoded attachment; citations enclose the original JSON body", "source_bytes":bytes.len().to_string(),
                    "cites":cites.into_iter().map(|c|json!({"record":rows[c.input].0,"offset":c.bytes.start.to_string(),"end":c.bytes.end.to_string()})).collect::<Vec<_>>()});
                Ok(Export{bytes:output,metadata})
            }).await.map_err(|_|ContentError::Limited)??;
            reader.page(pin, None, 1).await?;
            Ok(exported)
        };
        tokio::time::timeout(Duration::from_secs(120), work)
            .await
            .map_err(|_| ContentError::Limited)?
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn base64_is_canonical_and_binary_exact() {
        for (encoded, plain) in [
            ("", &b""[..]),
            ("Zg==", &b"f"[..]),
            ("Zm8=", &b"fo"[..]),
            ("Zm9v", &b"foo"[..]),
            ("AP/+/Q==", &[0, 255, 254, 253][..]),
        ] {
            assert_eq!(decode_base64(encoded).unwrap(), plain);
        }
        for text in ["Zg=", "Zg===", "Zh==", "Zm9=", "Zg==Zg==", "Zm 8", "____"] {
            assert!(decode_base64(text).is_err(), "{text}");
        }
    }
}

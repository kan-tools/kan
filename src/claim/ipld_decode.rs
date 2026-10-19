//! Decode the common claim envelope without guessing tags from byte contents.
//! The upstream generic Ipld visitor treats CID-shaped untagged bytes as links.
//! Keep upstream strict scalar decoding, but determine links from tag42 only.
use atproto_dasl::{
    drisl::cbor::{CborDecoder, CborItem},
    DecodeConfig, DecodeError, Ipld,
};
use std::collections::BTreeMap;

pub(super) fn value(bytes: &[u8]) -> Result<Ipld, DecodeError> {
    let config = DecodeConfig {
        max_alloc: bytes.len(),
        ..DecodeConfig::default()
    };
    let max_depth = config.max_depth;
    let mut decoder = CborDecoder::with_config(bytes, config);
    let value = item(&mut decoder, 0, max_depth)?;
    if decoder.has_more_data()? {
        return Err(DecodeError::TrailingData);
    }
    Ok(value)
}

fn item(
    decoder: &mut CborDecoder<&[u8]>,
    depth: usize,
    maximum: usize,
) -> Result<Ipld, DecodeError> {
    if depth > maximum {
        return Err(DecodeError::MaxDepthExceeded {
            depth,
            max: maximum,
        });
    }
    Ok(match decoder.decode_item()? {
        CborItem::Unsigned(n) => Ipld::Integer(i128::from(n)),
        CborItem::Negative(n) => Ipld::Integer(n),
        CborItem::Bytes(bytes) => Ipld::Bytes(bytes),
        CborItem::Text(text) => Ipld::String(text),
        CborItem::False => Ipld::Bool(false),
        CborItem::True => Ipld::Bool(true),
        CborItem::Null => Ipld::Null,
        CborItem::Float(n) => Ipld::Float(n),
        CborItem::Array(n) => {
            if depth == maximum {
                return Err(DecodeError::MaxDepthExceeded {
                    depth: depth + 1,
                    max: maximum,
                });
            }
            let mut values = Vec::new();
            for _ in 0..n {
                values.push(item(decoder, depth + 1, maximum)?);
            }
            Ipld::List(values)
        }
        CborItem::Map(n) => {
            if depth == maximum {
                return Err(DecodeError::MaxDepthExceeded {
                    depth: depth + 1,
                    max: maximum,
                });
            }
            let mut values = BTreeMap::new();
            let mut previous: Option<String> = None;
            for _ in 0..n {
                let CborItem::Text(key) = decoder.decode_item()? else {
                    return Err(DecodeError::Deserialization("map key must be text".into()));
                };
                if previous
                    .as_ref()
                    .is_some_and(|p| (p.len(), p.as_bytes()) >= (key.len(), key.as_bytes()))
                {
                    return Err(DecodeError::MapKeysNotSorted);
                }
                previous = Some(key.clone());
                values.insert(key, item(decoder, depth + 1, maximum)?);
            }
            Ipld::Map(values)
        }
        CborItem::Tag(42) => {
            let CborItem::Bytes(bytes) = decoder.decode_item()? else {
                return Err(DecodeError::Deserialization(
                    "CID tag requires bytes".into(),
                ));
            };
            let cid = atproto_dasl::Cid::from_dag_cbor_bytes(&bytes)?;
            if cid.to_dag_cbor_bytes() != bytes {
                return Err(DecodeError::InvalidCid {
                    reason: "noncanonical or trailing CID bytes".into(),
                });
            }
            Ipld::Link(cid)
        }
        CborItem::Tag(tag) => {
            return Err(DecodeError::Deserialization(format!(
                "unsupported CBOR tag {tag}"
            )))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bytes_and_links_remain_distinct_at_every_depth() {
        let cid =
            atproto_dasl::Cid::from(atproto_dasl::compute_raw_cid(b"synthetic opaque payload"));
        let original = Ipld::Map(BTreeMap::from([
            ("bytes".into(), Ipld::Bytes(cid.to_dag_cbor_bytes())),
            ("link".into(), Ipld::Link(cid.clone())),
            (
                "list".into(),
                Ipld::List(vec![Ipld::Bytes(cid.to_dag_cbor_bytes()), Ipld::Link(cid)]),
            ),
        ]));
        let bytes = atproto_dasl::to_vec(&original).unwrap();
        assert_eq!(value(&bytes).unwrap(), original);
    }
    #[test]
    fn canonical_scalars_and_invalid_encodings_preserve_strictness() {
        for raw in [
            Ipld::Integer(-1),
            Ipld::Integer(i128::from(u64::MAX)),
            Ipld::Float(1.25),
            Ipld::Null,
            Ipld::Bool(true),
            Ipld::String("snow ☃".into()),
        ] {
            let bytes = atproto_dasl::to_vec(&raw).unwrap();
            assert_eq!(value(&bytes).unwrap(), raw);
        }
        for bytes in [
            vec![0x18, 0x01],
            vec![0x01, 0x02],
            vec![0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02],
            vec![0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02],
            vec![0xd8, 42, 0x61, b'x'],
            vec![0x9f, 0xff],
            vec![0xf9, 0x3c, 0x00],
            vec![0x5a, 0xff, 0xff, 0xff, 0xff],
        ] {
            assert!(value(&bytes).is_err(), "{bytes:?}");
        }
    }
    #[test]
    fn nesting_and_tagged_cid_boundaries_are_enforced() {
        let maximum = DecodeConfig::default().max_depth;
        let mut nested = vec![0x81; maximum];
        nested.push(0xf6);
        assert!(value(&nested).is_ok());
        nested.insert(0, 0x81);
        assert!(matches!(
            value(&nested),
            Err(DecodeError::MaxDepthExceeded { .. })
        ));

        let cid = atproto_dasl::Cid::from(atproto_dasl::compute_raw_cid(b"synthetic link"));
        let mut trailing = cid.to_dag_cbor_bytes();
        trailing.push(0);
        let mut tagged = vec![0xd8, 42];
        tagged.extend(atproto_dasl::to_vec(&Ipld::Bytes(trailing)).unwrap());
        assert!(value(&tagged).is_err());

        // Declared container counts cannot cause eager count-sized allocation.
        for prefix in [0x9b, 0xbb] {
            let mut huge_count = vec![prefix];
            huge_count.extend(u64::MAX.to_be_bytes());
            assert!(value(&huge_count).is_err());
        }
    }
}

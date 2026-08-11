//! Key handling and height calculation for MST.
//!
//! Height is determined by counting leading zero bits in SHA-256(key),
//! divided by 2 (giving fanout of 4).

use sha2::{Digest, Sha256};

/// Calculate the height/layer for a key.
///
/// Height is determined by counting leading zero bits in SHA-256(key),
/// divided by 2 (giving fanout of 4).
///
/// # Height Distribution
///
/// - Height 0: ~75% of keys (most common)
/// - Height 1: ~18.75% of keys
/// - Height 2: ~4.69% of keys
/// - Height 3+: increasingly rare
///
/// # Example
///
/// ```rust
/// use atproto_repo::mst::key_height;
///
/// // Most keys will have height 0
/// let height = key_height("app.bsky.feed.post/abc123");
/// println!("Key height: {}", height);
/// ```
#[must_use]
pub fn key_height(key: &str) -> u32 {
    let hash = Sha256::digest(key.as_bytes());
    let leading_zeros = count_leading_zero_bits(&hash);
    leading_zeros / 2
}

/// Count leading zero bits in a byte array.
fn count_leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0;
    for byte in bytes {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Validate a key for use in MST.
///
/// Keys must:
/// - Not be empty
/// - Be valid UTF-8 (enforced by Rust's String type)
/// - Follow collection/rkey format (loosely enforced)
///
/// # Errors
///
/// Returns error message if the key is invalid.
pub fn validate_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("key cannot be empty".to_string());
    }

    // Check for path separator
    if !key.contains('/') {
        return Err("key must contain '/' separator".to_string());
    }

    // Basic format validation (collection/rkey)
    let parts: Vec<&str> = key.splitn(2, '/').collect();
    if parts.len() != 2 {
        return Err("key must have collection/rkey format".to_string());
    }

    let collection = parts[0];
    let rkey = parts[1];

    if collection.is_empty() {
        return Err("collection cannot be empty".to_string());
    }

    if rkey.is_empty() {
        return Err("rkey cannot be empty".to_string());
    }

    Ok(())
}

/// Find the common prefix length between two keys.
#[must_use]
pub fn common_prefix_len(a: &str, b: &str) -> usize {
    a.bytes().zip(b.bytes()).take_while(|(a, b)| a == b).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_height_distribution() {
        // Test that most keys have low height
        let mut heights = [0u32; 10];
        let test_keys: Vec<String> = (0..1000)
            .map(|i| format!("app.bsky.feed.post/{}", i))
            .collect();

        for key in &test_keys {
            let h = key_height(key) as usize;
            if h < 10 {
                heights[h] += 1;
            }
        }

        // Height 0 should be most common (roughly 75%)
        assert!(
            heights[0] > 600,
            "Expected >600 at height 0, got {}",
            heights[0]
        );

        // Heights should generally decrease
        assert!(heights[1] < heights[0]);
    }

    #[test]
    fn test_key_height_deterministic() {
        let key = "app.bsky.feed.post/abc123";
        let h1 = key_height(key);
        let h2 = key_height(key);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_leading_zero_bits() {
        assert_eq!(count_leading_zero_bits(&[0x00, 0x00, 0xFF]), 16);
        assert_eq!(count_leading_zero_bits(&[0x00, 0x80, 0x00]), 8);
        assert_eq!(count_leading_zero_bits(&[0x80, 0x00, 0x00]), 0);
        assert_eq!(count_leading_zero_bits(&[0x40, 0x00, 0x00]), 1);
        assert_eq!(count_leading_zero_bits(&[0x01, 0x00, 0x00]), 7);
    }

    #[test]
    fn test_validate_key_valid() {
        assert!(validate_key("app.bsky.feed.post/abc123").is_ok());
        assert!(validate_key("app.bsky.graph.follow/did:plc:xyz").is_ok());
        assert!(validate_key("com.example/test").is_ok());
    }

    #[test]
    fn test_validate_key_invalid() {
        // Empty
        assert!(validate_key("").is_err());

        // No separator
        assert!(validate_key("noseparator").is_err());

        // Empty collection
        assert!(validate_key("/rkey").is_err());

        // Empty rkey
        assert!(validate_key("collection/").is_err());
    }

    #[test]
    fn test_common_prefix_len() {
        assert_eq!(
            common_prefix_len("app.bsky.feed.post/abc", "app.bsky.feed.post/def"),
            19
        );
        assert_eq!(common_prefix_len("abc", "abc"), 3);
        assert_eq!(common_prefix_len("abc", "xyz"), 0);
        assert_eq!(common_prefix_len("", "abc"), 0);
    }
}

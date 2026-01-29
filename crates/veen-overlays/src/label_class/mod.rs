use serde::{Deserialize, Serialize};

use veen_core::{h, label::Label};

/// Returns the schema identifier for `veen.label.class.v1`.
#[must_use]
pub fn schema_label_class() -> [u8; 32] {
    h(b"veen.label.class.v1")
}

/// Label classification record as defined in LCLASS0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelClassRecord {
    pub label: Label,
    pub class: String,
    pub sensitivity: Option<String>,
    pub retention_hint: Option<u64>,
}

impl LabelClassRecord {
    /// Returns whether the record carries a retention hint.
    #[must_use]
    pub fn has_retention_hint(&self) -> bool {
        self.retention_hint.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veen_core::label::{Label, StreamId};

    #[test]
    fn schema_matches_expected_digest() {
        assert_eq!(
            schema_label_class(),
            [
                0xa5, 0x32, 0x9b, 0x5c, 0x86, 0xc5, 0xaa, 0x57, 0x41, 0x94, 0x43, 0xbe, 0x2b, 0xd8,
                0x81, 0xd1, 0xa7, 0x4d, 0x1f, 0xe4, 0xe5, 0xb4, 0x41, 0xe2, 0xbf, 0xe4, 0x00, 0x72,
                0xc0, 0xb3, 0xd7, 0x35,
            ]
        );
    }

    #[test]
    fn retention_hint_detection() {
        let label = Label::derive([], StreamId::new([0x11; 32]), 0);
        let with_hint = LabelClassRecord {
            label,
            class: "user".into(),
            sensitivity: None,
            retention_hint: Some(86_400),
        };
        assert!(with_hint.has_retention_hint());

        let without = LabelClassRecord {
            label,
            class: "metric".into(),
            sensitivity: Some("low".into()),
            retention_hint: None,
        };
        assert!(!without.has_retention_hint());
    }
}

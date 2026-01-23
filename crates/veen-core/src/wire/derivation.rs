use crate::hash::ht;

pub(crate) const TAG_SIG: &str = "veen/sig";
pub(crate) const TAG_NONCE: &str = "veen/nonce";
pub(crate) const TAG_LEAF: &str = "veen/leaf";
pub(crate) const TAG_ATT_NONCE: &str = "veen/att-nonce";
pub(crate) const TAG_MMR_NODE: &str = "veen/mmr-node";
pub(crate) const TAG_MMR_ROOT: &str = "veen/mmr-root";
pub(crate) const TAG_ATT_NODE: &str = "veen/att-node";
pub(crate) const TAG_ATT_ROOT: &str = "veen/att-root";

#[must_use]
pub(crate) fn hash_tagged(tag: &str, data: &[u8]) -> [u8; 32] {
    ht(tag, data)
}

use std::fmt;

use serde::de::{Error as DeError, SeqAccess, Visitor};

pub(crate) struct SeqLenExpectation(pub(crate) &'static str);

impl<'de> Visitor<'de> for SeqLenExpectation {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

pub(crate) fn seq_next_required<'de, A, T>(
    seq: &mut A,
    idx: usize,
    expecting: &'static str,
) -> Result<T, A::Error>
where
    A: SeqAccess<'de>,
    T: serde::Deserialize<'de>,
{
    seq.next_element()?
        .ok_or_else(|| DeError::invalid_length(idx, &SeqLenExpectation(expecting)))
}

pub(crate) fn seq_no_trailing<'de, A>(
    seq: &mut A,
    idx: usize,
    expecting: &'static str,
) -> Result<(), A::Error>
where
    A: SeqAccess<'de>,
{
    if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
        return Err(DeError::invalid_length(idx, &SeqLenExpectation(expecting)));
    }
    Ok(())
}

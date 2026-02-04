use super::*;

#[derive(Subcommand)]
pub(crate) enum SelftestCommand {
    /// Run the VEEN core self-test suite.
    Core,
    /// Run property-based tests.
    Props,
    /// Run fuzz tests against VEEN wire objects.
    Fuzz,
    /// Run the full test suite (core + props + fuzz).
    All,
    /// Exercise federated overlay scenarios (FED1/AUTH1).
    Federated,
    /// Exercise lifecycle and revocation checks (KEX1+).
    Kex1,
    /// Exercise hardening/PoW checks (SH1+).
    Hardened,
    /// Exercise label/schema overlays (META0+).
    Meta,
    /// Exercise recorder overlay scenarios.
    Recorder,
    /// Run every v0.0.1+ suite sequentially with aggregated reporting.
    Plus,
    /// Run the v0.0.1++ orchestration suite.
    #[command(name = "plus-plus")]
    PlusPlus,
}

#[derive(Debug)]
pub(crate) struct SelftestFailure {
    inner: anyhow::Error,
}

impl SelftestFailure {
    pub(crate) fn new(inner: anyhow::Error) -> Self {
        Self { inner }
    }
}

impl fmt::Display for SelftestFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "self-test failure: {}", self.inner)
    }
}

impl std::error::Error for SelftestFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.inner.as_ref())
    }
}

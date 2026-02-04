use super::{
    handle_selftest_all, handle_selftest_core, handle_selftest_federated, handle_selftest_fuzz,
    handle_selftest_hardened, handle_selftest_kex1, handle_selftest_meta, handle_selftest_plus,
    handle_selftest_plus_plus, handle_selftest_props, handle_selftest_recorder, selftest::SelftestCommand,
    Result,
};

pub(crate) async fn handle_selftest_command(cmd: SelftestCommand) -> Result<()> {
    match cmd {
        SelftestCommand::Core => handle_selftest_core().await,
        SelftestCommand::Props => handle_selftest_props().await,
        SelftestCommand::Fuzz => handle_selftest_fuzz().await,
        SelftestCommand::All => handle_selftest_all().await,
        SelftestCommand::Federated => handle_selftest_federated().await,
        SelftestCommand::Kex1 => handle_selftest_kex1().await,
        SelftestCommand::Hardened => handle_selftest_hardened().await,
        SelftestCommand::Meta => handle_selftest_meta().await,
        SelftestCommand::Recorder => handle_selftest_recorder().await,
        SelftestCommand::Plus => handle_selftest_plus().await,
        SelftestCommand::PlusPlus => handle_selftest_plus_plus().await,
    }
}

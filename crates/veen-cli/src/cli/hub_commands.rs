use super::{
    handle_hub_admission, handle_hub_admission_log, handle_hub_checkpoint_latest,
    handle_hub_checkpoint_range, handle_hub_health, handle_hub_kex_policy, handle_hub_key,
    handle_hub_metrics, handle_hub_profile, handle_hub_role, handle_hub_start, handle_hub_status,
    handle_hub_stop, handle_hub_tls_info, handle_hub_verify_rotation, HubCommand, Result,
};

pub(crate) async fn handle_hub_command(cmd: HubCommand) -> Result<()> {
    match cmd {
        HubCommand::Start(args) => handle_hub_start(args).await,
        HubCommand::Stop(args) => handle_hub_stop(args).await,
        HubCommand::Status(args) => handle_hub_status(args).await,
        HubCommand::Key(args) => handle_hub_key(args).await,
        HubCommand::VerifyRotation(args) => handle_hub_verify_rotation(args).await,
        HubCommand::Health(args) => handle_hub_health(args).await,
        HubCommand::Metrics(args) => handle_hub_metrics(args).await,
        HubCommand::Profile(args) => handle_hub_profile(args).await,
        HubCommand::Role(args) => handle_hub_role(args).await,
        HubCommand::KexPolicy(args) => handle_hub_kex_policy(args).await,
        HubCommand::TlsInfo(args) => handle_hub_tls_info(args).await,
        HubCommand::Admission(args) => handle_hub_admission(args).await,
        HubCommand::AdmissionLog(args) => handle_hub_admission_log(args).await,
        HubCommand::CheckpointLatest(args) => handle_hub_checkpoint_latest(args).await.map(|_| ()),
        HubCommand::CheckpointRange(args) => handle_hub_checkpoint_range(args).await.map(|_| ()),
    }
}

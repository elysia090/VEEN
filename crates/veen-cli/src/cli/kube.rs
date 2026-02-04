use super::*;

pub(crate) use crate::kube::KubeCommand;

pub(crate) async fn handle_kube_command_wrapper(cmd: KubeCommand) -> Result<()> {
    crate::kube::handle_kube_command(cmd).await
}

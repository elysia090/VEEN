use super::{KubeCommand, Result};
use crate::kube::handle_kube_command;

pub(crate) async fn handle_kube_command_wrapper(cmd: KubeCommand) -> Result<()> {
    handle_kube_command(cmd).await
}

use anyhow::Result;

/// Scenario acceptance covering disposable mesh deployments on Kubernetes.
///
/// Expectations:
/// - Launch the hub pod on a local Kubernetes distribution (kind/k3d).
/// - Provision a persistent volume claim for the hub data directory.
/// - Execute the "veen selftest core" equivalent workload against the hub.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Scenario acceptance requires a disposable Kubernetes mesh"]
async fn goals_k8s_disposable_mesh() -> Result<()> {
    todo!(
        "Implement kind/k3d based disposable mesh acceptance that provisions a PVC and runs the VEEN core self-test"
    );
}

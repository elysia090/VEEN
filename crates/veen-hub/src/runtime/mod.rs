use std::net::SocketAddr;
use std::path::Path;

use anyhow::Result;

mod config;
mod observability;

pub use config::{
    AdmissionConfig, AnchorConfig, DedupConfig, FederationConfig, HubConfigOverrides, HubRole,
    HubRuntimeConfig, ObservabilityConfig,
};
pub use observability::{HubObservability, ObservabilitySnapshot};

use crate::pipeline::HubPipeline;
use crate::server::HubServerHandle;
use crate::storage::HubStorage;

pub struct HubRuntime {
    config: HubRuntimeConfig,
    storage: HubStorage,
    pipeline: HubPipeline,
    server: HubServerHandle,
}

impl HubRuntime {
    pub async fn start(config: HubRuntimeConfig) -> Result<Self> {
        let storage = HubStorage::bootstrap(&config).await?;
        let pipeline = HubPipeline::initialise(&config, &storage).await?;
        let server =
            HubServerHandle::spawn(config.listen, pipeline.clone(), config.tooling_enabled).await?;
        Ok(Self {
            config,
            storage,
            pipeline,
            server,
        })
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen
    }

    pub fn data_dir(&self) -> &Path {
        self.storage.data_dir()
    }

    pub fn observability(&self) -> HubObservability {
        self.pipeline.observability()
    }

    pub async fn shutdown(self) -> Result<()> {
        self.server.shutdown().await?;
        self.storage.flush().await?;
        self.storage.teardown().await?;
        Ok(())
    }

    pub fn pipeline(&self) -> &HubPipeline {
        &self.pipeline
    }
}

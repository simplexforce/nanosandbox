//! ProxiedNetwork manager
//!
//! Manages the lifecycle of the HTTP proxy and network configuration.

use crate::error::{Result, SandboxError};
use crate::network::HttpProxy;
use std::net::TcpListener;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Manages proxied network access for a sandbox
pub struct ProxiedNetwork {
    proxy_port: u16,
    proxy_url: String,
    shutdown_tx: watch::Sender<bool>,
    _proxy_handle: JoinHandle<()>,
    _runtime: Arc<Runtime>,
}

impl ProxiedNetwork {
    /// Setup proxied network for a sandbox
    ///
    /// # Arguments
    ///
    /// * `allowed_domains` - List of domains to allow access to
    ///
    /// # Returns
    ///
    /// A `ProxiedNetwork` instance that manages the proxy lifecycle
    pub fn setup(allowed_domains: Vec<String>) -> Result<Self> {
        // Find a free port
        let proxy_port = Self::find_free_port()?;

        // Create tokio runtime for the proxy
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .map_err(|e| SandboxError::Internal(format!("Failed to create runtime: {}", e)))?,
        );

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Create and start the proxy
        let proxy = HttpProxy::new(allowed_domains, proxy_port);
        let proxy_handle = runtime.spawn(async move {
            if let Err(e) = proxy.run(shutdown_rx).await {
                tracing::error!("Proxy error: {}", e);
            }
        });

        // Give proxy a moment to start
        std::thread::sleep(std::time::Duration::from_millis(50));

        let proxy_url = format!("http://127.0.0.1:{}", proxy_port);

        Ok(Self {
            proxy_port,
            proxy_url,
            shutdown_tx,
            _proxy_handle: proxy_handle,
            _runtime: runtime,
        })
    }

    /// Get the proxy port
    pub fn port(&self) -> u16 {
        self.proxy_port
    }

    /// Get the proxy URL
    pub fn url(&self) -> &str {
        &self.proxy_url
    }

    /// Get environment variables for the proxy
    ///
    /// Returns a list of (key, value) pairs to set in the sandbox environment
    pub fn env_vars(&self) -> Vec<(String, String)> {
        vec![
            ("HTTP_PROXY".into(), self.proxy_url.clone()),
            ("HTTPS_PROXY".into(), self.proxy_url.clone()),
            ("http_proxy".into(), self.proxy_url.clone()),
            ("https_proxy".into(), self.proxy_url.clone()),
        ]
    }

    /// Find a free port to listen on
    fn find_free_port() -> Result<u16> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| SandboxError::Internal(format!("Failed to bind: {}", e)))?;
        let port = listener
            .local_addr()
            .map_err(|e| SandboxError::Internal(format!("Failed to get addr: {}", e)))?
            .port();
        Ok(port)
    }

    /// Shutdown the proxy
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

impl Drop for ProxiedNetwork {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_free_port() {
        let port = ProxiedNetwork::find_free_port().unwrap();
        assert!(port > 0);
    }

    #[test]
    fn test_env_vars() {
        let network = ProxiedNetwork::setup(vec!["example.com".into()]).unwrap();
        let vars = network.env_vars();

        assert_eq!(vars.len(), 4);
        assert!(vars.iter().any(|(k, _)| k == "HTTP_PROXY"));
        assert!(vars.iter().any(|(k, _)| k == "HTTPS_PROXY"));
        assert!(vars.iter().any(|(k, _)| k == "http_proxy"));
        assert!(vars.iter().any(|(k, _)| k == "https_proxy"));

        // Cleanup
        network.shutdown();
    }
}

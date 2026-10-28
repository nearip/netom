use std::{net::SocketAddr, sync::Arc};

use arc_swap::ArcSwapOption;
use axum::routing::get;
use log::{debug, error};
use tokio::{sync::mpsc, task::JoinHandle};
#[cfg(feature = "http-api-gzip")]
use tower_http::compression::CompressionLayer;

use crate::{
    daemon_info::DaemonInfo,
    ingress::{self, http_ng::IngressApi},
    units::rib_unit::rib::Rib,
    webui::WebUI,
};

#[derive(Default)]
pub struct Api {
    /// Interfaces to listen on
    interfaces: Vec<SocketAddr>,

    /// The /api/v1 or similar for this API
    api_root: String,

    /// The Rib (wrapping rotonda-store)
    pub store: Arc<ArcSwapOption<Rib>>,

    /// The `ingress::Register`
    ingress_register: Arc<ingress::Register>,

    /// The metrics collection
    metrics: crate::metrics::Collection,

    /// Version, uptime and the running config snapshot
    daemon_info: Arc<DaemonInfo>,

    /// The axum Router, populated with endpoints
    router: axum::Router<ApiState>,

    /// Sending side of channels to signal serving tasks to shutdown
    signal_txs: Vec<mpsc::Sender<()>>,

    /// Handles of serving tasks to be awaited upon shutdown/restart
    serve_handles: Vec<JoinHandle<()>>,
}

#[derive(Clone)]
pub struct ApiState {
    /// The Rib (wrapping rotonda-store) to be set by the RibUnit
    //pub(crate) store: OnceLock<Arc<Rib>>,
    pub(crate) store: Arc<ArcSwapOption<Rib>>,

    /// The `ingress::Register`
    pub(crate) ingress_register: Arc<ingress::Register>,
    // roto::Compiled: < >
    /// The metrics collection
    pub(crate) metrics: crate::metrics::Collection,

    /// Version, uptime and the running config snapshot
    pub(crate) daemon_info: Arc<DaemonInfo>,
}

impl Api {
    /// Create a new HTTP Api based on configured interfaces and an `ingress::Register`
    ///
    /// The reference to the Rib (rotonda-store) will be unset, and is to be set by a/the RibUnit
    pub fn new(
        interfaces: Vec<SocketAddr>,
        ingress_register: Arc<ingress::Register>,
        metrics: crate::metrics::Collection,
        daemon_info: Arc<DaemonInfo>,
    ) -> Self {
        let state = ApiState {
            store: Default::default(),
            ingress_register: ingress_register.clone(),
            metrics: metrics.clone(),
            daemon_info: daemon_info.clone(),
        };

        let router = axum::Router::<ApiState>::new()
            .route("/metrics", get(Self::metrics))
            .with_state(state);

        let mut res = Self {
            api_root: "".into(),
            store: Default::default(),
            interfaces,
            ingress_register,
            metrics,
            daemon_info,
            router,
            signal_txs: vec![],
            serve_handles: vec![],
        };

        // The web-ui lives on /
        eprintln!("calling WebUI::register_routes");
        WebUI::register_routes(&mut res);
        eprintln!("calling WebUI::register_routes done");

        // All other endpoints go under /api/v1
        res.api_root = "/api/v1".into();

        IngressApi::register_routes(&mut res);
        crate::daemon_info::http_ng::register_routes(&mut res);
        crate::units::bgp_tcp_in::http_ng::register_routes(&mut res);

        res
    }

    async fn metrics(
        state: axum::extract::State<ApiState>,
    ) -> Result<String, String> {
        Ok(state
            .metrics
            .assemble(crate::metrics::OutputFormat::Prometheus))
    }

    /// Clone an `ApiState` based on the references to the store an ingress registry
    pub fn cloned_api_state(&self) -> ApiState {
        debug!(
            "cloned_api_state(), store is_some: {:?}",
            self.store.load().is_some()
        );
        ApiState {
            store: self.store.clone(),
            ingress_register: self.ingress_register.clone(),
            metrics: self.metrics.clone(),
            daemon_info: self.daemon_info.clone(),
        }
    }

    /// Set the reference to the Rib (once)
    ///
    /// When this method is called while `self.store` is already set, the call is basically a
    /// no-op.
    pub fn set_rib(&mut self, rib: Arc<Rib>) {
        if self.store.swap(Some(rib)).is_some() {
            debug!("http_ng set_rib(): Rib already set")
        }
    }

    /// Set the interfaces
    pub fn set_interfaces(
        &mut self,
        interfaces: impl IntoIterator<Item = SocketAddr>,
    ) {
        //Vec<SocketAddr>) {
        self.interfaces = interfaces.into_iter().collect();
    }

    /// Add an HTTP GET endpoint
    pub fn add_get<H, T>(&mut self, path: impl AsRef<str>, handler: H)
    where
        H: axum::handler::Handler<T, ApiState>,
        T: 'static,
    {
        debug!("add_get for {}", path.as_ref());
        self.router = self
            .router
            .clone()
            .route(
                &format!("{}{}", self.api_root, path.as_ref()),
                get(handler),
            )
            .with_state(self.cloned_api_state());
    }

    /// Start the HTTP API listeners on the configured interfaces
    pub fn start(&mut self) {
        self.signal_txs = vec![];
        self.serve_handles = vec![];
        for interface in self.interfaces.clone() {
            let (signal_tx, signal_rx) = mpsc::channel::<()>(1);
            self.signal_txs.push(signal_tx);

            debug!("starting Api on interface {interface}");
            let mut app =
                self.router.clone().with_state(self.cloned_api_state());
            #[cfg(feature = "http-api-gzip")]
            {
                app = app.layer(CompressionLayer::new());
            }

            #[cfg(feature = "http-api-gzip")]
            {
                app = app.layer(CompressionLayer::new());
            }

            let h = tokio::spawn(async move {
                let listener =
                    match tokio::net::TcpListener::bind(interface).await {
                        Ok(listener) => listener,
                        Err(e) => {
                            error!("Could not bind on {}: {}", interface, e);
                            return;
                        }
                    };
                let _ = axum::serve(listener, app)
                    .with_graceful_shutdown(Self::shutdown(signal_rx))
                    .await;
            });
            self.serve_handles.push(h);
        }
    }

    async fn shutdown(mut rx: mpsc::Receiver<()>) {
        rx.recv().await;
        //debug!("in Api::shutdown(), got signal");
    }

    /// Stop all listeners and start on the configured interfaces again
    pub fn restart(&mut self) {
        //debug!("in restart(), draining {} signal_txs...", self.signal_txs.len());
        for tx in self.signal_txs.drain(..) {
            //debug!("try_send for tx $x");
            let _ = tx.try_send(());
        }

        for h in self.serve_handles.drain(..) {
            let handle = tokio::runtime::Handle::current();
            tokio::task::block_in_place(move || {
                h.is_finished();
                let _ = handle.block_on(h);
            });
        }
        self.start();
    }
}

pub enum ApiError {
    BadRequest(String),
    InternalServerError(String),
    ServiceUnavailable(String),
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        debug!("in into_response()");
        fn to_json(msg: String) -> String {
            debug!("in to_json() in into_response()");
            serde_json::json!({
                "data": None::<()>,
                "error": msg
            })
            .to_string()
        }
        (
            [("content-type", "application/json")],
            match self {
                ApiError::BadRequest(msg) => {
                    (axum::http::StatusCode::BAD_REQUEST, to_json(msg))
                }
                ApiError::InternalServerError(msg) => (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    to_json(msg),
                ),
                ApiError::ServiceUnavailable(msg) => (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    to_json(msg),
                ),
            },
        )
            .into_response()
    }
}

const STREAM_CHUNK_SIZE: usize = 256 * 1024;

/// How long a streaming response may block on a single channel send — i.e. a
/// client that has stopped reading, leaving the bounded response channel full
/// — before the dump is aborted. Without this bound a connected-but-stalled
/// client pins the blocking dump thread (and, for full-table dumps, its
/// [`crate::units::rib_unit::rib::DumpGuard`] slot) indefinitely.
const STREAM_WRITE_STALL: std::time::Duration =
    std::time::Duration::from_secs(60);

pub(crate) struct StreamResponseWriter {
    sender: tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
    buffer: Vec<u8>,
    handle: tokio::runtime::Handle,
}

impl StreamResponseWriter {
    pub(crate) fn new(
        sender: tokio::sync::mpsc::Sender<
            Result<bytes::Bytes, std::io::Error>,
        >,
        handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            sender,
            buffer: Vec::with_capacity(STREAM_CHUNK_SIZE),
            handle,
        }
    }

    fn send_buffer(&mut self) -> std::io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let chunk = bytes::Bytes::copy_from_slice(&self.buffer);
        self.buffer.clear();
        // Bounded send (runs on a spawn_blocking thread, so block_on is legal):
        // abort the dump if the client stops draining for STREAM_WRITE_STALL
        // (channel stays full). A closed channel — client disconnected — still
        // maps to BrokenPipe exactly as the previous blocking_send did.
        self.handle
            .block_on(self.sender.send_timeout(Ok(chunk), STREAM_WRITE_STALL))
            .map_err(|e| match e {
                tokio::sync::mpsc::error::SendTimeoutError::Timeout(_) => {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "client stalled draining response",
                    )
                }
                tokio::sync::mpsc::error::SendTimeoutError::Closed(_) => {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "receiver dropped",
                    )
                }
            })
    }
}

impl std::io::Write for StreamResponseWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut remaining = buf;
        while !remaining.is_empty() {
            let n =
                remaining.len().min(STREAM_CHUNK_SIZE - self.buffer.len());
            self.buffer.extend_from_slice(&remaining[..n]);
            remaining = &remaining[n..];
            if self.buffer.len() == STREAM_CHUNK_SIZE {
                self.send_buffer()?;
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.send_buffer()
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;
    use std::io::Write;

    #[tokio::test]
    async fn response_writer_bounds_chunks_and_stops_on_disconnect() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let handle = tokio::runtime::Handle::current();
        let producer = tokio::task::spawn_blocking(move || {
            let mut writer = StreamResponseWriter::new(tx, handle);
            writer
                .write_all(&vec![b'x'; STREAM_CHUNK_SIZE * 5 + 17])
                .unwrap();
            writer.flush().unwrap();
        });
        let mut sizes = Vec::new();
        while let Some(chunk) = rx.recv().await {
            let chunk = chunk.unwrap();
            assert!(chunk.len() <= STREAM_CHUNK_SIZE);
            assert!(chunk.iter().all(|&b| b == b'x'));
            sizes.push(chunk.len());
        }
        producer.await.unwrap();
        assert_eq!(
            sizes,
            [
                STREAM_CHUNK_SIZE,
                STREAM_CHUNK_SIZE,
                STREAM_CHUNK_SIZE,
                STREAM_CHUNK_SIZE,
                STREAM_CHUNK_SIZE,
                17
            ]
        );

        let (tx, rx) = tokio::sync::mpsc::channel(2);
        drop(rx);
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let mut writer = StreamResponseWriter::new(tx, handle);
            writer.write_all(b"a").unwrap();
            assert_eq!(
                writer.flush().unwrap_err().kind(),
                std::io::ErrorKind::BrokenPipe
            );
        })
        .await
        .unwrap();
    }
}

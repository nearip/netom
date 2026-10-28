use std::net::IpAddr;

use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
};
use inetnum::asn::Asn;
use serde::Deserialize;

use crate::{
    http_ng::{Api, ApiError, ApiState},
    ingress::{register::IngressState, IngressId, IngressInfo, IngressType},
    representation::OutputFormat,
    roto_runtime::types::PeerRibType,
};

pub struct IngressApi {}

impl IngressApi {
    /// Add ingress register specific endpoints to a HTTP API
    pub fn register_routes(router: &mut Api) {
        router.add_get("/ingresses", Self::ingresses);
        router.add_get("/ingresses/{ingress_id}", Self::ingress_id);
    }

    async fn ingress_id(
        Path(ingress_id): Path<IngressId>,
        state: State<ApiState>,
    ) -> Result<impl IntoResponse, ApiError> {
        //let mut res = Vec::new();
        //let _ = state.ingress_register.get_and_output(ingress_id, Json(&mut res));
        //Ok(res.into())

        let raw = serde_json::json!(
            {"data": state.ingress_register.get(ingress_id)
                .as_ref().map(|ingress_info| crate::ingress::register::IdAndInfo{ingress_id, ingress_info})

            }
        );
        Ok(([("content-type", "application/json")], raw.to_string()))
    }

    async fn ingresses(
        Query(filter): Query<QueryFilter>,
        state: State<ApiState>,
    ) -> Result<impl IntoResponse, ApiError> {
        let format = filter.format;
        use crate::http_ng::StreamResponseWriter;
        use std::io::Write;
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let mut writer = StreamResponseWriter::new(tx, handle);
            if state
                .ingress_register
                .write_search(filter, &mut writer)
                .is_ok()
            {
                let _ = writer.flush();
            }
        });
        Ok((
            [("content-type", format.content_type())],
            axum::body::Body::from_stream(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            ),
        ))
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct QueryFilter {
    #[serde(rename = "filter[type]")]
    pub ingress_type: Option<IngressType>,

    #[serde(rename = "filter[state]")]
    pub ingress_state: Option<IngressState>,

    #[serde(rename = "filter[ribType]")]
    pub rib_type: Option<PeerRibType>,

    #[serde(rename = "filter[peerAddress]")]
    pub remote_addr: Option<IpAddr>,

    #[serde(rename = "filter[peerAsn]")]
    pub remote_asn: Option<Asn>,

    #[serde(default)]
    pub format: OutputFormat,
}

impl QueryFilter {
    /// Returns true if `ingress_info` matches the  set fields in Self.
    ///
    /// This can be used in a call to `iter().filter()`.
    pub fn filter(&self, ingress_info: &IngressInfo) -> bool {
        if self.remote_addr.is_some()
            && self.remote_addr != ingress_info.remote_addr
        {
            return false;
        }
        if self.remote_asn.is_some()
            && self.remote_asn != ingress_info.remote_asn
        {
            return false;
        }
        if self.ingress_type.is_some()
            && self.ingress_type != ingress_info.ingress_type
        {
            return false;
        }
        if self.ingress_state.is_some()
            && self.ingress_state != ingress_info.state
        {
            return false;
        }
        if self.rib_type.is_some()
            && self.rib_type != ingress_info.peer_rib_type
        {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn ingress_http_stream_preserves_bytes_and_content_types() {
        let register = Arc::new(crate::ingress::Register::new());
        for n in 0..500 {
            let id = register.register();
            register.update_info(
                id,
                IngressInfo::new()
                    .with_name(format!("router {n} {}", "x".repeat(2048)))
                    .with_ingress_type(IngressType::Bmp),
            );
        }
        let state = ApiState {
            store: Default::default(),
            ingress_register: register.clone(),
            metrics: Default::default(),
            daemon_info: Default::default(),
        };
        for format in [OutputFormat::Json, OutputFormat::Jsonl] {
            let filter = QueryFilter {
                format,
                ..Default::default()
            };
            let mut expected = Vec::new();
            assert!(register
                .write_search(filter.clone(), &mut expected)
                .is_ok());
            let response =
                IngressApi::ingresses(Query(filter), State(state.clone()))
                    .await
                    .map_err(|_| ())
                    .unwrap()
                    .into_response();
            assert_eq!(
                response.headers()["content-type"],
                format.content_type()
            );
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(body.as_ref(), expected);
        }
    }
}

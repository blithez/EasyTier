use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::foundation::time::{Duration, timeout};

use crate::{
    foundation::token_bucket::{ArcByteLimiter, ByteLimiter},
    packet::{PacketType, ZCPacket},
    peers::{
        PeerConnectionOrigin, PeerPacketIngress,
        conn::{
            peer_conn::{PeerConn, PeerConnId},
            peer_map::PeerMap,
            peer_session::PeerSessionStore,
        },
        context::{NetworkIdentity, PeerContext},
        create_packet_recv_chan,
        error::Error,
        recv_packet_envelope_from_chan,
        test_support::NoopPeerContext,
    },
    tunnel::ring::create_ring_tunnel_pair,
};

struct RejectingRecvLimiter;

impl ByteLimiter for RejectingRecvLimiter {
    fn try_consume(&self, _bytes: u64) -> bool {
        false
    }
}

struct LimitedPeerContext {
    limiter: ArcByteLimiter,
}

impl PeerContext for LimitedPeerContext {
    fn network_identity(&self) -> NetworkIdentity {
        NetworkIdentity::default()
    }

    fn recv_limiter(
        &self,
        _network_name: &str,
        _is_foreign_network: bool,
    ) -> Option<ArcByteLimiter> {
        Some(self.limiter.clone())
    }
}

impl PeerConn {
    #[tracing::instrument]
    async fn do_handshake_as_server(&mut self) -> Result<(), Error> {
        self.do_handshake_as_server_ext(|_, _| Ok(())).await
    }
}

#[tokio::test]
async fn peer_conn_handshake_over_memory_tunnel() {
    let peer_session_store = Arc::new(PeerSessionStore::new());
    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let client_ctx = Arc::new(NoopPeerContext::default());
    let server_ctx = Arc::new(NoopPeerContext::default());

    let mut client = PeerConn::new(1, client_ctx, client_tunnel, peer_session_store.clone());
    let mut server = PeerConn::new(2, server_ctx, server_tunnel, peer_session_store);

    let (client_ret, server_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );

    client_ret.unwrap();
    server_ret.unwrap();
    assert_eq!(client.get_peer_id(), 2);
    assert_eq!(server.get_peer_id(), 1);
    assert_eq!(client.get_conn_info().features, ["liveness-echo-v1"]);
    assert_eq!(server.get_conn_info().features, ["liveness-echo-v1"]);
}

#[tokio::test]
async fn peer_recv_limit_drops_excess_data_without_blocking_ping() {
    let peer_session_store = Arc::new(PeerSessionStore::new());
    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let client_ctx = Arc::new(NoopPeerContext::default());
    let server_ctx = Arc::new(LimitedPeerContext {
        limiter: Arc::new(RejectingRecvLimiter),
    });

    let mut client = PeerConn::new(1, client_ctx, client_tunnel, peer_session_store.clone());
    let mut server = PeerConn::new(2, server_ctx, server_tunnel, peer_session_store);

    let (client_ret, server_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );
    client_ret.unwrap();
    server_ret.unwrap();

    let (client_tx, _client_rx) = create_packet_recv_chan();
    let (server_tx, mut server_rx) = create_packet_recv_chan();
    client.start_recv_loop(client_tx).await;
    server.start_recv_loop(server_tx).await;

    let client_rx_packets = client.get_stats().rx_packets;

    let mut data = ZCPacket::new_with_payload(b"over limit");
    data.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
    client.send_msg(data).await.unwrap();

    let mut ping = ZCPacket::new_with_payload(&[]);
    ping.fill_peer_manager_hdr(1, 2, PacketType::Ping as u8);
    client.send_msg(ping).await.unwrap();

    timeout(Duration::from_secs(1), async {
        while client.get_stats().rx_packets == client_rx_packets {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("receive limiting must not block the following pong");

    assert!(
        timeout(Duration::from_millis(50), server_rx.recv())
            .await
            .is_err(),
        "over-limit data packet should be dropped"
    );
}

#[tokio::test]
async fn peer_conn_noise_handshake_advertises_liveness_echo() {
    fn context(peer_key: u8) -> Arc<NoopPeerContext> {
        let private = StaticSecret::from([peer_key; 32]);
        let public = PublicKey::from(&private);
        Arc::new(
            NoopPeerContext::new(NetworkIdentity {
                network_name: "net".to_owned(),
                network_secret: Some("secret".to_owned()),
                network_secret_digest: None,
            })
            .with_secure_mode(crate::proto::common::SecureModeConfig {
                enabled: true,
                local_private_key: Some(BASE64_STANDARD.encode(private.as_bytes())),
                local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
                x509: None,
            }),
        )
    }

    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let mut client = PeerConn::new(
        1,
        context(1),
        client_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let mut server = PeerConn::new(
        2,
        context(2),
        server_tunnel,
        Arc::new(PeerSessionStore::new()),
    );

    let (client_ret, server_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );

    client_ret.unwrap();
    server_ret.unwrap();
    assert_eq!(client.get_conn_info().features, ["liveness-echo-v1"]);
    assert_eq!(server.get_conn_info().features, ["liveness-echo-v1"]);
}

#[tokio::test]
async fn peer_conn_handshake_matches_plaintext_secret_identity() {
    let peer_session_store = Arc::new(PeerSessionStore::new());
    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let client_ctx = Arc::new(NoopPeerContext::new(NetworkIdentity {
        network_name: "net".to_string(),
        network_secret: Some("secret".to_string()),
        network_secret_digest: None,
    }));
    let server_ctx = Arc::new(NoopPeerContext::new(NetworkIdentity {
        network_name: "net".to_string(),
        network_secret: Some("secret".to_string()),
        network_secret_digest: None,
    }));

    let mut client = PeerConn::new(1, client_ctx, client_tunnel, peer_session_store.clone());
    let mut server = PeerConn::new(2, server_ctx, server_tunnel, peer_session_store);

    let (client_ret, server_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );

    client_ret.unwrap();
    server_ret.unwrap();
    assert!(client.matches_local_network_secret());
    assert!(server.matches_local_network_secret());
}

#[tokio::test]
async fn local_packet_channel_injection_has_no_attached_privilege() {
    let (sender, mut receiver) = create_packet_recv_chan();
    let mut packet = ZCPacket::new_with_payload(b"local");
    packet.fill_peer_manager_hdr(77, 3, PacketType::Data as u8);

    sender.send(packet).await.unwrap();

    let envelope = recv_packet_envelope_from_chan(&mut receiver).await.unwrap();
    let (_, ingress) = envelope.into_parts();
    assert_eq!(ingress, PeerPacketIngress::Local);
    assert!(!ingress.is_attached());
}

#[tokio::test]
async fn peer_map_forwards_packet_over_memory_tunnel() {
    let peer_session_store = Arc::new(PeerSessionStore::new());
    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let client_ctx = Arc::new(NoopPeerContext::default());
    let server_ctx = Arc::new(NoopPeerContext::default());

    let mut client_conn = PeerConn::new(
        1,
        client_ctx.clone(),
        client_tunnel,
        peer_session_store.clone(),
    );
    let mut server_conn = PeerConn::new(2, server_ctx.clone(), server_tunnel, peer_session_store);

    let (client_ret, server_ret) = tokio::join!(
        client_conn.do_handshake_as_client(),
        server_conn.do_handshake_as_server()
    );
    client_ret.unwrap();
    server_ret.unwrap();

    let (client_tx, _client_rx) = create_packet_recv_chan();
    let (server_tx, mut server_rx) = create_packet_recv_chan();
    let client_map = PeerMap::new(client_tx, client_ctx, 1);
    let server_map = PeerMap::new(server_tx, server_ctx, 2);

    client_map.add_new_peer_conn(client_conn).await.unwrap();
    server_map.add_new_peer_conn(server_conn).await.unwrap();

    let mut packet = ZCPacket::new_with_payload(b"hello");
    packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
    client_map.send_msg_directly(packet, 2).await.unwrap();

    let received = timeout(Duration::from_secs(1), server_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.payload(), b"hello");
}

#[tokio::test]
async fn peer_channel_uses_admission_origin_instead_of_packet_header() {
    let peer_session_store = Arc::new(PeerSessionStore::new());
    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let client_ctx = Arc::new(NoopPeerContext::default());
    let server_ctx = Arc::new(NoopPeerContext::default());

    let mut client_conn = PeerConn::new(
        1,
        client_ctx.clone(),
        client_tunnel,
        peer_session_store.clone(),
    );
    let mut server_conn = PeerConn::new_with_peer_id_hint_and_origin(
        2,
        server_ctx.clone(),
        server_tunnel,
        None,
        peer_session_store,
        PeerConnectionOrigin::Attached,
    );
    let (client_ret, server_ret) = tokio::join!(
        client_conn.do_handshake_as_client(),
        server_conn.do_handshake_as_server()
    );
    client_ret.unwrap();
    server_ret.unwrap();
    let server_conn_id = server_conn.get_conn_id();

    let (client_tx, _client_rx) = create_packet_recv_chan();
    let (server_tx, mut server_rx) = create_packet_recv_chan();
    let client_map = PeerMap::new(client_tx, client_ctx, 1);
    let server_map = PeerMap::new(server_tx, server_ctx, 2);
    client_map.add_new_peer_conn(client_conn).await.unwrap();
    server_map.add_new_peer_conn(server_conn).await.unwrap();
    assert!(server_map.has_direct_attached_peer(1));

    let mut packet = ZCPacket::new_with_payload(b"forged source");
    packet.fill_peer_manager_hdr(77, 3, PacketType::Data as u8);
    client_map.send_msg_directly(packet, 2).await.unwrap();

    let envelope = timeout(
        Duration::from_secs(1),
        recv_packet_envelope_from_chan(&mut server_rx),
    )
    .await
    .unwrap()
    .unwrap();
    let (received, ingress) = envelope.into_parts();
    assert_eq!(
        received.peer_manager_header().unwrap().from_peer_id.get(),
        77
    );
    assert_eq!(
        ingress,
        PeerPacketIngress::Peer {
            peer_id: 1,
            conn_id: server_conn_id,
            origin: PeerConnectionOrigin::Attached,
        }
    );
}

#[tokio::test]
async fn peer_map_reselects_cached_connection_after_close() {
    let peer_session_store = Arc::new(PeerSessionStore::new());
    let (client_tunnel_a, server_tunnel_a) = create_ring_tunnel_pair();
    let (client_tunnel_b, server_tunnel_b) = create_ring_tunnel_pair();
    let client_ctx = Arc::new(NoopPeerContext::default());
    let server_ctx = Arc::new(NoopPeerContext::default());

    let mut client_conn_a = PeerConn::new(
        1,
        client_ctx.clone(),
        client_tunnel_a,
        peer_session_store.clone(),
    );
    let mut server_conn_a = PeerConn::new(
        2,
        server_ctx.clone(),
        server_tunnel_a,
        peer_session_store.clone(),
    );
    let mut client_conn_b = PeerConn::new(
        1,
        client_ctx.clone(),
        client_tunnel_b,
        peer_session_store.clone(),
    );
    let mut server_conn_b =
        PeerConn::new(2, server_ctx.clone(), server_tunnel_b, peer_session_store);

    let (client_a_ret, server_a_ret, client_b_ret, server_b_ret) = tokio::join!(
        client_conn_a.do_handshake_as_client(),
        server_conn_a.do_handshake_as_server(),
        client_conn_b.do_handshake_as_client(),
        server_conn_b.do_handshake_as_server(),
    );
    client_a_ret.unwrap();
    server_a_ret.unwrap();
    client_b_ret.unwrap();
    server_b_ret.unwrap();

    let (client_tx, _client_rx) = create_packet_recv_chan();
    let (server_tx, mut server_rx) = create_packet_recv_chan();
    let client_map = PeerMap::new(client_tx, client_ctx, 1);
    let server_map = PeerMap::new(server_tx, server_ctx, 2);

    client_map.add_new_peer_conn(client_conn_a).await.unwrap();
    client_map.add_new_peer_conn(client_conn_b).await.unwrap();
    server_map.add_new_peer_conn(server_conn_a).await.unwrap();
    server_map.add_new_peer_conn(server_conn_b).await.unwrap();

    let mut first_packet = ZCPacket::new_with_payload(b"first");
    first_packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
    client_map.send_msg_directly(first_packet, 2).await.unwrap();
    let first_received = timeout(Duration::from_secs(1), server_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first_received.payload(), b"first");

    let first_conn_id = client_map.get_peer_default_conn_id(2).await.unwrap();
    assert_ne!(first_conn_id, PeerConnId::default());
    client_map.close_peer_conn(2, &first_conn_id).await.unwrap();
    timeout(Duration::from_secs(1), async {
        while client_map.get_peer_default_conn_id(2).await == Some(first_conn_id) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let mut second_packet = ZCPacket::new_with_payload(b"second");
    second_packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
    client_map
        .send_msg_directly(second_packet, 2)
        .await
        .unwrap();
    let second_received = timeout(Duration::from_secs(1), server_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second_received.payload(), b"second");
    assert_ne!(
        client_map.get_peer_default_conn_id(2).await,
        Some(first_conn_id)
    );
}

#[cfg(feature = "x509-auth")]
mod x509_handshake_tests {
    use super::*;
    use crate::config::normalize_secure_mode_config;
    use crate::proto::common::{SecureModeConfig, X509AuthConfig};

    fn client_auth() -> X509AuthConfig {
        X509AuthConfig {
            client_certificate_pem: Some(include_str!("../../tests/data/x509/client.pem").to_owned()),
            client_private_key_pem: Some(include_str!("../../tests/data/x509/client.key.pem").to_owned()),
            ..Default::default()
        }
    }

    fn server_auth() -> X509AuthConfig {
        X509AuthConfig {
            trusted_client_ca_pem: vec![include_str!("../../tests/data/x509/ca.pem").to_owned()],
            ..Default::default()
        }
    }

    fn context(name: &str, auth: Option<X509AuthConfig>, noise: bool) -> Arc<NoopPeerContext> {
        let context = NoopPeerContext::new(NetworkIdentity::new(name.to_owned(), "secret".to_owned()));
        if !noise { return Arc::new(context); }
        Arc::new(context.with_secure_mode(normalize_secure_mode_config(SecureModeConfig {
            enabled: true, x509: auth, ..Default::default()
        }).unwrap()))
    }

    async fn handshake(
        client: Arc<NoopPeerContext>, server: Arc<NoopPeerContext>,
    ) -> Result<(), Error> {
        handshake_with_sessions(client, server, Arc::new(PeerSessionStore::new())).await
    }

    async fn handshake_with_sessions(
        client: Arc<NoopPeerContext>,
        server: Arc<NoopPeerContext>,
        server_sessions: Arc<PeerSessionStore>,
    ) -> Result<(), Error> {
        let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
        let session_key = crate::peers::conn::peer_session::SessionKey::new(client.network_identity().network_name, 1);
        let previous_root = server_sessions.get(&session_key).map(|s| s.root_key());
        let mut client = PeerConn::new(1, client, client_tunnel, Arc::new(PeerSessionStore::new()));
        let mut server = PeerConn::new(2, server, server_tunnel, server_sessions.clone());
        // Drop rejected connections immediately, as the real admission path does.
        let client_task = async move { client.do_handshake_as_client().await };
        let server_task = async move { server.do_handshake_as_server().await };
        let (client_result, result) = timeout(Duration::from_secs(10), async {
            tokio::join!(client_task, server_task)
        }).await.expect("X.509 handshake must finish or reject within its timeout");
        if result.is_err() {
            assert_eq!(server_sessions.get(&session_key).map(|s| s.root_key()), previous_root,
                "unauthenticated clients must not allocate or replace session state");
        } else {
            client_result.expect("authorized client's handshake must also succeed");
        }
        result
    }

    #[tokio::test]
    async fn accepts_authorized_foreign_and_same_network_clients() {
        for name in ["client-net", "public-node"] {
            handshake(context(name, Some(client_auth()), true),
                context("public-node", Some(server_auth()), true)).await.unwrap();
        }
    }

    #[tokio::test]
    async fn rejects_revoked_client_reconnecting_to_existing_session() {
        let sessions = Arc::new(PeerSessionStore::new());
        let client = context("client-net", Some(client_auth()), true);
        let server = context("public-node", Some(server_auth()), true);
        handshake_with_sessions(client.clone(), server.clone(), sessions.clone()).await.unwrap();
        handshake_with_sessions(client.clone(), server, sessions.clone()).await.unwrap();

        let mut revoked = server_auth();
        revoked.client_crl_pem = vec![include_str!("../../tests/data/x509/revoked.crl.pem").to_owned()];
        assert!(handshake_with_sessions(client,
            context("public-node", Some(revoked), true), sessions).await.is_err());
    }

    #[tokio::test]
    async fn certificate_client_can_connect_to_unprotected_node() {
        handshake(context("client-net", Some(client_auth()), true),
            context("public-node", None, true)).await.unwrap();
    }

    #[tokio::test]
    async fn rejects_missing_untrusted_revoked_and_legacy_clients() {
        let server = context("public-node", Some(server_auth()), true);
        assert!(handshake(context("client-net", None, true), server.clone()).await.is_err());
        assert!(handshake(context("client-net", Some(server_auth()), true), server.clone()).await.is_err());
        assert!(handshake(context("client-net", None, false), server).await.is_err());
        let mut untrusted = server_auth();
        untrusted.trusted_client_ca_pem = vec![include_str!("../../tests/data/x509/other-ca.pem").to_owned()];
        assert!(handshake(context("client-net", Some(client_auth()), true),
            context("public-node", Some(untrusted), true)).await.is_err());
        let mut revoked = server_auth();
        revoked.client_crl_pem = vec![include_str!("../../tests/data/x509/revoked.crl.pem").to_owned()];
        assert!(handshake(context("client-net", Some(client_auth()), true),
            context("public-node", Some(revoked), true)).await.is_err());
    }
}

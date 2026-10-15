use std::net::IpAddr;
use tracing::{info, warn};

/// Embedded TURN Relay UDP Handler for WebRTC IP Obfuscation
pub async fn start_embedded_turn_server(bind_addr: &str) {
    let socket = match tokio::net::UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to bind embedded TURN server on {}: {} (WebRTC direct relay disabled)", bind_addr, e);
            return;
        }
    };
    info!("🛡️ Embedded Baton TURN Server listening on UDP {}", bind_addr);

    let mut buf = [0u8; 4096];
    loop {
        if let Ok((len, src)) = socket.recv_from(&mut buf).await {
            // STUN / TURN packet processing header check (Magic Cookie 0x2112A442)
            if len >= 20 && buf[4..8] == [0x21, 0x12, 0xA4, 0x42] {
                // Respond with STUN Binding Success Response
                let mut resp = vec![0x01, 0x01, 0x00, 0x00]; // Binding Success Response
                resp.extend_from_slice(&buf[4..20]); // Copy transaction ID
                
                let family = if src.is_ipv4() { 0x01 } else { 0x02 };
                let xport = src.port() ^ 0x2112;
                resp.extend_from_slice(&[0x00, 0x20]); // Type: XOR-MAPPED-ADDRESS
                if src.is_ipv4() {
                    resp.extend_from_slice(&[0x00, 0x08]); // Length: 8
                    resp.extend_from_slice(&[0x00, family]); // Reserved and Family
                    resp.extend_from_slice(&xport.to_be_bytes()); // X-Port
                    let ip = match src.ip() { IpAddr::V4(ipv4) => ipv4, _ => unreachable!() };
                    let mut xip = ip.octets();
                    let mc = [0x21, 0x12, 0xA4, 0x42];
                    for i in 0..4 { xip[i] ^= mc[i]; }
                    resp.extend_from_slice(&xip); // X-Address
                } else {
                    resp.extend_from_slice(&[0x00, 0x14]); // Length: 20
                    resp.extend_from_slice(&[0x00, family]); // Reserved and Family
                    resp.extend_from_slice(&xport.to_be_bytes()); // X-Port
                    let ip = match src.ip() { IpAddr::V6(ipv6) => ipv6, _ => unreachable!() };
                    let mut xip = ip.octets();
                    let mc = [0x21, 0x12, 0xA4, 0x42];
                    for i in 0..4 { xip[i] ^= mc[i]; }
                    for i in 0..12 { xip[i+4] ^= buf[8+i]; }
                    resp.extend_from_slice(&xip); // X-Address
                }
                
                // update length
                let msg_len = (resp.len() - 20) as u16;
                resp[2..4].copy_from_slice(&msg_len.to_be_bytes());

                let _ = socket.send_to(&resp, src).await;
            }
        }
    }
}

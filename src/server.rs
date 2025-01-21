use std::{ops::RangeInclusive, sync::Arc, net::SocketAddr, time::{Duration, Instant}};
use std::{fs, collections::HashMap};

use dashmap::DashMap;
use mio::net::UdpSocket;
use uuid::Uuid;
use anyhow::{Error, Result};
use rand::Rng;
use serde_yaml;
use serde::Deserialize;

use crate::auth::{EncryptMethod, Authenticator};
use crate::shared::{CONTROL_PORT, CONN_LIFETIME, Header, BytePacketBuffer};


pub struct Conn {
    // Connection id as well as server listening port
    pub conn_id: u16,
    // Connection's time to live in second
    ttl: u8,
    // encryption and decryption method
    // 0x00 for non-encryption, 0x01 for aes-128-gcm,
    // and 0x02 for chacha20poly-1305
    method: EncryptMethod,
    // Client address and port
    pub addr: SocketAddr,
    // Client id, used for authentication in multi-user mode
    client_id: Uuid,
    pub header: Header,
    created_at: Instant,
}

#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    userpass: HashMap<String, [u8;32]>
}

pub struct Server {
    // Range of UDP ports that can be forwarded
    port_range: RangeInclusive<u16>,
    // Concurrent map of Connection ID and Connection
    conns: Arc<DashMap<u16, Conn>>,
    // Concurrent map of Connection ID and corresponding auth method
    auth: Arc<DashMap<u16, Authenticator>>,
    // Socket that forwards inbound traffic to corresponding client
    socket_outbound: UdpSocket
}

impl Conn {
    pub fn new(port: u16, method: EncryptMethod, addr: SocketAddr, client_id: Uuid) -> Conn {
        // using udp port as connection id,
        // making sure it's unique
        // let port = addr.port();
        let auth = method.clone();
        let id = port.clone();
        Conn {
            conn_id: port,
            ttl: CONN_LIFETIME,
            method,
            addr,
            client_id,
            header: Header::new(0, 1, auth.to_num(), 0, id, 0),
            created_at: Instant::now(),
        }
    }
    pub fn is_alive(&self) -> bool {
        let elapsed = self.created_at.elapsed();
        let ttl_duration = Duration::from_secs(self.ttl as u64);
        if elapsed < ttl_duration {
            true
        } else { false }
    }

    pub fn reset_lifetime(&mut self) -> Result<()> {
        self.created_at = Instant::now();
        Ok(())
    }
}

impl Server {
    pub fn new(port_range: RangeInclusive<u16>) -> Result<Server> {
        assert!(!port_range.is_empty(), "Must provide at least one port");
        Ok(Server {
            port_range,
            conns: Arc::new(DashMap::new()),
            auth: Arc::new(DashMap::new()),
            socket_outbound: UdpSocket::bind("127.0.0.1:7835".parse()?).unwrap()
        })
    }
    /// kill should be dead connection
    /// will panic if given connection ID does not exist
    pub fn check_alive(&mut self, conn_id: u16) {
        let conn = self.conns.get(&conn_id).unwrap();
        if !conn.is_alive() {
            // remove dead connection
            let conns = self.conns.clone();
            let _ = conns.remove(&conn_id);
        }
    }

    pub fn assign_port(&self) -> Result<u16> {
        for _ in 0..150 {
            let range = self.port_range.clone();
            let port = rand::thread_rng().gen_range(range);
            if !self.conns.contains_key(&port) {
                return Ok(port);
            } else { continue }
        }
        Err(Error::msg("Failed to find an available port"))
    }

    pub fn send_to(&self, conn_id: u16, data: &[u8]) -> Result<()> {
        let conn = self.conns.get(&conn_id).unwrap();
        let mut to_write = Vec::new();
        to_write.extend_from_slice(&conn.header.to_bytes()?);
        to_write.extend_from_slice(data);
        if to_write.len() < 512 {
            let mut buffer = BytePacketBuffer::new();
            buffer.write_and_fill(&to_write)?;
            let _ = self.socket_outbound.send_to(&buffer.buf,conn.addr)?;
            return Ok(());
        } else if to_write.len() == 512 {
            let _ = self.socket_outbound.send_to(&to_write, conn.addr)?;
            return Ok(())
        }
        Err(Error::msg("Fail to send data"))
    }
}
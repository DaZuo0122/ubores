use std::{ops::RangeInclusive, sync::Arc, net::SocketAddr, time::{Duration, Instant}};
use std::{fs, collections::HashMap};

use dashmap::DashMap;
use mio::net::UdpSocket;
use uuid::Uuid;
use anyhow::Result;
use rand::Rng;
use serde_yaml;
use serde::Deserialize;

use crate::auth::{EncryptMethod, Authenticator};
use crate::shared::{CONTROL_PORT, CONN_LIFETIME};


pub struct Conn {
    // Connection id
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
}

impl Conn {
    pub fn new(method: EncryptMethod, addr: SocketAddr, client_id: Uuid) -> Conn {
        // using udp port as connection id,
        // making sure it's unique
        let port = addr.port();
        Conn {
            conn_id: port,
            ttl: CONN_LIFETIME,
            method,
            addr,
            client_id,
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
    pub fn new(port_range: RangeInclusive<u16>) -> Server {
        assert!(!port_range.is_empty(), "Must provide at least one port");
        Server {
            port_range,
            conns: Arc::new(DashMap::new()),
            auth: Arc::new(DashMap::new()),
        }
    }

    pub fn check_alive(&mut self, conn_id: u16) {
        /// kill should be dead connection
        /// will panic if given connection ID does not exist
        let conn = self.conns.get(&conn_id).unwrap();
        if !conn.is_alive() {
            // remove dead connection
            let mut conns = self.conns.clone();
            let _ = conns.remove(&conn_id);
        }
    }
}
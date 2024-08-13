/*
use std::collections::HashMap;
use std::time::Duration;

use crate::Error;
use crate::PresharedKey;
use crate::PrivateKey;
use crate::PublicKey;
use crate::Session;

/// Wireguard protocol state machine.
pub struct Node {
    public_key: PublicKey,
    private_key: PrivateKey,
    peers: HashMap<PublicKey, PeerState>,
}

impl Node {
    pub fn new(public_key: PublicKey, private_key: PrivateKey, peers: Vec<Peer>) -> Self {
        Self {
            public_key,
            private_key,
            peers: peers
                .into_iter()
                .map(|peer| {
                    (
                        peer.public_key,
                        PeerState {
                            peer,
                            session: None,
                        },
                    )
                })
                .collect(),
        }
    }

    pub fn send(&mut self, _data: &[u8], _destination: &PublicKey) -> Result<(), Error> {
        Ok(())
    }

    pub fn receive(&mut self) -> Result<Option<(Vec<u8>, &PublicKey)>, Error> {
        Ok(None)
    }
}

pub struct Peer {
    public_key: PublicKey,
    private_key: PrivateKey,
    preshared_key: PresharedKey,
    persistent_keepalive: Duration,
}

struct PeerState {
    peer: Peer,
    session: Option<Session>,
}

// from the original Wireguard paper
const REKEY_AFTER_MESSAGES: u64 = 1_u64.pow(60);
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - 1_u64.pow(13);
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
*/

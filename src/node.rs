use std::time::Duration;

use crate::PrivateKey;
use crate::PublicKey;

/// Wireguard protocol state machine.
pub struct Node {
    static_public: PublicKey,
    static_private: PrivateKey,
    persistent_keepalive: Duration,
}

impl Node {
    pub fn new(
        static_public: PublicKey,
        static_private: PrivateKey,
        persistent_keepalive: Duration,
    ) -> Self {
        Self {
            static_public,
            static_private,
            persistent_keepalive,
        }
    }
}

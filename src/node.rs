use std::collections::HashMap;
use std::collections::VecDeque;
use std::hash::Hash;
use std::mem::take;
use std::time::Duration;
use std::time::Instant;

use static_assertions::const_assert;

use crate::Context;
use crate::Cookie;
use crate::DecodeWithContext;
use crate::EncodeWithContext;
use crate::Error;
use crate::Initiator;
use crate::InputBuffer;
use crate::Message;
use crate::PresharedKey;
use crate::PrivateKey;
use crate::PublicKey;
use crate::Responder;
use crate::Session;
use crate::SessionIndex;
use crate::Sink;
use crate::Source;
use crate::Timer;

/// Wireguard protocol state machine.
pub struct Node<E = ()> {
    private_key: PrivateKey,
    public_key: PublicKey,
    cookie: Option<Cookie>,
    peers: Vec<PeerState<E>>,
    public_key_to_peer: HashMap<PublicKey, usize>,
    endpoint_to_peer: HashMap<E, usize>,
    session_index_to_peer: HashMap<SessionIndex, usize>,
    incoming_packets: VecDeque<(Vec<u8>, E)>,
    now: Instant,
    under_load: bool,
    #[cfg(test)]
    name: String,
}

impl<E: Clone + Hash + Eq> Node<E> {
    pub fn new(
        private_key: PrivateKey,
        peers: Vec<Peer<E>>,
        #[cfg(test)] name: impl ToString,
    ) -> Self {
        let mut new_peers: Vec<PeerState<E>> = Vec::with_capacity(peers.len());
        let mut public_key_to_peer = HashMap::new();
        let mut endpoint_to_peer = HashMap::new();
        for peer in peers.into_iter() {
            public_key_to_peer.insert(peer.public_key, new_peers.len());
            if let Some(endpoint) = peer.endpoint.as_ref() {
                endpoint_to_peer.insert(endpoint.clone(), new_peers.len());
            }
            new_peers.push(PeerState {
                peer,
                session: None,
                initiator: None,
                outgoing_packets: Default::default(),
                outgoing_data_packets: Default::default(),
                last_sent: None,
                next_initiation: Default::default(),
            });
        }
        let public_key = (&private_key).into();
        Self {
            private_key,
            public_key,
            cookie: Default::default(),
            peers: new_peers,
            public_key_to_peer,
            endpoint_to_peer,
            session_index_to_peer: Default::default(),
            incoming_packets: Default::default(),
            now: Instant::now(),
            under_load: false,
            #[cfg(test)]
            name: name.to_string(),
        }
    }

    pub fn advance(&mut self, now: Instant) -> Result<(), Error> {
        self.now = now;
        for state in self.peers.iter_mut() {
            if let Some(session) = state.session.as_ref() {
                if session.ttl().has_expired(self.now) {
                    state.destroy_session();
                }
            }
            /*
            if let Some(session) = state.session.as_mut() {
                let keepalive = match state.last_sent {
                    Some(last_sent) if timeout_expired(self.now, last_sent, KEEPALIVE_TIMEOUT) => {
                        true
                    }
                    None => true,
                    _ => false,
                };
                if keepalive {
                    session.send(&[])?;
                }
            }
                */
        }
        Ok(())
    }

    pub fn send(&mut self, data: Vec<u8>, destination: &PublicKey) -> Result<(), Error> {
        let i = self.public_key_to_peer.get(destination).ok_or(Error)?;
        let state = &mut self.peers[*i];
        state.outgoing_data_packets.push_back(data);
        match state.session.as_mut() {
            Some(session) => {
                if session.new_handshake_on_send_limit().is_reached()
                    || session.new_handshake_on_send_timer().has_expired(self.now)
                {
                    state.session = None;
                    state.initiate_new_handshake(
                        self.public_key,
                        self.private_key.clone(),
                        self.now,
                    )?;
                }
            }
            None => {
                state.initiate_new_handshake(
                    self.public_key,
                    self.private_key.clone(),
                    self.now,
                )?;
            }
        };
        Ok(())
    }

    pub fn flush<S: Sink<E>>(&mut self, sink: &mut S) -> Result<(), std::io::Error> {
        for state in self.peers.iter_mut() {
            let mut sent_some = false;
            let endpoint = match state.peer.endpoint.as_ref() {
                Some(endpoint) => endpoint,
                None => {
                    eprintln!("no endpoint");
                    continue;
                }
            };
            // send handshake messages
            while let Some(packet) = state.outgoing_packets.pop_front() {
                eprintln!("send {}", packet.len());
                sink.send(packet.as_slice(), endpoint)?;
                sent_some = true;
            }
            // send data messages
            if let Some(session) = state.session.as_mut() {
                while let Some(data) = state.outgoing_data_packets.pop_front() {
                    let message = session.session.send(data.as_slice())?;
                    let mut packet = Vec::with_capacity(message.len());
                    message.encode_with_context(
                        &mut packet,
                        session.session.context(&self.public_key),
                    );
                    eprintln!("send {:?}", message.get_type());
                    sink.send(packet.as_slice(), endpoint)?;
                    sent_some = true;
                }
            }
            if sent_some {
                state.last_sent = Some(self.now);
            }
        }
        Ok(())
    }

    pub fn fill<S: Source<E>>(&mut self, source: &mut S) -> Result<(), std::io::Error> {
        while let Some((packet, endpoint)) = source.receive()? {
            if packet.is_empty() {
                break;
            }
            self.incoming_packets.push_back((packet, endpoint));
        }
        Ok(())
    }

    pub fn receive(&mut self) -> Result<Option<(Vec<u8>, PublicKey)>, Error> {
        let mut incoming_packets = take(&mut self.incoming_packets);
        let mut ret: Option<(Vec<u8>, PublicKey)> = None;
        while let Some((packets, endpoint)) = incoming_packets.pop_front() {
            let mut buffer = InputBuffer::new(packets.as_slice());
            match self.process_incoming_packet(&mut buffer, endpoint) {
                Ok(other_ret @ Some(_)) => {
                    ret = other_ret;
                    break;
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("failed to process incoming packet: {}", e);
                }
            }
        }
        self.incoming_packets = incoming_packets;
        Ok(ret)
    }

    fn process_incoming_packet(
        &mut self,
        buffer: &mut InputBuffer,
        endpoint: E,
    ) -> Result<Option<(Vec<u8>, PublicKey)>, Error> {
        let mut context = Context {
            static_public: &self.public_key,
            // TODO last sent cookie?
            cookie: self.cookie.as_ref(),
            under_load: self.under_load,
            mac2_is_valid: None,
        };
        let message = Message::decode_with_context(buffer, &mut context)?;
        eprintln!("receive {:?}", message.get_type());
        if let Some(false) = context.mac2_is_valid {
            // TODO send cookie
        }
        let i = self.endpoint_to_peer.get(&endpoint).copied();
        match message {
            Message::HandshakeInitiation(message) => {
                eprintln!("receive 0");
                let (mut responder, message) =
                    Responder::new(self.public_key, self.private_key.clone(), message)?;
                eprintln!("receive 1");
                let i = match i {
                    Some(i) => i,
                    None => {
                        let i = *self
                            .public_key_to_peer
                            .get(&message.static_public)
                            .ok_or(Error)?;
                        self.endpoint_to_peer.insert(endpoint.clone(), i);
                        i
                    }
                };
                eprintln!("receive 2");
                let peer = &mut self.peers[i];
                if peer.peer.endpoint.is_none() {
                    peer.peer.endpoint = Some(endpoint);
                }
                let (session, outgoing_packet) =
                    responder.handshake_response(&message, &peer.peer.preshared_key)?;
                eprintln!("receive 3");
                let receiver_index = session.receiver_index();
                peer.session = Some(SessionState {
                    session,
                    created_at: self.now,
                    was_initiator: false,
                });
                peer.outgoing_packets.push_back(outgoing_packet);
                self.session_index_to_peer.insert(receiver_index, i);
                Ok(None)
            }
            Message::HandshakeResponse(message) => {
                let i = match i {
                    Some(i) => i,
                    None => {
                        let i = *self
                            .session_index_to_peer
                            .get(&message.receiver_index)
                            .ok_or(Error)?;
                        self.endpoint_to_peer.insert(endpoint.clone(), i);
                        i
                    }
                };
                let peer = &mut self.peers[i];
                if peer.peer.endpoint.is_none() {
                    peer.peer.endpoint = Some(endpoint);
                }
                eprintln!("response");
                if peer.next_initiation.has_expired(self.now) {
                    peer.initiator = None;
                }
                if let Some(initiator) = peer.initiator.take() {
                    peer.session = Some(SessionState {
                        session: initiator.on_handshake_response(message)?,
                        created_at: self.now,
                        was_initiator: true,
                    });
                }
                Ok(None)
            }
            Message::PacketData(message) => {
                eprintln!("receive packet-data 0");
                let i = match i {
                    Some(i) => i,
                    None => *self
                        .session_index_to_peer
                        .get(&message.receiver_index)
                        .ok_or(Error)?,
                };
                eprintln!("receive packet-data 1");
                let peer = &mut self.peers[i];
                if let Some(session) = peer.session.as_mut() {
                    eprintln!("receive packet-data 2a");
                    if session.packet_drop_timer().has_expired(self.now)
                        || session.packet_drop_limit().is_reached()
                    {
                        return Ok(None);
                    }
                    eprintln!("receive packet-data 2a 1");
                    let data = session.session.receive(&message)?;
                    eprintln!("receive packet-data 2a 2");
                    let ret = if data.is_empty() {
                        // do not return keepalive packets
                        Ok(None)
                    } else {
                        Ok(Some((data, peer.peer.public_key)))
                    };
                    eprintln!("receive packet-data 2a 3");
                    if peer.initiator.is_none()
                        && session
                            .new_handshake_on_receive_timer()
                            .has_expired(self.now)
                    {
                        peer.initiate_new_handshake(
                            self.public_key,
                            self.private_key.clone(),
                            self.now,
                        )?;
                    }
                    eprintln!("receive packet-data 2a 4");
                    ret
                } else {
                    eprintln!("receive packet-data 2b");
                    Ok(None)
                }
            }
        }
    }
}

#[cfg(test)]
impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "{} > connections", self.name)?;
        for state in self.peers.iter() {
            match state.session.as_ref() {
                Some(session) => {
                    writeln!(
                        f,
                        "ok {}->{}",
                        session.session.sender_index(),
                        session.session.receiver_index()
                    )?;
                }
                None => match state.initiator.as_ref() {
                    Some(initiator) => {
                        writeln!(f, "initiated {}", initiator.sender_index())?;
                    }
                    None => {
                        writeln!(f, "no-session")?;
                    }
                },
            }
        }
        writeln!(f, "{} > timers", self.name)?;
        for state in self.peers.iter() {
            writeln!(
                f,
                "new-handshake-on-send {} or {} messages",
                state
                    .session
                    .as_ref()
                    .and_then(|session| session.new_handshake_on_send_timer())
                    .remaining_secs(self.now),
                state
                    .session
                    .as_ref()
                    .map(|session| session.new_handshake_on_send_limit().remaining())
                    .unwrap_or_else(|| "none".to_string())
            )?;
            writeln!(
                f,
                "new-handshake-on-receive {}",
                state
                    .session
                    .as_ref()
                    .and_then(|session| session.new_handshake_on_receive_timer())
                    .remaining_secs(self.now)
            )?;
            writeln!(
                f,
                "next-initiation-is-allowed-in {}",
                state.next_initiation.remaining_secs(self.now)
            )?;
            writeln!(
                f,
                "packet-drop {} or {} messages",
                state
                    .session
                    .as_ref()
                    .map(|session| session.packet_drop_timer())
                    .remaining_secs(self.now),
                state
                    .session
                    .as_ref()
                    .map(|session| session.packet_drop_limit().remaining())
                    .unwrap_or_else(|| "none".to_string()),
            )?;
        }
        writeln!(f, "-")?;
        Ok(())
    }
}

pub struct Peer<E> {
    public_key: PublicKey,
    preshared_key: PresharedKey,
    // TODO
    _persistent_keepalive: Duration,
    endpoint: Option<E>,
}

struct PeerState<E> {
    peer: Peer<E>,
    session: Option<SessionState>,
    initiator: Option<Initiator>,
    // encoded handshakes
    outgoing_packets: VecDeque<Vec<u8>>,
    // unencoded data
    outgoing_data_packets: VecDeque<Vec<u8>>,
    last_sent: Option<Instant>,
    next_initiation: Option<Instant>,
}

impl<E> PeerState<E> {
    fn initiate_new_handshake(
        &mut self,
        public_key: PublicKey,
        private_key: PrivateKey,
        now: Instant,
    ) -> Result<(), Error> {
        if self.initiator.is_some() {
            return Ok(());
        }
        if self.next_initiation.has_expired(now) {
            return Ok(());
        }
        let (initiator, packet) = Initiator::new(
            public_key,
            private_key,
            self.peer.preshared_key.clone(),
            self.peer.public_key,
        )?;
        self.initiator = Some(initiator);
        self.next_initiation = Some(now + REKEY_TIMEOUT);
        self.outgoing_packets.push_back(packet);
        Ok(())
    }

    fn destroy_session(&mut self) {
        self.session = None;
        self.outgoing_packets.clear();
    }
}

struct SessionState {
    session: Session,
    created_at: Instant,
    was_initiator: bool,
}

impl SessionState {
    fn num_sent_and_received(&self) -> u64 {
        self.session.receiving_key_counter().as_u64()
            + self.session.receiving_key_counter().as_u64()
    }

    fn new_handshake_on_send_timer(&self) -> Option<Instant> {
        if self.was_initiator {
            Some(self.created_at + REKEY_AFTER_TIME)
        } else {
            None
        }
    }

    fn new_handshake_on_send_limit(&self) -> Limit {
        Limit {
            counter: self.num_sent_and_received(),
            limit: REKEY_AFTER_MESSAGES,
        }
    }

    fn new_handshake_on_receive_timer(&self) -> Option<Instant> {
        if self.was_initiator {
            Some(self.created_at + REKEY_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT)
        } else {
            None
        }
    }

    fn packet_drop_timer(&self) -> Instant {
        self.created_at + REJECT_AFTER_TIME
    }

    fn packet_drop_limit(&self) -> Limit {
        Limit {
            counter: self.num_sent_and_received(),
            limit: REJECT_AFTER_MESSAGES,
        }
    }

    fn ttl(&self) -> Instant {
        self.created_at + REJECT_AFTER_TIME * 3
    }
}

struct Limit {
    counter: u64,
    limit: u64,
}

impl Limit {
    fn is_reached(&self) -> bool {
        self.counter > self.limit
    }

    #[cfg(test)]
    fn remaining(&self) -> String {
        if self.counter < self.limit {
            format!("+{}", self.limit - self.counter)
        } else {
            format!("-{}", self.counter - self.limit)
        }
    }
}

// from the original Wireguard paper
const REKEY_AFTER_MESSAGES: u64 = 2_u64.pow(60);
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - 2_u64.pow(13);
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const _REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const _COOKIE_TTL: Duration = Duration::from_secs(120);

const_assert!(
    REKEY_AFTER_TIME.as_nanos() >= KEEPALIVE_TIMEOUT.as_nanos() + REKEY_TIMEOUT.as_nanos()
);
const_assert!(REKEY_AFTER_MESSAGES <= REJECT_AFTER_MESSAGES);
const_assert!(REKEY_AFTER_TIME.as_nanos() <= REJECT_AFTER_TIME.as_nanos());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node() {
        let parent_private_key = PrivateKey::random();
        let parent_public_key: PublicKey = (&parent_private_key).into();
        let child_private_key = PrivateKey::random();
        let child_public_key: PublicKey = (&child_private_key).into();
        let preshared_key = PresharedKey::random();
        let mut parent: Node<()> = Node::new(
            parent_private_key,
            vec![Peer {
                public_key: child_public_key,
                preshared_key: preshared_key.clone(),
                _persistent_keepalive: Duration::ZERO,
                endpoint: None,
            }],
            "parent",
        );
        let mut child: Node<()> = Node::new(
            child_private_key,
            vec![Peer {
                public_key: parent_public_key,
                preshared_key: preshared_key.clone(),
                _persistent_keepalive: Duration::ZERO,
                endpoint: Some(()),
            }],
            "child",
        );
        let mut child_outgoing_packets: VecDeque<Vec<u8>> = Default::default();
        let mut parent_outgoing_packets: VecDeque<Vec<u8>> = Default::default();
        let expected_data = "hello world".as_bytes();
        child.advance(Instant::now()).unwrap();
        child
            .send(expected_data.to_vec(), &parent.public_key)
            .unwrap();
        child.flush(&mut child_outgoing_packets).unwrap();
        parent.advance(Instant::now()).unwrap();
        parent.fill(&mut child_outgoing_packets).unwrap();
        assert_eq!(None, parent.receive().unwrap());
        parent.flush(&mut parent_outgoing_packets).unwrap();
        child.advance(Instant::now()).unwrap();
        child.fill(&mut parent_outgoing_packets).unwrap();
        assert_eq!(None, child.receive().unwrap());
        eprintln!("{:?}", child);
        eprintln!("{:?}", parent);
        child.flush(&mut child_outgoing_packets).unwrap();
        parent.advance(Instant::now()).unwrap();
        parent.fill(&mut child_outgoing_packets).unwrap();
        let (actual_data, from) = parent.receive().unwrap().unwrap();
        assert_eq!(child_public_key, from);
        assert_eq!(expected_data, actual_data);
    }

    impl Sink<()> for VecDeque<Vec<u8>> {
        fn send(&mut self, data: &[u8], _: &()) -> Result<(), std::io::Error> {
            self.push_back(data.to_vec());
            Ok(())
        }
    }

    impl Source<()> for VecDeque<Vec<u8>> {
        fn receive(&mut self) -> Result<Option<(Vec<u8>, ())>, std::io::Error> {
            match self.pop_front() {
                Some(data) => Ok(Some((data, ()))),
                None => Ok(None),
            }
        }
    }
}

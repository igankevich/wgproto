use std::collections::HashMap;
use std::collections::VecDeque;
use std::hash::Hash;
use std::mem::take;
use std::time::Duration;
use std::time::Instant;

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

/// Wireguard protocol state machine.
pub struct Node<E = ()> {
    private_key: PrivateKey,
    public_key: PublicKey,
    cookie: Option<Cookie>,
    peers: Vec<PeerState<E>>,
    public_key_to_peer: HashMap<PublicKey, usize>,
    endpoint_to_peer: HashMap<E, usize>,
    session_index_to_peer: HashMap<SessionIndex, usize>,
    incoming_packets: Vec<(Vec<u8>, E)>,
    now: Instant,
    under_load: bool,
}

impl<E: Clone + Hash + Eq> Node<E> {
    pub fn new(private_key: PrivateKey, peers: Vec<Peer<E>>) -> Self {
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
                last_sent: None,
                next_initiation: None,
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
        }
    }

    pub fn advance(&mut self, now: Instant) -> Result<(), Error> {
        self.now = now;
        for _state in self.peers.iter_mut() {
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

    pub fn send(&mut self, data: &[u8], destination: &PublicKey) -> Result<(), Error> {
        let i = self.public_key_to_peer.get(destination).ok_or(Error)?;
        let state = &mut self.peers[*i];
        match state.session.as_mut() {
            Some(session) => {
                let message = session.session.send(data)?;
                let mut packet = Vec::with_capacity(message.len());
                message.encode_with_context(&mut packet, session.session.context(&self.public_key));
                state.outgoing_packets.push_back(packet);
                if session.session.sending_key_counter().as_u64() > REKEY_AFTER_MESSAGES
                    || (session.was_initiator && session.created_at + REKEY_AFTER_TIME < self.now)
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
                state.outgoing_packets.push_back(data.into());
            }
        };
        Ok(())
    }

    pub fn flush<S: Sink<E>>(&mut self, sink: &mut S) -> Result<(), std::io::Error> {
        for state in self.peers.iter_mut() {
            let mut sent_some = false;
            while let Some(packet) = state.outgoing_packets.front_mut() {
                let endpoint = match state.peer.endpoint.as_ref() {
                    Some(endpoint) => endpoint,
                    None => break,
                };
                let n = sink.send(packet, endpoint)?;
                if n != 0 {
                    sent_some = true;
                }
                if n != packet.len() {
                    packet.drain(..n);
                    break;
                }
                state.outgoing_packets.pop_front();
            }
            if sent_some {
                state.last_sent = Some(self.now);
            }
        }
        Ok(())
    }

    pub fn fill<S: Source<E>>(
        &mut self,
        buffer: &mut [u8],
        source: &mut S,
    ) -> Result<(), std::io::Error> {
        // TODO receive Vec<u8>
        while let Some((n, endpoint)) = source.receive(buffer)? {
            if n == 0 {
                break;
            }
            self.incoming_packets.push((buffer[..n].into(), endpoint));
        }
        Ok(())
    }

    pub fn receive(&mut self) -> Result<Option<(Vec<u8>, PublicKey)>, Error> {
        let mut incoming_packets = take(&mut self.incoming_packets);
        let mut ret: Option<(Vec<u8>, PublicKey)> = None;
        for (packets, endpoint) in incoming_packets.iter_mut() {
            let mut buffer = InputBuffer::new(packets.as_slice());
            while !buffer.is_empty() {
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
            packets.drain(..buffer.position());
        }
        self.incoming_packets = incoming_packets;
        Ok(ret)
    }

    fn process_incoming_packet(
        &mut self,
        buffer: &mut InputBuffer,
        endpoint: &E,
    ) -> Result<Option<(Vec<u8>, PublicKey)>, Error> {
        let mut context = Context {
            static_public: &self.public_key,
            // TODO last sent cookie?
            cookie: self.cookie.as_ref(),
            under_load: self.under_load,
            mac2_is_valid: None,
        };
        let message = Message::decode_with_context(buffer, &mut context)?;
        if let Some(false) = context.mac2_is_valid {
            // TODO send cookie
        }
        let i = self.endpoint_to_peer.get(endpoint).copied();
        match message {
            Message::HandshakeInitiation(message) => {
                let (mut responder, message) =
                    Responder::new(self.public_key, self.private_key.clone(), message)?;
                let i = match i {
                    Some(i) => i,
                    None => *self
                        .public_key_to_peer
                        .get(&message.static_public)
                        .ok_or(Error)?,
                };
                let peer = &mut self.peers[i];
                let (session, outgoing_packet) =
                    responder.handshake_response(&message, &peer.peer.preshared_key)?;
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
                    None => *self
                        .session_index_to_peer
                        .get(&message.receiver_index)
                        .ok_or(Error)?,
                };
                let peer = &mut self.peers[i];
                if let Some(next_initiation) = peer.next_initiation {
                    if next_initiation > self.now {
                        peer.initiator = None;
                    }
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
                let i = match i {
                    Some(i) => i,
                    None => *self
                        .session_index_to_peer
                        .get(&message.receiver_index)
                        .ok_or(Error)?,
                };
                let peer = &mut self.peers[i];
                if let Some(session) = peer.session.as_mut() {
                    if session.created_at + REJECT_AFTER_TIME < self.now
                        || session.num_sent_and_received() > REJECT_AFTER_MESSAGES
                    {
                        return Ok(None);
                    }
                    let data = session.session.receive(&message)?;
                    let ret = if data.is_empty() {
                        // do not return keepalive packets
                        Ok(None)
                    } else {
                        Ok(Some((data, peer.peer.public_key)))
                    };
                    if peer.initiator.is_none()
                        && self.now.saturating_duration_since(session.created_at)
                            < REKEY_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_AFTER_TIME
                    {
                        peer.initiate_new_handshake(
                            self.public_key,
                            self.private_key.clone(),
                            self.now,
                        )?;
                    }
                    ret
                } else {
                    Ok(None)
                }
            }
        }
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
    outgoing_packets: VecDeque<Vec<u8>>,
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
        if let Some(next_initiation) = self.next_initiation {
            if next_initiation < now {
                return Ok(());
            }
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
}

// from the original Wireguard paper
const REKEY_AFTER_MESSAGES: u64 = 1_u64.pow(60);
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - 1_u64.pow(13);
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const _REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const _COOKIE_TTL: Duration = Duration::from_secs(120);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node() {
        let parent_private_key = PrivateKey::random();
        let parent_public_key: PublicKey = (&parent_private_key).into();
        let preshared_key = PresharedKey::random();
        let mut parent: Node<()> = Node::new(
            PrivateKey::random(),
            vec![Peer {
                public_key: parent_public_key,
                preshared_key: preshared_key.clone(),
                _persistent_keepalive: Duration::ZERO,
                endpoint: None,
            }],
        );
        let mut child: Node<()> = Node::new(
            PrivateKey::random(),
            vec![Peer {
                public_key: parent.public_key,
                preshared_key: preshared_key.clone(),
                _persistent_keepalive: Duration::ZERO,
                endpoint: Some(()),
            }],
        );
        let mut child_outgoing_packets: VecDeque<Vec<u8>> = Default::default();
        let expected_data = "hello world";
        child.advance(Instant::now()).unwrap();
        child
            .send(expected_data.as_bytes(), &parent.public_key)
            .unwrap();
        child.flush(&mut child_outgoing_packets).unwrap();
        parent.advance(Instant::now()).unwrap();
        //parent.fill(&mut child_outgoing_packets).unwrap();
    }

    impl Sink<()> for VecDeque<Vec<u8>> {
        fn send(&mut self, data: &[u8], _: &()) -> Result<usize, std::io::Error> {
            self.push_back(data.to_vec());
            Ok(data.len())
        }
    }

    impl Source<()> for VecDeque<Vec<u8>> {
        fn receive(&mut self, _data: &mut [u8]) -> Result<Option<(usize, ())>, std::io::Error> {
            match self.pop_front() {
                Some(data) => Ok(Some((data.len(), ()))),
                None => Ok(None),
            }
        }
    }
}

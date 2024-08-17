use std::collections::HashMap;
use std::collections::VecDeque;
use std::hash::Hash;
use std::mem::take;
use std::ops::Deref;
use std::ops::DerefMut;
use std::time::Duration;
use std::time::Instant;

use rand::Rng;
use rand_core::OsRng;
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
use crate::Timestamp;

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
                max_received_timestamp: None,
                outgoing_packets: Default::default(),
                outgoing_data_packets: Default::default(),
                last_sent: None,
                last_received: None,
                next_initiation: Default::default(),
                initiated_at: None,
                retry_jitter: 0,
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
        for (i, state) in self.peers.iter_mut().enumerate() {
            if state.session_ttl_timer().expired(self.now, false) {
                state.destroy_session();
            }
            if state.initiation_stop_timer().expired(self.now, false) {
                state.destroy_initiator();
            }
            if state.initiation_retry_timer().expired(self.now, false)
                || state.no_receive_timer().expired(self.now, false)
            {
                state.new_initiator(
                    self.public_key,
                    self.private_key.clone(),
                    self.now,
                    &mut self.session_index_to_peer,
                    i,
                )?;
            }
            if state.no_send_timer().expired(self.now, false) {
                if let Some(session) = state.session.as_mut() {
                    session.session.send(&[])?;
                }
            }
            if state.persistent_keepalive_timer().expired(self.now, false) {
                if let Some(session) = state.session.as_mut() {
                    session.session.send(&[])?;
                }
            }
        }
        Ok(())
    }

    pub fn next_event_time(&self) -> Option<Instant> {
        let mut t_min: Option<Instant> = None;
        for state in self.peers.iter() {
            for timer in [
                state.initiation_retry_timer(),
                state.initiation_stop_timer(),
                state.next_initiation,
                state.no_receive_timer(),
                state.no_send_timer(),
                state.session_ttl_timer(),
                state.new_handshake_on_send_timer(),
                state.new_handshake_on_receive_timer(),
                state.packet_drop_timer(),
                state.persistent_keepalive_timer(),
            ]
            .into_iter()
            .flatten()
            {
                match t_min.as_mut() {
                    Some(t_min) => {
                        if timer < *t_min {
                            *t_min = timer;
                        }
                    }
                    None => t_min = Some(timer),
                }
            }
        }
        t_min
    }

    pub fn send(&mut self, data: Vec<u8>, destination: &PublicKey) -> Result<(), Error> {
        let i = self.public_key_to_peer.get(destination).ok_or(Error)?;
        let state = &mut self.peers[*i];
        state.outgoing_data_packets.push_back(data);
        match state.session.as_mut() {
            Some(session) => {
                if session.new_handshake_on_send_limit().reached()
                    || session
                        .new_handshake_on_send_timer()
                        .expired(self.now, false)
                {
                    state.session = None;
                    state.new_initiator(
                        self.public_key,
                        self.private_key.clone(),
                        self.now,
                        &mut self.session_index_to_peer,
                        *i,
                    )?;
                }
            }
            None => {
                state.new_initiator(
                    self.public_key,
                    self.private_key.clone(),
                    self.now,
                    &mut self.session_index_to_peer,
                    *i,
                )?;
            }
        };
        Ok(())
    }

    pub fn flush<S: Sink<E>>(&mut self, sink: &mut S) -> Result<(), std::io::Error> {
        for state in self.peers.iter_mut() {
            let mut guard = state.last_sent_guard(self.now);
            guard.flush(sink, &self.public_key)?;
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
                    // return data packets
                    ret = other_ret;
                    break;
                }
                Ok(None) => {
                    // process handshake packets
                }
                Err(_) => {
                    // ignore invalid packets
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
        if let Some(false) = context.mac2_is_valid {
            // TODO send cookie
        }
        let i = self.endpoint_to_peer.get(&endpoint).copied();
        match message {
            Message::HandshakeInitiation(message) => {
                let (mut responder, message) =
                    Responder::new(self.public_key, self.private_key.clone(), message)?;
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
                let peer = &mut self.peers[i];
                peer.validate_timestamp(message.timestamp)?;
                if peer.peer.endpoint.is_none() {
                    peer.peer.endpoint = Some(endpoint);
                }
                peer.last_received = Some(self.now);
                let (session, outgoing_packet) =
                    responder.handshake_response(&message, &peer.peer.preshared_key)?;
                let receiver_index = session.receiver_index();
                peer.new_session(SessionState {
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
                peer.last_received = Some(self.now);
                if peer.next_initiation.expired(self.now, false) {
                    peer.initiator = None;
                }
                if let Some(initiator) = peer.initiator.take() {
                    peer.new_session(SessionState {
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
                    if session.packet_drop_timer().expired(self.now)
                        || session.packet_drop_limit().reached()
                    {
                        return Ok(None);
                    }
                    let data = session.session.receive(&message)?;
                    peer.last_received = Some(self.now);
                    let ret = if data.is_empty() {
                        // do not return keepalive packets
                        Ok(None)
                    } else {
                        Ok(Some((data, peer.peer.public_key)))
                    };
                    if peer.initiator.is_none()
                        && session
                            .new_handshake_on_receive_timer()
                            .expired(self.now, false)
                    {
                        peer.new_initiator(
                            self.public_key,
                            self.private_key.clone(),
                            self.now,
                            &mut self.session_index_to_peer,
                            i,
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
                "next-initiation {}",
                state.initiation_retry_timer().remaining_secs(self.now)
            )?;
            writeln!(
                f,
                "stop-initiation {}",
                state.initiation_stop_timer().remaining_secs(self.now)
            )?;
            writeln!(
                f,
                "next-initiation-is-allowed-in {}",
                state.next_initiation.remaining_secs(self.now)
            )?;
            writeln!(
                f,
                "new-handshake-on-no-receive {}",
                state.no_receive_timer().remaining_secs(self.now)
            )?;
            writeln!(
                f,
                "keepalive-on-no-send {}",
                state.no_send_timer().remaining_secs(self.now)
            )?;
            writeln!(
                f,
                "session-ttl {}",
                state.session_ttl_timer().remaining_secs(self.now),
            )?;
            writeln!(
                f,
                "new-handshake-on-send {} or {} messages",
                state.new_handshake_on_send_timer().remaining_secs(self.now),
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
                    .new_handshake_on_receive_timer()
                    .remaining_secs(self.now)
            )?;
            writeln!(
                f,
                "packet-drop {} or {} messages",
                state.packet_drop_timer().remaining_secs(self.now),
                state
                    .session
                    .as_ref()
                    .map(|session| session.packet_drop_limit().remaining())
                    .unwrap_or_else(|| "none".to_string()),
            )?;
        }
        writeln!(
            f,
            "{} > next event time {}",
            self.name,
            self.next_event_time().remaining_secs(self.now)
        )?;
        writeln!(f, "-")?;
        Ok(())
    }
}

pub struct Peer<E> {
    public_key: PublicKey,
    preshared_key: PresharedKey,
    persistent_keepalive: Duration,
    endpoint: Option<E>,
}

struct PeerState<E> {
    peer: Peer<E>,
    session: Option<SessionState>,
    initiator: Option<Initiator>,
    max_received_timestamp: Option<Timestamp>,
    // encoded handshakes
    outgoing_packets: VecDeque<Vec<u8>>,
    // unencoded data
    outgoing_data_packets: VecDeque<Vec<u8>>,
    last_sent: Option<Instant>,
    last_received: Option<Instant>,
    next_initiation: Option<Instant>,
    initiated_at: Option<Instant>,
    retry_jitter: u64,
}

impl<E> PeerState<E> {
    fn new_initiator(
        &mut self,
        public_key: PublicKey,
        private_key: PrivateKey,
        now: Instant,
        session_index_to_peer: &mut HashMap<SessionIndex, usize>,
        peer_index: usize,
    ) -> Result<(), Error> {
        use std::collections::hash_map::Entry;
        if self.initiator.is_some() || !self.next_initiation.expired(now, true) {
            return Ok(());
        }
        let session_index = loop {
            let session_index = SessionIndex::new();
            if let Entry::Vacant(v) = session_index_to_peer.entry(session_index) {
                v.insert(peer_index);
                break session_index;
            }
        };
        let (initiator, packet) = Initiator::new(
            session_index,
            public_key,
            private_key,
            self.peer.preshared_key.clone(),
            self.peer.public_key,
        )?;
        self.initiator = Some(initiator);
        self.initiated_at = Some(now);
        self.retry_jitter = retry_jitter();
        self.next_initiation = Some(now + REKEY_TIMEOUT);
        self.outgoing_packets.push_back(packet);
        Ok(())
    }

    fn destroy_initiator(&mut self) {
        self.initiator = None;
        self.next_initiation = None;
        self.outgoing_packets.clear();
    }

    fn new_session(&mut self, session: SessionState) {
        self.session = Some(session);
        self.initiated_at = None;
    }

    fn destroy_session(&mut self) {
        self.session = None;
        self.outgoing_packets.clear();
    }

    fn initiation_retry_timer(&self) -> Option<Instant> {
        self.initiator.as_ref()?;
        self.initiated_at
            .map(|t| t + REKEY_TIMEOUT + Duration::from_millis(self.retry_jitter))
    }

    fn initiation_stop_timer(&self) -> Option<Instant> {
        self.initiator.as_ref()?;
        self.initiated_at.map(|t| t + REKEY_ATTEMPT_TIME)
    }

    fn no_receive_timer(&self) -> Option<Instant> {
        self.initiator.as_ref()?;
        let no_receive = match (self.last_sent, self.last_received) {
            (Some(_), None) => true,
            (Some(last_sent), Some(last_received)) if last_received < last_sent => true,
            // TODO do we need this? should never happen...
            (Some(last_sent), Some(last_received))
                if last_sent + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT < last_received =>
            {
                true
            }
            _ => false,
        };
        if no_receive {
            self.last_sent
                .map(|t| t + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT)
        } else {
            None
        }
    }

    fn no_send_timer(&self) -> Option<Instant> {
        self.initiator.as_ref()?;
        let no_send = match (self.last_sent, self.last_received) {
            (None, Some(_)) => true,
            (Some(last_sent), Some(last_received)) if last_sent < last_received => true,
            // TODO do we need this? should never happen...
            (Some(last_sent), Some(last_received))
                if last_received + KEEPALIVE_TIMEOUT < last_sent =>
            {
                true
            }
            _ => false,
        };
        if no_send {
            self.last_received.map(|t| t + KEEPALIVE_TIMEOUT)
        } else {
            None
        }
    }

    fn session_ttl_timer(&self) -> Option<Instant> {
        self.session.as_ref().map(|session| session.ttl_timer())
    }

    fn new_handshake_on_send_timer(&self) -> Option<Instant> {
        self.session
            .as_ref()
            .and_then(|session| session.new_handshake_on_send_timer())
    }

    fn new_handshake_on_receive_timer(&self) -> Option<Instant> {
        self.session
            .as_ref()
            .and_then(|session| session.new_handshake_on_receive_timer())
    }

    fn packet_drop_timer(&self) -> Option<Instant> {
        self.session
            .as_ref()
            .map(|session| session.packet_drop_timer())
    }

    fn persistent_keepalive_timer(&self) -> Option<Instant> {
        if self.session.is_some() {
            if self.peer.persistent_keepalive != Duration::ZERO {
                self.last_sent.map(|t| t + self.peer.persistent_keepalive)
            } else {
                None
            }
        } else {
            None
        }
    }

    fn last_sent_guard(&mut self, now: Instant) -> LastSentGuard<E> {
        LastSentGuard {
            old_num_queued_packets: self.num_queued_packets(),
            now,
            state: self,
        }
    }

    fn num_queued_packets(&self) -> usize {
        self.outgoing_packets.len() + self.outgoing_data_packets.len()
    }

    fn flush<S: Sink<E>>(
        &mut self,
        sink: &mut S,
        public_key: &PublicKey,
    ) -> Result<(), std::io::Error> {
        let endpoint = match self.peer.endpoint.as_ref() {
            Some(endpoint) => endpoint,
            None => {
                return Ok(());
            }
        };
        // send handshake messages
        while let Some(packet) = self.outgoing_packets.front() {
            sink.send(packet.as_slice(), endpoint)?;
            self.outgoing_packets.pop_front();
        }
        // send data messages
        if let Some(session) = self.session.as_mut() {
            while let Some(data) = self.outgoing_data_packets.front() {
                let message = session.session.send(data.as_slice())?;
                let mut packet = Vec::with_capacity(message.len());
                message.encode_with_context(&mut packet, session.session.context(public_key));
                sink.send(packet.as_slice(), endpoint)?;
                self.outgoing_data_packets.pop_front();
            }
        }
        Ok(())
    }

    fn validate_timestamp(&mut self, timestamp: Timestamp) -> Result<(), Error> {
        match self.max_received_timestamp.as_mut() {
            Some(max_received_timestamp) => {
                if timestamp < *max_received_timestamp {
                    return Err(Error);
                }
                *max_received_timestamp = timestamp;
            }
            None => {
                self.max_received_timestamp = Some(timestamp);
            }
        }
        Ok(())
    }
}

fn retry_jitter() -> u64 {
    OsRng.gen_range(0_u64..334_u64)
}

struct LastSentGuard<'a, E> {
    state: &'a mut PeerState<E>,
    old_num_queued_packets: usize,
    now: Instant,
}

impl<E> Deref for LastSentGuard<'_, E> {
    type Target = PeerState<E>;

    fn deref(&self) -> &Self::Target {
        self.state
    }
}

impl<E> DerefMut for LastSentGuard<'_, E> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.state
    }
}

impl<E> Drop for LastSentGuard<'_, E> {
    fn drop(&mut self) {
        if self.state.num_queued_packets() != self.old_num_queued_packets {
            self.last_sent = Some(self.now);
        }
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

    fn ttl_timer(&self) -> Instant {
        self.created_at + REJECT_AFTER_TIME * 3
    }
}

struct Limit {
    counter: u64,
    limit: u64,
}

impl Limit {
    fn reached(&self) -> bool {
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

trait Timer {
    fn expired(&self, now: Instant) -> bool;
}

impl Timer for Instant {
    fn expired(&self, now: Instant) -> bool {
        self <= &now
    }
}

trait OptionalTimer {
    fn expired(&self, now: Instant, default_value: bool) -> bool;
}

impl OptionalTimer for Option<Instant> {
    fn expired(&self, now: Instant, default_value: bool) -> bool {
        match self {
            Some(instant) => instant <= &now,
            None => default_value,
        }
    }
}

#[cfg(test)]
trait RemainingSecs {
    fn remaining_secs(&self, now: Instant) -> String;
}

#[cfg(test)]
impl RemainingSecs for Option<Instant> {
    fn remaining_secs(&self, now: Instant) -> String {
        match self {
            Some(instant) => match instant.checked_duration_since(now) {
                Some(dt) => format!("+{}s", dt.as_secs_f64()),
                None => format!("-{}s", now.duration_since(*instant).as_secs_f64()),
            },
            None => "none".into(),
        }
    }
}

// from the original Wireguard paper
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REKEY_AFTER_MESSAGES: u64 = 2_u64.pow(60);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - 2_u64.pow(13);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
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
    #[cfg_attr(miri, ignore)] // timeouts are too small for miri
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
                persistent_keepalive: Duration::ZERO,
                endpoint: None,
            }],
            "parent",
        );
        let mut child: Node<()> = Node::new(
            child_private_key,
            vec![Peer {
                public_key: parent_public_key,
                preshared_key: preshared_key.clone(),
                persistent_keepalive: Duration::ZERO,
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
        eprintln!("{:?}", child);
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

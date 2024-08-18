use std::net::SocketAddr;
use std::net::UdpSocket;

pub trait Sink<E> {
    fn send(&mut self, data: &[u8], endpoint: &E) -> Result<(), std::io::Error>;
}

pub trait Source<E> {
    fn receive(&mut self) -> Result<Option<(Vec<u8>, E)>, std::io::Error>;
}

impl Sink<SocketAddr> for UdpSocket {
    fn send(&mut self, data: &[u8], endpoint: &SocketAddr) -> Result<(), std::io::Error> {
        let n = self.send_to(data, endpoint)?;
        //let from = self.local_addr()?;
        //eprintln!("wgproto {}->{} sent {} bytes", from, endpoint, n);
        if n != data.len() {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "partial send_to",
            ))
        } else {
            Ok(())
        }
    }
}

impl Source<SocketAddr> for UdpSocket {
    fn receive(&mut self) -> Result<Option<(Vec<u8>, SocketAddr)>, std::io::Error> {
        let mut buffer = vec![0_u8; MAX_UDP_PACKET_SIZE];
        let (n, from) = self.recv_from(buffer.as_mut_slice())?;
        buffer.resize(n, 0);
        //let to = self.local_addr()?;
        //eprintln!("wgproto {}->{}, recv {} bytes", from, to, n);
        Ok(Some((buffer, from)))
    }
}

const MAX_UDP_PACKET_SIZE: usize = 65535;

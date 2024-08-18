use std::net::SocketAddr;
use std::net::UdpSocket;
use std::slice::from_raw_parts_mut;

pub trait Sink<E> {
    fn send(&mut self, data: &[u8], endpoint: &E) -> Result<(), std::io::Error>;
}

pub trait Source<E> {
    fn receive(&mut self) -> Result<Option<(Vec<u8>, E)>, std::io::Error>;
}

impl Sink<SocketAddr> for UdpSocket {
    fn send(&mut self, data: &[u8], endpoint: &SocketAddr) -> Result<(), std::io::Error> {
        let n = self.send_to(data, endpoint)?;
        if n != data.len() {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "partial sendto",
            ))
        } else {
            Ok(())
        }
    }
}

impl Source<SocketAddr> for UdpSocket {
    fn receive(&mut self) -> Result<Option<(Vec<u8>, SocketAddr)>, std::io::Error> {
        let mut buffer: Vec<u8> = Vec::with_capacity(MAX_UDP_PACKET_SIZE);
        let slice: &mut [u8] =
            unsafe { from_raw_parts_mut(buffer.as_mut_ptr(), MAX_UDP_PACKET_SIZE) };
        let (n, from) = self.recv_from(slice)?;
        unsafe {
            buffer.set_len(n);
        }
        buffer.shrink_to_fit();
        Ok(Some((buffer, from)))
    }
}

const MAX_UDP_PACKET_SIZE: usize = 65535;

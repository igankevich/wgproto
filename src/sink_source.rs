pub trait Sink<E> {
    fn send(&mut self, data: &[u8], endpoint: &E) -> Result<usize, std::io::Error>;
}

pub trait Source<E> {
    fn receive(&mut self, data: &mut [u8]) -> Result<Option<(usize, E)>, std::io::Error>;
}

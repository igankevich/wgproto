pub trait Sink<E> {
    fn send(&mut self, data: &[u8], endpoint: &E) -> Result<(), std::io::Error>;
}

pub trait Source<E> {
    fn receive(&mut self) -> Result<Option<(Vec<u8>, E)>, std::io::Error>;
}

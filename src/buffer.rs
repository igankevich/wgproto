use std::slice::SliceIndex;

pub struct InputBuffer<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> InputBuffer<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    pub fn get<I: SliceIndex<[u8]>>(
        &'a self,
        index: I,
    ) -> Option<&'a <I as SliceIndex<[u8]>>::Output> {
        self.data.get(index)
    }

    pub fn get_unchecked<I: SliceIndex<[u8]>>(
        &'a self,
        index: I,
    ) -> &'a <I as SliceIndex<[u8]>>::Output {
        &self.data[index]
    }

    pub fn get_next(&mut self, n: usize) -> Option<&[u8]> {
        match self.data.get(self.offset..(self.offset + n)) {
            ret @ Some(_) => {
                self.offset += n;
                ret
            }
            None => None,
        }
    }

    pub fn get_remaining(&mut self) -> &[u8] {
        let ret = &self.data[self.offset..];
        self.offset = self.data.len();
        ret
    }

    pub fn position(&self) -> usize {
        self.offset
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }
}

impl<'a> From<&'a [u8]> for InputBuffer<'a> {
    fn from(other: &'a [u8]) -> Self {
        Self::new(other)
    }
}

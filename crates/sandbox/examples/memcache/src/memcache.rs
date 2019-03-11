/// This is a simplified implementation of [rust-memcache](https://github.com/aisk/rust-memcache)
/// ported for AsyncRead + AsyncWrite.
use core::fmt::Display;
use futures::prelude::*;
use guest::BufferedStream;
use std::io::{Error, ErrorKind};


pub struct AsciiProtocol {
    io: BufferedStream,
}

impl AsciiProtocol {
    pub fn new(io: BufferedStream) -> Self {
        Self { io }
    }

    pub async fn get<'a, K: Display>(&'a mut self, key: &'a K) -> Result<Vec<u8>, Error> {
        // Send command
        let header = format!("get {}\r\n", key);
        await!(self.io.write_all(header.as_bytes()))?;
        await!(self.io.flush())?;

        // Read response header
        let header = {
            let v = await!(self.io.read_until(b'\n', Vec::default()))?;
            String::from_utf8(v).map_err(|_| Error::from(ErrorKind::InvalidInput))?
        };

        // Check response header and parse value length
        if header.contains("ERROR") {
            return Err(Error::new(ErrorKind::Other, header));
        } else if header.starts_with("END") {
            return Err(ErrorKind::NotFound.into());
        }

        let length_str = header.trim_end().rsplitn(2, ' ').next();
        let length: usize = match length_str {
            Some(x) => x
                .parse()
                .map_err(|_| Error::from(ErrorKind::InvalidInput))?,
            None => return Err(ErrorKind::InvalidInput.into()),
        };

        // Read value
        let mut buffer: Vec<u8> = vec![0; length];
        drop(await!(self.io.read_exact(&mut buffer))?);

        // Read the trailing header
        drop(await!(self.io.read_until(b'\n', Vec::default()))?);
        drop(await!(self.io.read_until(b'\n', Vec::default()))?);

        Ok(buffer)
    }
}

#![allow(clippy::missing_errors_doc)]

pub mod args;
pub mod iobuf;

use std::io::Read;

use liblzma::read;
use rand_chacha::rand_core::SeedableRng;
use rand_core::RngCore;

use crate::iobuf::IoBufs;

const MEM_COST: u32 = 65535;
const ITER_COST: u32 = 10;
const PARA_COST: u32 = 4;

pub fn compress(
    mut io: IoBufs,
    level: u32,
    threads: u32,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let level = std::cmp::min(9, level);

    let stream = liblzma::stream::MtStreamBuilder::new()
        .threads(threads)
        .check(liblzma::stream::Check::Crc64)
        .preset(level)
        .encoder()?;
    let xzenc = read::XzEncoder::new_stream(io.input, stream);

    let mut rng = rand_chacha::ChaChaRng::from_entropy();
    let mut salt: [u8; 32] = [0; 32];
    let mut nonce = chacha20::XNonce::default();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);

    let argon_param = argon2::Params::new(MEM_COST, ITER_COST, PARA_COST, None)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_param,
    );

    let mut hash: [u8; 32] = [0; 32];
    argon
        .hash_password_into(password.as_bytes(), &salt, &mut hash)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;

    let mut ciph = CipherReader::new(xzenc, hash.into(), nonce);

    io.output.write_all(&nonce)?;
    io.output.write_all(&salt)?;

    std::io::copy(&mut ciph, &mut io.output)?;
    Ok(())
}

pub fn decompress(mut io: IoBufs, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut nonce = chacha20::XNonce::default();
    let mut salt: [u8; 32] = [0; 32];
    io.input.read_exact(&mut nonce)?;
    io.input.read_exact(&mut salt)?;

    let argon_param = argon2::Params::new(MEM_COST, ITER_COST, PARA_COST, None)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_param,
    );

    let mut hash: [u8; 32] = [0; 32];
    argon
        .hash_password_into(password.as_bytes(), &salt, &mut hash)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;

    let ciph = CipherReader::new(io.input, hash.into(), nonce);
    let mut dec = read::XzDecoder::new_parallel(ciph);

    std::io::copy(&mut dec, &mut io.output)?;
    Ok(())
}

struct CipherReader<R: Read> {
    inner: R,
    cipher: chacha20::XChaCha20,
}

impl<R: Read> CipherReader<R> {
    fn new(inner: R, key: chacha20::Key, nonce: chacha20::XNonce) -> Self {
        use chacha20::cipher::KeyIvInit;

        Self {
            inner,
            cipher: chacha20::XChaCha20::new(&key, &nonce),
        }
    }
}

impl<R: Read> Read for CipherReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use chacha20::cipher::StreamCipher;

        let n = self.inner.read(buf)?;
        self.cipher.apply_keystream(&mut buf[..n]);
        Ok(n)
    }
}

#![allow(clippy::missing_errors_doc)]

pub mod args;
pub mod iobuf;

use std::io::Read;

use liblzma::read;
use rand_chacha::rand_core::SeedableRng;
use rand_core::RngCore;
use zeroize::Zeroize;

use crate::iobuf::IoBufs;

const MEM_COST: u32 = 65535;
const ITER_COST: u32 = 10;
const PARA_COST: u32 = 4;
const SALT_LENGTH: usize = 40; // argon2 salt is between 8 and 48 bytes long. 16 is sufficient

fn get_key(mut password: String, salt: &[u8]) -> Result<chacha20::Key, Box<dyn std::error::Error>> {
    let argon_param =
        argon2::Params::new(MEM_COST, ITER_COST, PARA_COST, None).map_err(|e| format!("{e}"))?;
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_param,
    );

    let mut key = chacha20::Key::default();
    argon
        .hash_password_into(password.as_bytes(), salt, key.as_mut_slice())
        .map_err(|e| format!("{e}"))?;
    password.zeroize();
    Ok(key)
}

pub fn compress(
    mut io: IoBufs,
    level: u32,
    threads: u32,
    password: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let level = std::cmp::min(9, level);

    let stream = liblzma::stream::MtStreamBuilder::new()
        .threads(threads)
        .check(liblzma::stream::Check::Crc64)
        .preset(level)
        .encoder()?;
    let xzenc = read::XzEncoder::new_stream(io.input, stream);

    let mut rng = rand_chacha::ChaChaRng::from_entropy();
    let mut salt = [0; SALT_LENGTH];
    rng.fill_bytes(&mut salt);

    let mut nonce = chacha20::XNonce::default();
    rng.fill_bytes(nonce.as_mut_slice());

    let key = get_key(password, &salt)?;

    let mut ciph = CipherReader::new(xzenc, key, nonce);

    io.output.write_all(&nonce)?;
    io.output.write_all(&salt)?;

    std::io::copy(&mut ciph, &mut io.output)?;
    Ok(())
}

pub fn decompress(mut io: IoBufs, password: String) -> Result<(), Box<dyn std::error::Error>> {
    let mut nonce = chacha20::XNonce::default();
    let mut salt = [0; SALT_LENGTH];
    io.input.read_exact(&mut nonce)?;
    io.input.read_exact(&mut salt)?;

    let key = get_key(password, &salt)?;
    let ciph = CipherReader::new(io.input, key, nonce);
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

#![allow(unused_imports)]

use std::io::{prelude::*, IsTerminal};
use std::io::{BufReader, BufWriter};

use clap::Parser;
use liblzma::read;
use rand_chacha::rand_core::SeedableRng;
use rand_core::RngCore;

#[derive(Parser)]
struct Args {
    #[clap(short, long)]
    decompress: bool,
    #[clap(short, long)]
    input: Option<String>,
    #[clap(short, long)]
    output: Option<String>,
    #[clap(short, long, default_value_t = 6)]
    level: u32,
    #[clap(short, long)]
    threads: Option<u32>,
}

struct IoBufs {
    input: Box<dyn BufRead>,
    output: Box<dyn Write>,
}

impl IoBufs {
    fn new(args: &Args) -> Self {
        let input: Box<dyn BufRead> = match args.input {
            None => {
                if std::io::stdin().is_terminal() {
                    eprintln!("Error: No input file specified");
                    std::process::exit(1);
                }
                Box::new(BufReader::new(std::io::stdin()))
            }
            Some(ref f) => {
                let Ok(file) = std::fs::File::open(f) else {
                    eprintln!("Error: Could not open input file: {f}");
                    std::process::exit(1);
                };
                Box::new(BufReader::new(file))
            }
        };

        let output: Box<dyn Write> = match args.output {
            None => {
                if std::io::stdout().is_terminal() {
                    eprintln!("Error: No output file specified");
                    std::process::exit(1);
                }

                Box::new(BufWriter::new(std::io::stdout()))
            }
            Some(ref f) => {
                let Ok(file) = std::fs::File::create(f) else {
                    eprintln!("Error: Could not create output file: {f}");
                    std::process::exit(1);
                };
                Box::new(BufWriter::new(file))
            }
        };
        Self { input, output }
    }
}

// Round trip some bytes from a byte source, into a compressor, into a
// decompressor, and finally into a vector.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let io = IoBufs::new(&args);
    let password = rpassword::prompt_password("Enter Passphrase: ").unwrap();

    let ret = if !args.decompress {
        let default_thread_count = num_cpus::get_physical() as u32 * 3 / 2;
        let threads = args.threads.unwrap_or(default_thread_count);

        compress(io, args.level, threads, password)
    } else {
        decompress(io, password)
    };
    if let Err(e) = ret {
        eprintln!("Error: {e}");
    }
    Ok(())
}

fn compress(
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
    let mut salt: [u8; 32] = [0; 32];
    let mut nonce = chacha20::XNonce::default();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);

    let argon_param = argon2::Params::new(65535, 10, 4, None).unwrap();
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_param,
    );

    let mut hash: [u8; 32] = [0; 32];
    argon
        .hash_password_into(password.as_bytes(), &salt, &mut hash)
        .unwrap();

    let mut ciph = CipherReader::new(xzenc, hash.into(), nonce);

    io.output.write_all(&nonce)?;
    io.output.write_all(&salt)?;

    std::io::copy(&mut ciph, &mut io.output)?;
    Ok(())
}

fn decompress(mut io: IoBufs, password: String) -> Result<(), Box<dyn std::error::Error>> {
    let mut nonce = chacha20::XNonce::default();
    let mut salt: [u8; 32] = [0; 32];
    io.input.read_exact(&mut nonce)?;
    io.input.read_exact(&mut salt)?;

    let argon_param = argon2::Params::new(65535, 10, 4, None).unwrap();
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_param,
    );

    let mut hash: [u8; 32] = [0; 32];
    argon
        .hash_password_into(password.as_bytes(), &salt, &mut hash)
        .unwrap();

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

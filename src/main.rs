use clap::Parser;

use libcomp::{args, iobuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = args::Args::parse();

    let io = iobuf::IoBufs::new(&args);
    let password = rpassword::prompt_password("Enter Passphrase: ").unwrap();

    let ret = if args.decompress {
        libcomp::decompress(io, &password)
    } else {
        let default_thread_count = u32::try_from(num_cpus::get_physical())? * 3 / 2;
        let threads = args.threads.unwrap_or(default_thread_count);

        libcomp::compress(io, args.level, threads, &password)
    };
    if let Err(e) = ret {
        eprintln!("Error: {e}");
    }
    Ok(())
}

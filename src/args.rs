use clap::Parser;

#[derive(Parser)]
pub struct Args {
    #[clap(short, long)]
    pub decompress: bool,
    #[clap(short, long)]
    pub input: Option<String>,
    #[clap(short, long)]
    pub output: Option<String>,
    #[clap(short, long, default_value_t = 6)]
    pub level: u32,
    #[clap(short, long)]
    pub threads: Option<u32>,
}

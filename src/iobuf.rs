use std::io::{prelude::*, IsTerminal};
use std::io::{BufReader, BufWriter};

use crate::args::Args;

pub struct IoBufs {
    pub input: Box<dyn BufRead>,
    pub output: Box<dyn Write>,
}

impl IoBufs {
    #[must_use]
    pub fn new(args: &Args) -> Self {
        #[allow(clippy::option_if_let_else)] // excuse: Nursery gets this wrong
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

        #[allow(clippy::option_if_let_else)] // excuse: Nursery gets this wrong
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

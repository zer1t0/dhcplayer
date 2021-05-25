mod args;
mod discover;
mod dhcp;
mod helpers;
mod server;
mod transport;
mod starvation;
mod release;
mod readin;

use crate::args::Arguments;
use log::error;

pub fn init_log(verbosity: usize) {
    stderrlog::new()
        .module(module_path!())
        .verbosity(verbosity + 1)
        .init()
        .unwrap();
}

fn main() {
    let res = match args::Arguments::parse_args() {
        Arguments::Server(args) => {
            init_log(args.verbosity);
            server::main(args)
        }
        Arguments::Discover(args) => {
            init_log(args.verbosity);
            discover::main(args)
        }
        Arguments::Starvation(args) => {
            init_log(args.verbosity);
            starvation::main(args)
        }
        Arguments::Release(args) => {
            init_log(args.verbosity);
            release::main(args)
        }
    };

    if let Err(err) = res {
        error!("{}", err);
    }
}

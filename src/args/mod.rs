pub mod discover;
mod helpers;
pub mod server;
pub mod starvation;
pub mod release;

use clap::{App, AppSettings};

fn args() -> App<'static, 'static> {
    App::new(env!("CARGO_PKG_NAME"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .version(env!("CARGO_PKG_VERSION"))
        .setting(AppSettings::SubcommandRequired)
        .subcommand(server::command())
        .subcommand(discover::command())
        .subcommand(starvation::command())
        .subcommand(release::command())
}

pub enum Arguments {
    Server(server::Arguments),
    Discover(discover::Arguments),
    Starvation(starvation::Arguments),
    Release(release::Arguments),
}

impl Arguments {
    pub fn parse_args() -> Self {
        let matches = args().get_matches();

        match matches.subcommand_name().unwrap() {
            name @ server::COMMAND_NAME => {
                return Arguments::Server(server::Arguments::parse(
                    matches.subcommand_matches(name).unwrap(),
                ))
            }
            name @ discover::COMMAND_NAME => {
                return Arguments::Discover(discover::Arguments::parse(
                    matches.subcommand_matches(name).unwrap(),
                ))
            }
            name @ starvation::COMMAND_NAME => {
                return Arguments::Starvation(starvation::Arguments::parse(
                    matches.subcommand_matches(name).unwrap(),
                ))
            }
            name @ release::COMMAND_NAME => {
                return Arguments::Release(release::Arguments::parse(
                    matches.subcommand_matches(name).unwrap(),
                ))
            }
            _ => unreachable!("Unknown command"),
        }
    }
}

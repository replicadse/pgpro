use std::{
    error::Error,
    fs::File,
    io::Read,
    path::Path,
    result::Result,
};

use crate::error::ArgumentError;

#[derive(Debug)]
pub struct CallArgs {
    pub privilege: Privilege,
    pub verbosity: bool,
    pub command: Command,
}

impl CallArgs {
    pub async fn validate(&self) -> Result<(), Box<dyn Error>> {
        match self.privilege {
            | Privilege::Normal => Ok(()),
            | Privilege::Experimental => Ok(()),
        }
    }
}

#[derive(Debug)]
pub enum Privilege {
    Normal,
    Experimental,
}

#[derive(Debug)]
pub enum Algorithm {
    RSA(u16),
}

#[derive(Debug)]
pub enum Command {
    GenerateKey {
        pass: String,
        owner: String,
        algo: Algorithm,
    },
    ListKeys,
    Encrypt {
        key: String,
        msg: String,
    },
    Decrypt {
        key: String,
        pass: String,
        msg: String,
    },
}

pub struct ClapArgumentLoader {}

impl ClapArgumentLoader {
    pub async fn load() -> Result<CallArgs, Box<dyn Error>> {
        let command = clap::App::new("pgpro")
            .version(env!("CARGO_PKG_VERSION"))
            .about("pgpro")
            .author("Weber, Heiko Alexander <haw@voidpointergroup.com>")
            .arg(
                clap::Arg::with_name("experimental")
                    .short("e")
                    .long("experimental")
                    .value_name("EXPERIMENTAL")
                    .help("Enables experimental features that do not count as stable.")
                    .required(false)
                    .takes_value(false),
            )
            .arg(
                clap::Arg::with_name("verbose")
                    .short("v")
                    .long("verbose")
                    .value_name("VERBOSE")
                    .help("Sets the verbosity.")
                    .multiple(false)
                    .required(false)
            )
            .subcommand(
                clap::App::new("generate-key")
                    .about("")
                    .arg(
                        clap::Arg::with_name("pass")
                            .short("p")
                            .long("pass")
                            .value_name("PASS")
                            .help("")
                            .default_value("")
                            .multiple(false)
                            .required(false)
                            .takes_value(true),
                    )
                    .arg(
                        clap::Arg::with_name("owner")
                            .short("o")
                            .long("owner")
                            .value_name("OWNER")
                            .help("")
                            .default_value("")
                            .multiple(false)
                            .required(false)
                            .takes_value(true),
                    ),
            )
            .subcommand(clap::App::new("list-keys").about(""))
            .subcommand(
                clap::App::new("encrypt")
                    .about("")
                    .arg(
                        clap::Arg::with_name("key")
                            .short("k")
                            .long("key")
                            .value_name("KEY")
                            .help("")
                            .multiple(false)
                            .required(false)
                            .takes_value(true),
                    )
                    .arg(
                        clap::Arg::with_name("message")
                            .short("m")
                            .long("message")
                            .value_name("MESSAGE")
                            .help("")
                            .multiple(false)
                            .required(false)
                            .takes_value(true),
                    ),
            )
            .subcommand(
                clap::App::new("decrypt")
                    .about("")
                    .arg(
                        clap::Arg::with_name("key")
                            .short("k")
                            .long("key")
                            .value_name("KEY")
                            .help("")
                            .multiple(false)
                            .required(false)
                            .takes_value(true),
                    )
                    .arg(
                        clap::Arg::with_name("pass")
                            .short("p")
                            .long("pass")
                            .value_name("PASS")
                            .help("")
                            .multiple(false)
                            .required(false)
                            .takes_value(true),
                    )
                    .arg(
                        clap::Arg::with_name("message")
                            .short("m")
                            .long("message")
                            .value_name("MESSAGE")
                            .help("")
                            .multiple(false)
                            .required(false)
                            .takes_value(true),
                    ),
            )
            .get_matches();

        let privilege = if command.is_present("experimental") {
            Privilege::Experimental
        } else {
            Privilege::Normal
        };

        let verbosity = command.is_present("verbose");

        fn load_arg<P: AsRef<Path>>(f: P) -> Result<String, Box<dyn Error>> {
            let mut file = File::open(f)?;
            let mut buf = String::new();
            file.read_to_string(&mut buf)?;
            Ok(buf)
        }

        let callargs = if let Some(sc) = command.subcommand_matches("generate-key") {
            Ok(CallArgs {
                privilege,
                verbosity,
                command: Command::GenerateKey {
                    pass: sc.value_of("pass").unwrap().to_owned(),
                    owner: sc.value_of("owner").unwrap().to_owned(),
                    algo: Algorithm::RSA(4096),
                },
            })
        } else if let Some(_) = command.subcommand_matches("list-keys") {
            Ok(CallArgs {
                privilege,
                verbosity,
                command: Command::ListKeys {},
            })
        } else if let Some(v) = command.subcommand_matches("encrypt") {
            Ok(CallArgs {
                privilege,
                verbosity,
                command: Command::Encrypt {
                    key: v.value_of("key").unwrap().to_owned(),
                    msg: load_arg(v.value_of("message").unwrap())?,
                },
            })
        } else if let Some(v) = command.subcommand_matches("decrypt") {
            Ok(CallArgs {
                privilege,
                verbosity,
                command: Command::Decrypt {
                    key: v.value_of("key").unwrap().to_owned(),
                    pass: load_arg(v.value_of("pass").unwrap())?,
                    msg: load_arg(v.value_of("message").unwrap())?,
                },
            })
        } else {
            Err(Box::new(ArgumentError::new("unrecognized subcommand")) as Box<dyn Error>)
        }
        .unwrap();

        callargs.validate().await?;
        Ok(callargs)
    }
}

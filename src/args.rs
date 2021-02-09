use std::{fmt::Display, fs::File, io::Read, path::Path, result::Result};
use std::error::Error;

use clap::{Arg, ArgMatches};

#[derive(Debug)]
struct ArgumentError {
    details: String,
}
impl ArgumentError {
    fn new(msg: &str) -> Self {
        Self {
            details: msg.to_owned()
        }
    }
}
impl Display for ArgumentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.details)
    }
}
impl Error for ArgumentError{}


pub struct CallArgs {
    pub privilege: Privilege,
    pub command: Command,
}

impl CallArgs {
    pub async fn validate(&self) -> Result<(), Box<dyn Error>> {
        match self.privilege {
            Privilege::Normal => Ok(()),
            Privilege::Experimental => Ok(()),
        }
    }
}

pub enum Privilege {
    Normal,
    Experimental,
}

pub enum Algorithm {
    RSA(u16),
}

pub enum Command {
    Generate {
        pass: Option<String>,
        owner: Option<String>,
        algo: Option<Algorithm>,
    },
    Encrypt {
        pass: Option<String>,
        msg: Option<String>,
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
            .subcommand(clap::App::new("generate")
                .about("")
                .arg(clap::Arg::with_name("pass")
                    .short("p")
                    .long("pass")
                    .value_name("PASS")
                    .help("")
                    .multiple(false)
                    .required(false)
                    .takes_value(true))
                .arg(clap::Arg::with_name("bytes")
                    .short("b")
                    .long("bytes")
                    .value_name("LENGTH")
                    .help("")
                    .multiple(false)
                    .required(false)
                    .takes_value(true))
                .arg(clap::Arg::with_name("algorithm")
                    .short("t")
                    .long("type")
                    .value_name("ALGORITHM")
                    .help("")
                    .multiple(false)
                    .required(false)
                    .takes_value(true))
                .arg(clap::Arg::with_name("owner")
                    .short("o")
                    .long("owner")
                    .value_name("OWNER")
                    .help("")
                    .multiple(false)
                    .required(false)
                    .takes_value(true))
            )
            .subcommand(clap::App::new("encrypt")
                .about("")
                .arg(clap::Arg::with_name("pass")
                    .short("p")
                    .long("pass")
                    .value_name("PASS")
                    .help("")
                    .multiple(false)
                    .required(false)
                    .takes_value(true))
                .arg(clap::Arg::with_name("message")
                    .short("m")
                    .long("message")
                    .value_name("MESSAGE")
                    .help("")
                    .multiple(false)
                    .required(false)
                    .takes_value(true))
            )
            .get_matches();

        let privilege = if command.is_present("experimental") {
            Privilege::Experimental
        } else {
            Privilege::Normal
        };

        let callargs = if let Some(args) = command.subcommand_matches("generate") {
            Ok(CallArgs {
                privilege,
                command: Command::Generate {
                    pass: Some(String::from("test")),
                    owner: Some(String::from("owner")),
                    algo: Some(Algorithm::RSA(2048)),
                },
            })
        }
        else if let Some(v) = command.subcommand_matches("encrypt") {
            fn load_arg<P: AsRef<Path>+std::fmt::Debug>(f: Option<P>) -> Result<Option<String>, Box<dyn Error>> {
                println!("{:?}", f);
                match f {
                    Some(v) => {
                        let mut file = File::open(v)?;
                        let mut buf = String::new();
                        file.read_to_string(&mut buf)?;
                        Ok(Some(buf))
                    },
                    None => Ok(None),
                }
            }

            Ok(CallArgs {
                privilege,
                command: Command::Encrypt {
                    pass: load_arg(v.value_of("pass"))?,
                    msg: load_arg(v.value_of("message"))?,
                },
            })
        } else {
            Err(Box::new(ArgumentError::new("unrecognized subcommand")) as Box<dyn Error>)
        }.unwrap();

        callargs.validate().await?;
        Ok(callargs)
    }
}

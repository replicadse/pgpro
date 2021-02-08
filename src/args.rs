use std::io::Result;

pub struct CallArgs {
    pub privileges: Privilege,
    pub command: Command,
}

impl CallArgs {
    pub async fn validate(&self) -> Result<()> {
        match self.privileges {
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
}

pub struct ClapArgumentLoader {}

impl ClapArgumentLoader {
    pub async fn load() -> std::io::Result<CallArgs> {
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
                    .default_value("")
                    .multiple(false)
                    .required(false)
                    .takes_value(true))
                .arg(clap::Arg::with_name("bytes")
                    .short("b")
                    .long("bytes")
                    .value_name("LENGTH")
                    .help("")
                    .default_value("4096")
                    .multiple(false)
                    .required(false)
                    .takes_value(true))
                .arg(clap::Arg::with_name("algorithm")
                    .short("t")
                    .long("type")
                    .value_name("ALGORITHM")
                    .help("")
                    .default_value("RSA")
                    .multiple(false)
                    .required(false)
                    .takes_value(true))
                .arg(clap::Arg::with_name("owner")
                    .short("o")
                    .long("owner")
                    .value_name("OWNER")
                    .help("")
                    .default_value("")
                    .multiple(false)
                    .required(false)
                    .takes_value(true))
            )
            .get_matches();

        let privileges = if command.is_present("experimental") {
            Privilege::Experimental
        } else {
            Privilege::Normal
        };

        let res = CallArgs {
            privileges,
            command: Command::Generate {
                pass: Some(String::from("test")),
                owner: Some(String::from("owner")),
                algo: Some(Algorithm::RSA(2048)),
            },
        };
        res.validate().await?;
        Ok(res)
    }
}

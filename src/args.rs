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

pub enum Command {
    Dummy,
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
            .get_matches();

        let privileges = if command.is_present("experimental") {
            Privilege::Experimental
        } else {
            Privilege::Normal
        };

        let res = CallArgs {
            privileges,
            command: Command::Dummy,
        };
        res.validate().await?;
        Ok(res)
    }
}

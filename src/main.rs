use futures::executor::block_on;
use std::error::Error;
use std::result::Result;

mod args;

async fn main_async() -> Result<(), Box<dyn Error>> {
    let cmd = args::ClapArgumentLoader::load().await?;
    match cmd.command {
        args::Command::Dummy => {
            print!("dummy");
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    block_on(main_async())
}

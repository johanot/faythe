
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate custom_error;


extern crate clap;


use std::fs::File;
use std::io::Read;
use std::thread;




#[derive(Deserialize)]
pub struct FaytheConfig {
    pub kubeconfig_path: String,
    pub secret_namespace: String,
    pub secret_hostlabel: String,
}


mod monitor;
mod issuer;
mod kube;
mod log;

custom_error!{ FaytheError
    StringConvertion{source: std::string::FromUtf8Error} = "string error",
    Deserialize{source: serde_json::Error} = "parse error",
    Exec{source: std::io::Error} = "exec error",
    Format = "format error",
}

fn main() -> Result<(), FaytheError> {

    let args = clap::App::new("faythe")
        .arg(clap::Arg::with_name("config")
            .value_name("config-file")
            .help("Path to Faythe config file (JSON)")
            .takes_value(true)
            .required(true))
         .arg(clap::Arg::with_name("config-check")
             .long("config-check")
             .help("Parses Faythe config file and exits")
             .takes_value(false)
             .required(false));

    let m = args.get_matches();
    let matches = match &m.value_of("config") {
        Some(m) => Ok(m),
        _ => Err(FaytheError::Format)
    }?.to_owned();

    let config = parse_config_file(&matches)?;
    run(config);
    Ok(())
}

fn run(config: FaytheConfig) {
    let monitor = thread::spawn(|| monitor::monitor_ingresses(config));
    let issuer = thread::spawn(|| issuer::process_queue());

    // if thread-join fails, we might as well just panic
    monitor.join();
    issuer.join();
}

fn parse_config_file(file: &str) -> Result<FaytheConfig, FaytheError> {
    let path = std::path::Path::new(&file);
    let mut file = File::open(path).unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();

    let c: serde_json::Result<FaytheConfig> = serde_json::from_str(&data);
    Ok(c?)
}


#[macro_use] extern crate serde_derive;
#[macro_use] extern crate custom_error;


extern crate clap;


use std::fs::File;
use std::io::Read;
use std::thread;

use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;

#[derive(Clone, Deserialize, Debug)]
pub struct FaytheConfig {
    pub kubeconfig_path: String,
    pub secret_namespace: String,
    pub secret_hostlabel: String,
    pub lets_encrypt_url: String,
    pub lets_encrypt_proxy: Option<String>,
    pub lets_encrypt_email: String,
    pub auth_dns_server: String,
    pub auth_dns_key: String,
    pub val_dns_servers: Vec<String>,
    pub auth_dns_zone: String,
    #[serde(default = "default_interval")]
    pub monitor_interval: u64,
    #[serde(default = "default_renewal_threshold")]
    pub renewal_threshold: u16,
    #[serde(default = "default_issue_grace")]
    pub issue_grace: u64,
    #[serde(default = "default_issue_wildcard_certs")]
    pub issue_wildcard_certs: bool,
    #[serde(default = "default_wildcard_cert_k8s_prefix")]
    pub wildcard_cert_k8s_prefix: String,
}

// millis (5 seconds)
fn default_interval() -> u64 {
    5 * 1000
}

// millis (1 hour)
fn default_issue_grace() -> u64 {
    60*60*1000
}

// days
fn default_renewal_threshold() -> u16 { 30 }

fn default_issue_wildcard_certs() -> bool { false }

fn default_wildcard_cert_k8s_prefix() -> String { "wild--card".to_string() }

mod monitor;
mod issuer;
mod kube;
mod log;
mod dns;

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
    let (tx, rx): (Sender<kube::Secret>, Receiver<kube::Secret>) = mpsc::channel();
    let monitor = thread::spawn(monitor::monitor(config.clone(), tx));
    let issuer = thread::spawn(move || { issuer::process(config.clone(), rx) });

    // if thread-join fails, we might as well just panic
    monitor.join().unwrap();
    issuer.join().unwrap();
}

fn parse_config_file(file: &str) -> Result<FaytheConfig, FaytheError> {
    let path = std::path::Path::new(&file);
    let mut file = File::open(path).unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();

    let c: serde_json::Result<FaytheConfig> = serde_json::from_str(&data);
    Ok(c?)
}

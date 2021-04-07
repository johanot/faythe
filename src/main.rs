#[macro_use] extern crate serde_derive;
#[macro_use] extern crate lazy_static;

extern crate clap;

use std::{thread, process};

use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;

use crate::common::CertSpec;
use crate::config::{FaytheConfig, ConfigContainer, MonitorConfig};

use dbc_rust_modules::{log, exec};

mod common;
mod config;
mod monitor;
mod issuer;
mod kube;
mod file;
mod dns;
mod metrics;

#[macro_export]
macro_rules! set {
    ( $( $x:expr ),* ) => {
        {
            let mut set = std::collections::HashSet::new();
            $(
                set.insert($x.to_string());
            )*
            set
        }
    };
}

fn main() {
    env_logger::init();
    let args = clap::App::new("faythe")
         .arg(clap::Arg::with_name("config-check")
             .long("config-check")
             .help("Parses Faythe config file and exits")
             .takes_value(false)
             .required(false))
         .arg(clap::Arg::with_name("config")
            .value_name("config-file")
            .help("Path to Faythe config file (JSON)")
            .takes_value(true)
            .required(true));

    let m = args.get_matches();
    let config_check = m.is_present("config-check");
    let config_file = m.value_of("config").unwrap().to_owned();
    let config = config::parse_config_file(&config_file);
    match config {
        Ok(c) => if !config_check { run(&c); },
        Err(e) => { eprintln!("config-file parse error: {}", &e); process::exit(1); }
    }
}

fn run(config: &FaytheConfig) {
    let (tx, rx): (Sender<CertSpec>, Receiver<CertSpec>) = mpsc::channel();

    let mut threads = Vec::new();
    for c in &config.kube_monitor_configs {
        let container = ConfigContainer{
            faythe_config: config.clone(),
            monitor_config: MonitorConfig::Kube(c.to_owned())
        };
        let tx_ = tx.clone();
        threads.push(thread::spawn(move || { monitor::monitor_k8s(container,tx_) }));
    }
    for c in &config.file_monitor_configs {
        let container = ConfigContainer{
            faythe_config: config.clone(),
            monitor_config: MonitorConfig::File(c.to_owned())
        };
        let tx_ = tx.clone();
        threads.push(thread::spawn(move || { monitor::monitor_files(container,tx_) }));
    }
    let config_ = config.clone();
    threads.push(thread::spawn(move || { issuer::process(config_, rx) }));

    if threads.len() < 2 {
        panic!("No monitors started! Did you forget to add monitor configuration to the config file?")
    }

    let metrics_port = config.metrics_port;
    metrics::serve(metrics_port);
    for t in threads {
        t.join().unwrap();
    }
}

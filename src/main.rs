#[macro_use] extern crate serde_derive;
#[macro_use] extern crate lazy_static;

extern crate clap;

use std::thread;

use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;

use crate::common::CertSpec;
use crate::config::{FaytheConfig, ConfigContainer, MonitorConfig};


mod common;
mod config;
mod exec;
mod monitor;
mod issuer;
mod kube;
mod log;
mod dns;

fn main() {

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
    let matches = m.value_of("config").unwrap().to_owned();
    let config = config::parse_config_file(&matches);
    run(&config);
}

fn run(config: &FaytheConfig) {
    let (tx, rx): (Sender<CertSpec>, Receiver<CertSpec>) = mpsc::channel();

    let mut threads = Vec::new();
    for c in &config.kube_monitor_configs {
        let container = ConfigContainer{
            faythe_config: config.clone(),
            monitor_config: MonitorConfig::Kube(c.to_owned())
        };
        threads.push(thread::spawn(monitor::monitor_k8s(container,tx.clone())));
    }
    let config_ = config.clone();
    threads.push(thread::spawn(move || { issuer::process(config_, rx) }));

    for t in threads {
        t.join().unwrap();
    }
}

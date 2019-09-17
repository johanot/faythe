
use std::thread;
use std::time::Duration;

use crate::{kube, FaytheConfig};
use crate::log;

use std::sync::mpsc::Receiver;

pub fn process_queue(config: FaytheConfig, rx: Receiver<kube::Secret>) -> impl FnOnce() {
    log::event("processing-started");
    move || loop {
        let secret = rx.recv().unwrap();
        println!("{}", &secret.name);


    }
}
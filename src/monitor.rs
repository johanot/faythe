
extern crate time;

use std::thread;
use std::time::Duration;

use crate::{kube, FaytheConfig};
use crate::log;

use std::io::Cursor;
use x509_parser::pem::Pem;
use std::result::Result;
use std::any::Any;

use std::collections::HashMap;
use std::sync::mpsc::Sender;

struct Entry {
    secret: kube::Secret,
    time: time::Tm,
}

trait ShouldRetry {
    fn should_retry(&self, config: &FaytheConfig) -> bool;
}

impl ShouldRetry for Option<&Entry> {
    fn should_retry(&self, config: &FaytheConfig) -> bool {
        let issue_time = match self {
            Some(entry) => entry.time,
            None => time::empty_tm()
        };
        time::now_utc() > issue_time + time::Duration::milliseconds(config.issue_grace as i64)
    }
}

pub fn monitor(config: FaytheConfig, tx: Sender<kube::Secret>) -> impl FnOnce() {
    move || {
        let mut process_queue = HashMap::new();

        log::event("monitoring-started");
        loop {
            let _ = || -> Result<Box<dyn Any>, kube::KubeError> {
                let ingresses = kube::get_ingresses()?;
                let secrets = kube::get_secrets(&config)?;

                for i in &ingresses {
                    for h in &i.hosts {
                        let s = &secrets[h];
                        if !is_valid(&config, s) {
                            if process_queue.get(h).should_retry(&config) {
                                &mut process_queue.insert(h.clone(), Entry{
                                    secret: s.clone(),
                                    time: time::now_utc()
                                });
                                println!("(re)-issuing: {}", h);
                                tx.send(s.clone()).unwrap();
                            }
                        }
                    }
                }
                Ok(Box::new(ingresses))
            }().or_else(|res: kube::KubeError| -> Result<Box<dyn Any>, kube::KubeError> {
                log::error("failed to talk to kube", &res);
                Err(res)
            });

            thread::sleep(Duration::from_millis(config.monitor_interval));
        }
    }
}

fn is_valid(config: &FaytheConfig, secret: &kube::Secret) -> bool {
    let reader = Cursor::new(&secret.cert);
    let (pem,_bytes_read) = Pem::read(reader).expect("Reading PEM failed");
    let x509 = pem.parse_x509().expect("X.509: decoding DER failed");
    let cert = x509.tbs_certificate;

    //TODO: check common name as well
    cert.validity.not_after.to_utc() > time::now_utc() + time::Duration::days(config.renewal_threshold as i64)
}

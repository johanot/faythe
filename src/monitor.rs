
extern crate time;

use std::thread;
use std::time::Duration;

use crate::{kube, FaytheConfig};
use crate::kube::K8SObject;
use crate::log;

use std::io::Cursor;
use x509_parser::pem::Pem;
use std::result::Result;
use std::any::Any;

use std::sync::mpsc::Sender;


trait ShouldRetry {
    fn should_retry(&self, config: &FaytheConfig) -> bool;
}

impl ShouldRetry for kube::Ingress {
    fn should_retry(&self, config: &FaytheConfig) -> bool {
        time::now_utc() > self.touched + time::Duration::milliseconds(config.issue_grace as i64)
    }
}

pub fn monitor(config: FaytheConfig, tx: Sender<kube::Secret>) -> impl FnOnce() {
    move || {
        log::event("monitoring-started");
        loop {
            let _ = || -> Result<Box<dyn Any>, kube::KubeError> {
                let ingresses = kube::get_ingresses(&config.auth_dns_zone)?;
                let secrets = kube::get_secrets(&config)?;

                for i in &ingresses {
                    if i.should_retry(&config) {
                        for h in &i.hosts {
                            secrets.get(h).and_then(|s| {
                                if !is_valid(&config, s) {
                                    println!("(re)-issuing: {}", h);
                                    match i.touch() {
                                        Ok(_) => tx.send(s.clone()).unwrap(),
                                        Err(e) => log::error("failed to annotate ingress, bailing out.", &e)
                                    };

                                }
                                Some(s)
                            });
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

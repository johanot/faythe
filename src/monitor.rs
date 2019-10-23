
extern crate time;

use std::thread;
use std::time::Duration;

use crate::{kube, FaytheConfig};
use crate::kube::{K8SObject, Secret};
use crate::log;

use std::io::Cursor;
use x509_parser::pem::Pem;
use std::result::Result;
use std::any::Any;

use std::sync::mpsc::Sender;
use core::fmt::Debug;
use acme_lib::persist::PersistKind::Certificate;


trait ShouldRetry {
    fn should_retry(&self, config: &FaytheConfig) -> bool;
}

impl ShouldRetry for kube::Ingress {
    fn should_retry(&self, config: &FaytheConfig) -> bool {
        time::now_utc() > self.touched + time::Duration::milliseconds(config.issue_grace as i64)
    }
}

pub trait Rewritable {
    fn rewrite_host(&self, config: &FaytheConfig) -> String;
    fn rewrite_k8s(&self, config: &FaytheConfig) -> String;
    fn rewrite_dns(&self, config: &FaytheConfig) -> String;
    fn rewrite(&self, config: &FaytheConfig, prefix: &String) -> String;
}

impl Rewritable for String {
    fn rewrite_host(&self, config: &FaytheConfig) -> String {
        self.rewrite(&config, &"*.".to_string())
    }
    fn rewrite_k8s(&self, config: &FaytheConfig) -> String {
        self.rewrite(&config, &format!("{}.", config.wildcard_cert_k8s_prefix))
    }
    fn rewrite_dns(&self, config: &FaytheConfig) -> String {
        self.rewrite(&config, &String::new())
    }
    fn rewrite(&self, config: &FaytheConfig, prefix: &String) -> String {
        let mut h = self.clone();
        if config.issue_wildcard_certs {
            let mut iter = h.split('.');
            let first = iter.next();
            if first.is_some() && first.unwrap() != prefix {
                let parts: Vec<&str> = iter.collect();
                h = format!("{prefix}{host}", prefix=prefix, host=parts.join("."))
            }
        }
        h
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
                            let s = secrets.get(&h.rewrite_k8s(&config))
                                .and_then(|s| Some(s.clone()))
                                .unwrap_or(kube::new_secret(&config, &h));

                            if !is_valid(&config, &s) {
                                println!("(re)-issuing: {}", &s.host);
                                match i.touch() {
                                    Ok(_) => tx.send(s).unwrap(),
                                    Err(e) => log::error("failed to annotate ingress, bailing out.", &e)
                                };

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
    // no cert, it's probably a first time issue
    if secret.cert.len() == 0 {
        //TODO: log::info perhaps?
        return false
    }

    let reader = Cursor::new(&secret.cert);
    match Pem::read(reader) {
        Ok((pem,_)) => match pem.parse_x509() {
            //TODO: check common name as well
            Ok(x509) => Ok(x509.tbs_certificate.validity.not_after.to_utc() > time::now_utc() + time::Duration::days(config.renewal_threshold as i64)),
            Err(e) => { log::error_debug("failed to parse x509 fields", &e); Err(()) }
        },
        Err(e) => { log::error_debug("failed to read pem-blob", &e); Err(()) }
    }.is_ok()
}

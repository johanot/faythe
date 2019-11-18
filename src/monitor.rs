
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

/*
    Hostname rewrite occurs _only_ if wildcard certificates are to be issued.
    If a certificate for "service.example.com" is wanted, Faythe should issue a cert for: "*.example.com".
    The Rewritable Trait (implemented below) swaps out the first part of the hostname, meaning "service." for "service.example.com"
    and replaces it with "something else". See detailed comments below.
*/
impl Rewritable for String {
    /*
        The certificate common name (CN) should contain "*.example.com"
        The same goes for the k8s secret label value, i.e.
        ingress.hostname = "*.example.com".
    */
    fn rewrite_host(&self, config: &FaytheConfig) -> String {
        self.rewrite(&config, &"*.".to_string())
    }
    /*
        Kubernetes object names must be DNS-compatible and thus cannot contain asterisks (*).
        config.wildcard_cert_k8s_prefix decides what to prefix k8s object names, the default being: "wild--card"
        a wildcard cert for example.com would then be named: "wild--card.example.com" in k8s.
    */
    fn rewrite_k8s(&self, config: &FaytheConfig) -> String {
        self.rewrite(&config, &format!("{}.", config.wildcard_cert_k8s_prefix))
    }
    /*
        Normally the DNS-record for challenges would be named: _acme-challenge.<domain>, e.g.
        "_acme-challenge.service.example.com".
        For wildcard certs, the challenge has to be placed one level up in the DNS-zone, i.e.
        _acme-challenge.example.com, hence "rewrite_dns" inserts a blank host-prefix.
    */
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
                            let s = secrets.get(&h.rewrite_host(&config))
                                .and_then(|s| Some(s.clone()))
                                .unwrap_or(kube::new_secret(&config, &h));

                            if !is_valid(&config, &s) {
                                log::info("(re-)issuing", (&s.host).into());

                                match i.touch() {
                                    Ok(_) => tx.send(s).unwrap(),
                                    Err(e) => log::error("failed to annotate ingress, bailing out.", (&e).into())
                                };

                            }
                        }
                    }
                }
                Ok(Box::new(ingresses))
            }().or_else(|res: kube::KubeError| -> Result<Box<dyn Any>, kube::KubeError> {
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
            Err(e) => { log::error("failed to parse x509 fields", (&e).into()); Err(()) }
        },
        Err(e) => { log::error("failed to read pem-blob", (&e).into()); Err(()) }
    }.is_ok()
}


extern crate time;

use std::thread;
use std::time::Duration;

use crate::{kube};
use crate::log;
use crate::config::ConfigContainer;

use std::result::Result;
use std::any::Any;

use std::sync::mpsc::Sender;

use crate::common::{CertSpec};
use std::collections::HashMap;
use crate::common::{CertSpecable, ValidityVerifier};

pub fn monitor_k8s(config: ConfigContainer, tx: Sender<CertSpec>) -> impl FnOnce() {
    move || {
        log::event("k8s monitoring-started");
        let monitor_config = config.get_kube_monitor_config().unwrap();
        loop {
            let _ = || -> Result<Box<dyn Any>, kube::KubeError> {
                let ingresses = kube::get_ingresses(&monitor_config)?;
                let secrets = kube::get_secrets(&monitor_config)?;

                inspect(&config, &tx, &ingresses, secrets);
                Ok(Box::new(()))
            }().or_else(|res: kube::KubeError| -> Result<Box<dyn Any>, kube::KubeError> {
                Err(res)
            });

            thread::sleep(Duration::from_millis(config.faythe_config.monitor_interval));
        }
    }
}

fn inspect<CS, VV>(config: &ConfigContainer, tx: &Sender<CertSpec>, objects: &Vec<CS>, certs: HashMap<String, VV>)
    where CS: CertSpecable, VV: ValidityVerifier {

    let faythe_config = &config.faythe_config;
    for o in objects {
        if o.should_retry(&faythe_config) {
            let maybe_spec = match certs.get(&o.get_raw_cn()) {
                Some(cert) => o.to_cert_spec(&config, cert.is_valid(&faythe_config)),
                None => o.to_cert_spec(&config, true)
            };

            match maybe_spec {
                Ok(cert_spec) => {
                    match o.touch(&config) {
                        Ok(_) => {
                            log::info("touched", &cert_spec.cn); //TODO: improve logging
                            if cert_spec.needs_issuing {
                                log::info("(re-)issuing", &cert_spec.cn); //TODO: improve logging
                                tx.send(cert_spec).unwrap()
                            }
                        },
                        Err(e) => log::error("failed to touch ingress, bailing out.", &e)
                    };
                },
                Err(e) => log::error("certspec invalid", &e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use crate::common;
    use crate::mpsc;
    use crate::mpsc::{Sender, Receiver};
    use crate::kube::Ingress;

    fn create_channel() -> (Sender<CertSpec>, Receiver<CertSpec>) {
        mpsc::channel()
    }

    fn create_ingress(host: &String) -> Vec<Ingress> {
        [Ingress{
            name: "test".to_string(),
            namespace: "test".to_string(),
            touched: time::empty_tm(),
            hosts: [host.clone()].to_vec(),
        }].to_vec()
    }

    #[test]
    fn test_normal_new_issue() {
        let host = String::from("host1.subdivision.unit.test");

        let config = common::create_test_config(false);
        let (tx, rx) = create_channel();
        let ingresses = create_ingress(&host);
        let secrets: HashMap<String, kube::Secret> = HashMap::new();
        let thread = thread::spawn(move || {
            inspect(&config,&tx, &ingresses, secrets)
        });

        let spec = rx.recv().unwrap();
        assert_eq!(spec.cn.to_domain_string(), host);
        thread.join().unwrap();
    }

    #[test]
    fn test_wildcard_new_issue() {
        let host = String::from("host1.subdivision.unit.test");

        let config = common::create_test_config(true);
        let (tx, rx) = create_channel();
        let ingresses = create_ingress(&host);
        let secrets: HashMap<String, kube::Secret> = HashMap::new();
        let thread = thread::spawn(move || {
            inspect(&config,&tx, &ingresses, secrets)
        });

        let spec = rx.recv().unwrap();
        assert_eq!(spec.cn.to_domain_string(), String::from("*.subdivision.unit.test"));
        thread.join().unwrap();
    }

    #[test]
    fn test_wildcard_host_in_ingress() {
        let host = String::from("*.subdivision.unit.test");

        let config = common::create_test_config(false);
        let (tx, rx) = create_channel();
        let ingresses = create_ingress(&host);
        let secrets: HashMap<String, kube::Secret> = HashMap::new();
        let thread = thread::spawn(move || {
            inspect(&config, &tx, &ingresses, secrets)
        });

        assert!(rx.recv().is_err()); // it is not allowed to ask for a wildcard cert in k8s ingress specs
        thread.join().unwrap();
    }

    #[test]
    fn test_non_authoritative_domain() {
        let host = String::from("host1.subdivision.unit.wrongtest");

        let config = common::create_test_config(false);
        let (tx, rx) = create_channel();
        let ingresses = create_ingress(&host);
        let secrets: HashMap<String, kube::Secret> = HashMap::new();
        let thread = thread::spawn(move || {
            inspect(&config, &tx, &ingresses, secrets)
        });

        assert!(rx.recv().is_err()); // faythe must know an authoritative ns server for the domain in question
        thread.join().unwrap();
    }
}

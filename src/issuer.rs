
use std::thread;
use std::time::Duration;

use crate::{dns, FaytheConfig, common};
use crate::log;

use std::sync::mpsc::{Receiver,TryRecvError};
use std::collections::VecDeque;

use acme_lib::{ClientConfig, Directory, DirectoryUrl, create_rsa_key};
use acme_lib::persist::MemoryPersist;

use crate::common::{CertSpec, Persistable, PersistError, DNSName};
use acme_lib::order::{Auth, NewOrder};
use std::prelude::v1::Vec;

use serde_json::json;
use std::convert::TryFrom;

pub fn process(faythe_config: FaytheConfig, rx: Receiver<CertSpec>) {
    log::event("processing-started");

    let mut queue: VecDeque<IssueOrder> = VecDeque::new();
    loop {
        let res = rx.try_recv();
        match res {
            Ok(cert_spec) => {
                if ! queue.iter().any(|o: &IssueOrder| o.spec.name == cert_spec.name) {
                    match setup_challenge(&faythe_config, &cert_spec) {
                        Ok(order) => queue.push_back(order),
                        Err(_) => log::event(format!("failed to setup challenge for host: {host}", host = cert_spec.cn).as_str())
                    };
                } else {
                    log::info("similar cert-spec is already in the issuing queue", &cert_spec)
                }
            },
            Err(TryRecvError::Disconnected) => panic!("channel disconnected"),
            Err(_) => {}
        }

        if check_queue(&faythe_config, &mut queue).is_err() {
            log::event("check queue err");
        }
        thread::sleep(Duration::from_millis(5000));
    }
}

fn check_queue(config: &FaytheConfig, queue: &mut VecDeque<IssueOrder>) -> Result<(), IssuerError> {
    match queue.pop_front() {
        Some(mut order) => {
            match validate_challenge(&config, &order) {
                Ok(_) => {
                    order.inner.refresh()?;
                    if order.inner.is_validated() {
                        order.issue()?;
                    } else {
                        queue.push_back(order);
                    }
                    Ok(())
                },
                Err(e) => match e {
                    IssuerError::DNSWrongAnswer(domain) => {
                        log::info("Wrong DNS answer", &domain);
                        // if now is less than 5 minutes since LE challenge request, put the order back on the queue for processing,
                        // otherwise: give up. 5 minutes is the apparent max validity for LE replay nonces anyway.
                        if time::now_utc() < order.challenge_time + time::Duration::minutes(5) {
                            queue.push_back(order);
                        } else {
                            log::info("giving up validating dns challenge for spec", &order.spec);
                        }
                        Ok(())
                    },
                        _ => Err(e)
                    }
            }
        },
        None => Ok(())
    }
}

fn validate_challenge(config: &FaytheConfig, order: &IssueOrder) -> Result<(), IssuerError> {

    for a in &order.authorizations {
        let domain = DNSName::try_from(&String::from(a.domain_name()))?;
        let challenge = a.dns_challenge();
        let proof = challenge.dns_proof();
        let log_data = json!({ "domain": &domain, "proof": &proof });

        log::info("Validating internally", &log_data);
        dns::query(&config.auth_dns_server, &domain, &proof)?;
        for d in &config.val_dns_servers {
            dns::query( &d, &domain, &proof)?;
        }
        log::info("Asking LE to validate", &log_data);
        challenge.validate(5000)?;
    }
    Ok(())
}

fn setup_challenge(config: &FaytheConfig, spec: &CertSpec) -> Result<IssueOrder, IssuerError> {

    // start by deleting any existing challenges here,
    // because we don't want to bother Let's encrypt and their rate limits,
    // in case we have trouble communicating with the NS-server or similar.
    dns::delete(&config, &spec)?;

    let persist = MemoryPersist::new();
    let url = DirectoryUrl::Other(&config.lets_encrypt_url);

    let cc = match &config.lets_encrypt_proxy {
        Some(proxy) => ClientConfig::with_proxy(proxy.clone()),
        None => ClientConfig::default()
    };
    let dir = Directory::from_url_with_config(persist, url, &cc)?;

    let acc = dir.account(&config.lets_encrypt_email)?;
    let ord_new = spec.to_acme_order(&acc)?;
    let authorizations = ord_new.authorizations()?;

    for a in &authorizations {
        // LE may require validation for only a subset of requested domains
        if a.need_challenge() {
            let challenge = a.dns_challenge();
            let domain = DNSName::try_from(&String::from(a.domain_name()))?;
            dns::add(&config, &domain, &challenge.dns_proof())?;
        }
    }

    Ok(IssueOrder{
        spec: spec.clone(),
        authorizations,
        inner: ord_new,
        challenge_time: time::now_utc(),
    })
}

struct IssueOrder {
    spec: CertSpec,
    inner: NewOrder<MemoryPersist>,
    authorizations: Vec<Auth<MemoryPersist>>,
    challenge_time: time::Tm,
}

impl IssueOrder {
    fn issue(&self) -> Result<(), IssuerError> {
        log::info("Issuing", &self.spec);

        let (pkey_pri, pkey_pub) = create_rsa_key(2048);
        let ord_csr = match self.inner.confirm_validations() {
            Some(csr) => Ok(csr),
            None => Err(IssuerError::ChallengeRejected)
        }?;

        let ord_cert =
            ord_csr.finalize_pkey(pkey_pri, pkey_pub, 5000)?;
        let cert = ord_cert.download_and_save_cert()?;

        Ok(self.spec.persist(cert)?)
    }
}

pub enum IssuerError {
    ConfigurationError,
    ChallengeRejected,
    AcmeClient,
    DNS,
    DNSWrongAnswer(String),
    PersistError
}

impl std::convert::From<dns::DNSError> for IssuerError {
    fn from(error: dns::DNSError) -> IssuerError {
        match error {
            dns::DNSError::WrongAnswer(domain) => IssuerError::DNSWrongAnswer(domain),
            _ => IssuerError::DNS
        }
    }
}

impl std::convert::From<PersistError> for IssuerError {
    fn from(_: PersistError) -> IssuerError {
        IssuerError::PersistError
    }
}

impl std::convert::From<acme_lib::Error> for IssuerError {
    fn from(_: acme_lib::Error) -> IssuerError {
        IssuerError::AcmeClient
    }
}

impl std::convert::From<common::SpecError> for IssuerError {
    fn from(_: common::SpecError) -> IssuerError {
        IssuerError::ConfigurationError
    }
}

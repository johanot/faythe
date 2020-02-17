
use std::thread;
use std::time::Duration;

use crate::{dns, FaytheConfig};
use crate::log;

use std::sync::mpsc::{Receiver,TryRecvError};
use std::collections::VecDeque;

use acme_lib::{ClientConfig, Directory, DirectoryUrl, create_rsa_key};
use acme_lib::persist::MemoryPersist;

use crate::common::{CertSpec, Persistable, PersistError, DNSName};

pub fn process(faythe_config: FaytheConfig, rx: Receiver<CertSpec>) {
    log::event("processing-started");

    let mut queue: VecDeque<IssueOrder> = VecDeque::new();
    loop {
        let res = rx.try_recv();
        match res {
            Ok(cert_spec) => {
                match setup_challenge(&faythe_config, &cert_spec) {
                    Ok(order) => queue.push_back(order),
                    Err(_) => log::event(format!("failed to setup challenge for host: {host}", host=cert_spec.cn).as_str())
                };
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
        Some(order) => {
            match validate_challenge(&config, &order) {
                Ok(_) =>  (order.issue)(),
                Err(e) => match e {
                    IssuerError::DNSWrongAnswer => {
                        log::info("Wrong DNS answer", &order.host);
                        // if now is less than 5 minutes since LE challenge request, put the order back on the queue for processing,
                        // otherwise: give up. 5 minutes is the apparent max validity for LE replay nonces anyway.
                        if time::now_utc() < order.challenge_time + time::Duration::minutes(5) {
                            queue.push_back(order);
                        } else {
                            log::event(&format!("giving up validating dns challenge for host: {}", &order.host));
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
    log::info("Validating", &order.host);

    dns::query(&config.auth_dns_server, &order.host, &order.proof)?;
    for d in &config.val_dns_servers {
        dns::query( &d, &order.host, &order.proof)?;
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
    let mut ord_new = spec.to_acme_order(&acc)?;

    let auths = ord_new.authorizations()?;
    if auths.len() > 0 {
        let challenge = auths[0].dns_challenge(); //TODO: sans
        let proof = challenge.dns_proof();

        //println!("please add this to dns: _acme-challenge.{} TXT {}", &secret.host, &secret.challenge);
        dns::add(&config, &spec, &proof)?;
        let spec_ = spec.clone();
        Ok(IssueOrder{
            host: spec.cn.clone(),
            proof: proof.clone(),
            challenge_time: time::now_utc(),
            issue: Box::new(move || -> Result<(), IssuerError> {
                log::info("challenge propagated", &spec_.cn);
                challenge.validate(5000)?;
                ord_new.refresh()?;
                log::info("challenge validated", &spec_.cn);

                let (pkey_pri, pkey_pub) = create_rsa_key(2048);
                let ord_csr = match ord_new.confirm_validations() {
                    Some(csr) => Ok(csr),
                    None => Err(IssuerError::ChallengeRejected)
                }?;

                let ord_cert =
                    ord_csr.finalize_pkey(pkey_pri, pkey_pub, 5000)?;
                let cert = ord_cert.download_and_save_cert()?;

                Ok(spec_.persist(cert)?)
            })
        })
    } else {
        Err(IssuerError::NoAuthorizationsForDomain)
    }
}


struct IssueOrder {
    host: DNSName,
    proof: String,
    challenge_time: time::Tm,
    issue: Box<dyn FnOnce() -> Result<(), IssuerError>>,
}

pub enum IssuerError {
    ChallengeRejected,
    AcmeClient,
    DNS,
    DNSWrongAnswer,
    NoAuthorizationsForDomain,
    PersistError
}

impl std::convert::From<dns::DNSError> for IssuerError {
    fn from(error: dns::DNSError) -> IssuerError {
        match error {
            dns::DNSError::WrongAnswer => IssuerError::DNSWrongAnswer,
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


use std::thread;
use std::time::Duration;

use crate::{kube, FaytheConfig};
use crate::log;

use std::sync::mpsc::{Receiver,TryRecvError};
use crate::kube::{Secret, Persistable};
use std::collections::VecDeque;

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::error::Error;
use x509_parser::objects::Nid::ChallengePassword;

use acme_lib::{Directory, DirectoryUrl, create_rsa_key};
use acme_lib::persist::{FilePersist, MemoryPersist};
use acme_lib::create_p384_key;

use std::fs::File;
use std::io::Read;

use crate::dns;
use crate::monitor::Rewritable;


pub fn process(config: FaytheConfig, rx: Receiver<kube::Secret>) {
    log::event("processing-started");

    let mut queue: VecDeque<IssueOrder> = VecDeque::new();
    loop {
        let res = rx.try_recv();
        match res {
            Ok(mut secret) => {
                match setup_challenge(&config, &mut secret) {
                    Ok(order) => queue.push_back(order),
                    Err(err) => log::event(&("failed to setup challenge for host: ".to_owned() + &secret.host))
                };
            },
            Err(TryRecvError::Disconnected) => panic!("channel disconnected"),
            Err(_) => {}
        }

        if check_queue(&config, &mut queue).is_err() {
            log::event("check queue err");
        }
        thread::sleep(Duration::from_millis(5000));
    }
}

fn check_queue(config: &FaytheConfig, queue: &mut VecDeque<IssueOrder>) -> Result<(), IssuerError> {
    match queue.pop_front() {
        Some(order) => {
            match validate_challenge(&config, &order) {
                Ok(_) =>  (order.issue)(&config),
                Err(e) => match e {
                    IssuerError::DNSWrongAnswer => {
                        println!("Wrong DNS answer: {}", &order.host);
                        queue.push_back(order);
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
    println!("Validating: {}", &order.host);

    dns::query(&config, &config.auth_dns_server, &order.host.rewrite_dns(&config), &order.challenge)?;
    dns::query(&config, &config.val_dns_server, &order.host.rewrite_dns(&config), &order.challenge)?;
    Ok(())
}

fn setup_challenge(config: &FaytheConfig, secret: &mut Secret) -> Result<IssueOrder, IssuerError> {

    // start by deleting any existing challenges here,
    // because we don't want to bother Let's encrypt and their rate limits,
    // in case we have trouble communicating with the NS-server or similar.
    dns::delete(&config, &secret)?;

    let persist = MemoryPersist::new();
    let url = DirectoryUrl::Other(&config.lets_encrypt_url);
    let dir = Directory::from_url(persist, url)?;

    let acc = dir.account(&config.lets_encrypt_email)?;
    let mut ord_new = acc.new_order(&secret.host, &[])?;

    let auths = ord_new.authorizations()?;
    if auths.len() > 0 {
        let challenge = auths[0].dns_challenge();
        secret.challenge = challenge.dns_proof();

        //println!("please add this to dns: _acme-challenge.{} TXT {}", &secret.host, &secret.challenge);
        dns::add(&config, &secret)?;
        let mut secret_ = secret.clone();
        Ok(IssueOrder{
            host: secret_.host.clone(),
            challenge: secret_.challenge.clone(),
            issue: Box::new(move |conf: &FaytheConfig| -> Result<(), IssuerError> {
                println!("challenge propagated!");
                challenge.validate(5000)?;
                ord_new.refresh()?;
                println!("challenge validated!");


                let (pkey_pri, pkey_pub) = create_rsa_key(2048);
                let ord_csr = match ord_new.confirm_validations() {
                    Some(csr) => Ok(csr),
                    None => Err(IssuerError::ChallengeRejected)
                }?;

                println!("issuing!");
                let ord_cert =
                    ord_csr.finalize_pkey(pkey_pri, pkey_pub, 5000)?;
                let cert = ord_cert.download_and_save_cert()?;

                secret_.cert = cert.certificate().as_bytes().to_vec();
                secret_.key = cert.private_key().as_bytes().to_vec();
                secret_.persist(&conf).unwrap();

                Ok(())
            })
        })
    } else {
        Err(IssuerError::NoAuthorizationsForDomain)
    }
}


struct IssueOrder {
    host: String,
    challenge: String,
    issue: Box<FnOnce(&FaytheConfig) -> Result<(), IssuerError>>
}

pub enum IssuerError {
    ChallengeRejected,
    AcmeClient,
    DNS,
    DNSWrongAnswer,
    NoAuthorizationsForDomain
}

impl std::convert::From<dns::DNSError> for IssuerError {
    fn from(error: dns::DNSError) -> IssuerError {
        match error {
            dns::DNSError::WrongAnswer => IssuerError::DNSWrongAnswer,
            _ => IssuerError::DNS
        }
    }
}

impl std::convert::From<acme_lib::Error> for IssuerError {
    fn from(error: acme_lib::Error) -> IssuerError {
        IssuerError::AcmeClient
    }
}


trait Challenger {
    fn ns_record(&self) -> String;
}

impl Challenger for Secret {
    fn ns_record(&self) -> String {
        String::from("_acme-challenge.") + &self.host
    }
}


use std::thread;
use std::time::Duration;

use crate::{kube, FaytheConfig};
use crate::log;

use std::sync::mpsc::{Receiver,TryRecvError};
use crate::kube::{Secret, Persistable};
use std::collections::VecDeque;

extern crate trust_dns;
extern crate trust_dns_resolver;
use trust_dns::client::{Client, ClientConnection, ClientStreamHandle, SyncClient};
use trust_dns::udp::UdpClientConnection;
use std::net::Ipv4Addr;
use std::str::FromStr;
use trust_dns::op::DnsResponse;
use trust_dns::rr::{DNSClass, Name, RData, Record, RecordType};
use std::error::Error;
use self::trust_dns::error::ClientError;
use x509_parser::objects::Nid::ChallengePassword;

use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;
use crate::issuer::IssuerError::DNSClient;

use acme_lib::{Directory, DirectoryUrl, create_rsa_key};
use acme_lib::persist::{FilePersist, MemoryPersist};
use acme_lib::create_p384_key;

use std::fs::File;
use std::io::Read;

use openssl::rsa::Rsa;
use trust_dns::rr::dnssec::{Algorithm, Signer, KeyPair};
use trust_dns::op::ResponseCode;
use trust_dns::rr::rdata::key::KEY;
use trust_dns::rr::rdata::txt::TXT;

use crate::nsupdate;


pub fn process(config: FaytheConfig, rx: Receiver<kube::Secret>) {
    log::event("processing-started");

    //let dns_client = dns_client(&config);
    //let lets_encrypt_account = auth(&config);
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

fn dns_client(server: &String) -> Result<SyncClient<UdpClientConnection>, IssuerError> {
    Ok(SyncClient::new(dns_connection(server)?))
}

fn dns_connection(server: &String) -> Result<UdpClientConnection, IssuerError> {
    let resolver = match Resolver::from_system_conf() {
        Ok(res) => Ok(res),
        _ => Err(IssuerError::DNSClient),
    }?;
    let response = resolver.lookup_ip(server)?;

    let address = match response.iter().next() {
        Some(a) => Ok(a),
        None => Err(IssuerError::DNSClient)
    }?;
    let parsed = format!("{}:53", address).parse()?;
    Ok(UdpClientConnection::new(parsed)?)
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
    let auth_client = dns_client(&config.auth_dns_server)?;
    let val_client = dns_client(&config.val_dns_server)?;

    let name = Name::from_str(&format!("_acme-challenge.{}", &order.host)).unwrap();

    println!("Validating: {}", &order.host);

    has_txt_record(&auth_client.query(&name, DNSClass::IN, RecordType::TXT)?, &order.challenge)?;
    //TODO: re-write dns validation checks to use exec("dig ..")
    //below check doesn't work - with the current impl
    //has_txt_record(&val_client.query(&name, DNSClass::IN, RecordType::TXT)?, &order.challenge)?;
    //sleep instead for now :(
    //240000 = 4 minutes of sleep, which seem to be a good compromise between ensuring DNS-propagation on one hand
    //while still making sure that the Lets encrypt replay nonce doesn't become invalid. (nonce validity = 5 minutes)
    thread::sleep(Duration::from_millis(240000));
    Ok(())
}

fn has_txt_record(response: &DnsResponse, expected: &String) -> Result<(), IssuerError>  {
    let answers: &[Record] = response.answers();
    if answers.len() < 1 {
        println!("Empty response");
        return Err(IssuerError::DNSWrongAnswer);
    }

    println!("Response: {}", &answers[0].rdata().or_empty());

    match &answers[0].rdata().or_empty() == expected {
        true => Ok(()),
        false => Err(IssuerError::DNSWrongAnswer)
    }
}

fn setup_challenge(config: &FaytheConfig, secret: &mut Secret) -> Result<IssueOrder, IssuerError> {

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
        nsupdate::update_dns(&config, &secret)?;
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
    NotReady,
    ChallengeRejected,
    AcmeClient,
    DNS,
    DNSClient,
    DNSWrongAnswer,
    NoAuthorizationsForDomain
}

trait OrEmpty {
    fn or_empty(self) -> String;
}

impl OrEmpty for &trust_dns::rr::RData {
    fn or_empty(self) -> String {
        match self {
            &RData::TXT(ref content) => {
                let txt = content.txt_data();
                if txt.len() > 0 {
                    let v = Vec::from(txt[0].clone());
                    String::from_utf8(v).unwrap_or(String::new())
                } else {
                    String::new()
                }
            }
            _ => String::new()
        }
    }
}

impl std::convert::From<std::net::AddrParseError> for IssuerError {
    fn from(error: std::net::AddrParseError) -> IssuerError {
        IssuerError::DNSClient
    }
}

impl std::convert::From<trust_dns_resolver::error::ResolveError> for IssuerError {
    fn from(error: trust_dns_resolver::error::ResolveError) -> IssuerError {
        IssuerError::DNSClient
    }
}

impl std::convert::From<ClientError> for IssuerError {
    fn from(error: ClientError) -> IssuerError {
        IssuerError::DNS
    }
}


impl std::convert::From<nsupdate::DNSError> for IssuerError {
    fn from(error: nsupdate::DNSError) -> IssuerError {
        IssuerError::DNS
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


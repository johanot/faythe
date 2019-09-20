
use std::thread;
use std::time::Duration;

use crate::{kube, FaytheConfig};
use crate::log;

use std::sync::mpsc::{Receiver,TryRecvError};
use acme_client::{Account, Directory};
use crate::kube::Secret;
use std::collections::VecDeque;

extern crate trust_dns;
use trust_dns::client::{Client, ClientConnection, ClientStreamHandle, SyncClient};
use trust_dns::udp::UdpClientConnection;
use std::net::Ipv4Addr;
use std::str::FromStr;
use trust_dns::op::DnsResponse;
use trust_dns::rr::{DNSClass, Name, RData, Record, RecordType};
use std::error::Error;
use self::trust_dns::error::ClientError;
use x509_parser::objects::Nid::ChallengePassword;


pub fn process(config: FaytheConfig, rx: Receiver<kube::Secret>) -> impl FnOnce() {
    log::event("processing-started");

    //let dns_client = dns_client(&config);
    let lets_encrypt_account = auth(&config);
    let mut queue: VecDeque<Secret> = VecDeque::new();
    move || loop {
        match rx.try_recv() {
            Ok(mut secret) => {
                match setup_challenge(&lets_encrypt_account, &mut secret) {
                    Ok(_) => queue.push_back(secret),
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

fn dns_client(server: &String) -> SyncClient<UdpClientConnection> {
    let address = "172.16.1.16:53".parse().unwrap();
    let conn = UdpClientConnection::new(address).unwrap();

    SyncClient::new(conn)
}


fn check_queue(config: &FaytheConfig, queue: &mut VecDeque<Secret>) -> Result<(), ChallengeError> {
    match queue.pop_front() {
        Some(secret) => {
            match validate_challenge(&config, &secret) {
                Ok(_) => issue_certificate(&secret),
                Err(e) =>
                    match e {
                        ChallengeError::DNSWrongAnswer => {
                            queue.push_back(secret);
                            Ok(())
                        }
                    } else {
                        Err(e)
                    }
                },
            }
        }
        None => Ok(())
    }
}

fn validate_challenge(config: &FaytheConfig, secret: &Secret) -> Result<(), ChallengeError> {
    println!("validate");

    let auth_client = dns_client(&config.auth_dns_server);
    let val_client = dns_client(&config.val_dns_server);

    let name = Name::from_str("dbc.dk").unwrap();

    let response: DnsResponse = auth_client.query(&name, DNSClass::IN, RecordType::TXT)?;
    has_txt_record(&response, &secret.challenge)
}

fn has_txt_record(response: &DnsResponse, expected: &String) -> Result<(), ChallengeError>  {
    let answers: &[Record] = response.answers();
    if answers.len() < 1 { return Err(ChallengeError::DNSWrongAnswer); }
    let content = match answers[0].rdata() {
        &RData::TXT(ref content) => {
            let v = Vec::from(content.txt_data()[0].clone());
            String::from_utf8(v).unwrap_or(String::new())
        },
        _ => String::new()
    };

    match &content == expected {
        true => Ok(()),
        false => Err(ChallengeError::DNSWrongAnswer)
    }
}


fn issue_certificate(secret: &Secret) -> Result<(), ChallengeError> {
    Ok(())
}

fn auth(config: &FaytheConfig) -> Account {
    let directory = Directory::from_url(&config.lets_encrypt_url).unwrap();
    directory.account_registration().register().unwrap()
}

fn setup_challenge(account: &Account, secret: &mut Secret) -> Result<(), ChallengeError> {
    // acme
    let authorization = account.authorization(&secret.host)?;
    let dns_challenge = match authorization.get_dns_challenge() {
        Some(c) => Ok(c),
        None => Err(ChallengeError::SetupChallenge)
    }?;
    secret.challenge = dns_challenge.signature()?;

    // dns
    println!("please add this to dns: _acme-challenge.{} TXT {}", &secret.host, &secret.challenge);
    Ok(())
}

enum ChallengeError {
    AcmeClient,
    SetupChallenge,
    DNS,
    DNSWrongAnswer,
}


impl std::convert::From<ClientError> for ChallengeError {
    fn from(error: ClientError) -> ChallengeError {
        ChallengeError::DNS
    }
}

impl std::convert::From<acme_client::error::Error> for ChallengeError {
    fn from(error: acme_client::error::Error) -> ChallengeError {
        ChallengeError::AcmeClient
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
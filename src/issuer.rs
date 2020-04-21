
use std::thread;
use std::time::Duration;

use crate::{dns, FaytheConfig, common};
use crate::log;

use std::sync::mpsc::{Receiver,TryRecvError};
use std::collections::{VecDeque, HashSet, HashMap};

use acme_lib::{ClientConfig, Directory, DirectoryUrl, create_rsa_key};
use acme_lib::persist::MemoryPersist;

use crate::common::{CertSpec, Persistable, PersistError, DNSName};
use acme_lib::order::{Auth, NewOrder};
use std::prelude::v1::Vec;

use serde_json::json;
use std::convert::TryFrom;
use trust_dns_resolver::Resolver;
use std::sync::RwLock;
use std::fmt::Debug;
use crate::dns::DNSError;

pub fn process(faythe_config: FaytheConfig, rx: Receiver<CertSpec>) {

    let mut queue: VecDeque<IssueOrder> = VecDeque::new();
    RESOLVERS.with(|r| r.write().unwrap().inner = init_resolvers(&faythe_config));

    log::event("processing-started");
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

        if check_queue(&mut queue).is_err() {
            log::event("check queue err");
        }
        thread::sleep(Duration::from_millis(5000));
    }
}

fn check_queue(queue: &mut VecDeque<IssueOrder>) -> Result<(), IssuerError> {
    match queue.pop_front() {
        Some(mut order) => {
            match validate_challenge(&order) {
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

fn validate_challenge(order: &IssueOrder) -> Result<(), IssuerError> {

    for a in &order.authorizations {
        let domain = DNSName::try_from(&String::from(a.domain_name()))?;
        let challenge = a.dns_challenge();
        let proof = challenge.dns_proof();
        let log_data = json!({ "domain": &domain, "proof": &proof });

        RESOLVERS.with(|r| -> Result<(), DNSError> {
            log::info("Validating internally", &log_data);
            for d in &order.auth_dns_servers {
                dns::query(r.read().unwrap().get(&d).unwrap(), &domain, &proof)?;
            }
            for d in &order.val_dns_servers {
                dns::query(r.read().unwrap().get(&d).unwrap(), &domain, &proof)?;
            }
            Ok(())
        })?;
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

    let auth_dns_servers = spec.get_auth_dns_servers(&config)?;
    let mut val_dns_servers = HashSet::new();
    for s in &config.val_dns_servers {
        val_dns_servers.insert(s.to_owned());
    }


    Ok(IssueOrder{
        spec: spec.clone(),
        authorizations,
        inner: ord_new,
        challenge_time: time::now_utc(),
        auth_dns_servers,
        val_dns_servers,
    })
}

struct IssueOrder {
    spec: CertSpec,
    inner: NewOrder<MemoryPersist>,
    authorizations: Vec<Auth<MemoryPersist>>,
    challenge_time: time::Tm,
    auth_dns_servers: HashSet<String>,
    val_dns_servers: HashSet<String>,
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

#[derive(Debug)]
enum ResolverError<'l> {
    SystemResolveConf,
    NoIpsForResolversFound(&'l String),
    Other
}

impl std::convert::From<std::io::Error> for ResolverError<'_> {
    fn from(_: std::io::Error) -> Self {
        ResolverError::Other
    }
}

thread_local! {
    static RESOLVERS: RwLock<Resolvers> = RwLock::new(Resolvers{
        inner: HashMap::with_capacity(0)
    });
}

struct Resolvers {
    inner: HashMap<String, Resolver>
}

impl Resolvers {
    fn get(&self, server: &String) -> Option<&Resolver> {
        self.inner.get(server)
    }
}

fn init_resolvers<'l>(config: &FaytheConfig) -> HashMap<String, Resolver> {
    use trust_dns_resolver::config::{ResolverConfig, NameServerConfigGroup, ResolverOpts};
    use trust_dns_resolver::error::ResolveErrorKind;
    use std::net::IpAddr;

    let mut resolvers = HashMap::new();

    let create_resolvers = |server: &String, resolvers: &mut HashMap<String, Resolver>| {

        match || -> Result<(), ResolverError> {
            let system_resolver = Resolver::from_system_conf().or(Err(ResolverError::SystemResolveConf))?;

            //try-parse what's in the config file as an ip-address, if that fails, assume it's a hostname that can be looked up
            let ip: IpAddr = match server.parse() {
                Ok(ip) => Ok(ip),
                Err(_) => {
                    match system_resolver.lookup_ip(server) {
                        Ok(res) => res.iter().next().ok_or(ResolverError::NoIpsForResolversFound(server)), // grabbing the first A record only for now
                        Err(err) => {
                            Err(match err.kind() {
                                ResolveErrorKind::NoRecordsFound { .. } => ResolverError::NoIpsForResolversFound(server),
                                _ => ResolverError::Other
                            })
                        }
                    }
                }
            }?;

            let mut conf = ResolverConfig::new();
            for c in &*NameServerConfigGroup::from_ips_clear(&[ip.to_owned()], 53) {
                conf.add_name_server(c.to_owned());
            }

            resolvers.insert(server.to_owned(), Resolver::new(conf, ResolverOpts::default())?);
            Ok(())
        }() {
            Err(e) => { log::error(format!("failed to init resolver for server: {}", &server).as_str(), &e); }
            _ => {}
        };
    };

    config.zones.iter().for_each(|(_, z)| create_resolvers(&z.server, &mut resolvers));
    config.val_dns_servers.iter().for_each(|s| create_resolvers(&s, &mut resolvers));
    resolvers
}
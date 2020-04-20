extern crate regex;
extern crate openssl;

use acme_lib::persist::Persist;
use acme_lib::order::NewOrder;
use acme_lib::{Account, Certificate};
use regex::Regex;
use crate::config::{FaytheConfig, ConfigContainer, Zone};
use crate::{file, kube, log};
use serde::export::Formatter;
use crate::kube::KubeError;
use std::convert::TryFrom;
use crate::file::FileError;
use std::path::PathBuf;
use self::openssl::x509::{X509, X509NameEntryRef};
use self::openssl::nid::Nid;
use self::openssl::asn1::Asn1TimeRef;
use std::collections::HashSet;

pub type CertName = String;

#[derive(Debug, Clone)]
pub struct CertSpec {
    pub name: CertName,
    pub cn: DNSName,
    pub sans: Vec<DNSName>,
    pub persist_spec: PersistSpec,
}

#[derive(Debug, Serialize, Clone)]
pub struct DNSName {
    pub name: String,
    pub is_wildcard: bool
}

impl std::convert::TryFrom<&String> for DNSName {
    type Error = SpecError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        lazy_static! {
            static ref RE: Regex = Regex::new("^(\\*\\.)?(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$").unwrap();
        }
        if RE.is_match(value) {
            Ok(DNSName{
                name: String::from(value.clone().trim_start_matches("*.")),
                is_wildcard: value.starts_with("*.")
            })
        } else {
            Err(SpecError::InvalidHostname)
        }
    }
}

impl DNSName {

    fn generic_checks<'l>(&self, config: &'l FaytheConfig) -> Result<&'l Zone, SpecError> {
        let zone: &'l Zone = self.find_zone(&config)?;
        if zone.issue_wildcard_certs && self.is_wildcard {
            return Err(SpecError::WildcardHostnameNotAllowedWithAutoWildcardIssuingEnabled)
        }
        Ok(zone)
    }

    // will return *.example.com for wildcard name: *.example.com
    pub fn to_domain_string(&self) -> String {
        self.to_string(true)
    }

    // will return example.com for wildcard name: *.example.com
    pub fn to_parent_domain_string(&self) -> String {
        self.to_string(false)
    }

    pub fn to_wildcard(&self) -> Result<DNSName, SpecError> {
        let mut iter = self.name.split('.');
        let first = iter.next();
        match first {
            Some(_) => {
                let parts: Vec<&str> = iter.collect();
                Ok(DNSName {
                    name: parts.join("."),
                    is_wildcard: true
                })
            },
            None => Err(SpecError::InvalidHostname)
        }
    }

    /*
        Ok, admitted, "find_zone" turned out to be quite an algorithm - sorry.
        Since Faythe now supports multiple authoritative zones, we might end up with authoritative zones like:
          1. k8s.dbc.dk
          2. dbc.dk

        Trouble is then to select the appropriate DNS-zone for challenge responses.
        The basic idea is to go backwards through zone fragments and name fragments until the best match is found.

        Examples:

        "foo.k8s.dbc.dk" gives a score of 3 for zone "k8s.dbc.dk" and score 2 for "dbc.dk" -> the former is selected
        "foo.dbc.dk" will not match "k8s.dbc.dk" and yield score 2 for "dbc.dk" -> the latter is selected
        "dk" will not match any of the zones.

        See test case "common::test_find_zone()" for more examples
    */
    pub fn find_zone<'l>(&self, config: &'l FaytheConfig) -> Result<&'l Zone, SpecError> {
        let domain_string = self.to_parent_domain_string();
        struct Match<'a> {
            zone: &'a Zone,
            score: i32,
        }
        let mut best_match = None::<Match>;
        for (name, zone) in &config.zones {
            let mut name_parts = domain_string.split('.');
            let mut zone_parts = name.split('.');
            let mut score= 0;
            while let Some(np) = name_parts.next_back() {
                match zone_parts.next_back() {
                    zp if zp.is_some() && zp.as_ref().unwrap() == &np => score += 1,  // the zone and the ns name has one matching name fraction; increment the score of this match by 1
                    None => {},                                                       // the zone name has no more parts left to check; this is all fine
                    _ => score = -30000                                               // the current zone name fraction doesn't match the corresponding name fraction, disregard zone as "no match" by setting the score very low
                }
            }
            if zone_parts.next_back().is_none() {
                if best_match.is_none() && score > 0 || best_match.is_some() && score > best_match.as_ref().unwrap().score {
                    best_match = Some(Match {
                        zone,
                        score
                    })
                }
            }
        }
        // if we haven't found at least one matching zone name by now, we can't honor the cert request, since we are not authoritative for the requested domain
        best_match.and_then(|m| Some(m.zone)).ok_or(SpecError::NonAuthoritativeDomain(self.clone()))
    }

    fn to_string(&self, include_asterisk: bool) -> String {
        if self.is_wildcard && include_asterisk {
            format!("*.{name}",name=self.name)
        } else {
            self.name.clone()
        }
    }
}

impl std::fmt::Display for DNSName {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.to_domain_string())
    }
}

impl CertSpec {
    pub fn to_acme_order<'l, P>(&self, acc: &Account<P>) -> Result<NewOrder<P>, acme_lib::Error> where P: Persist {
        let mut sans: Vec<String> = Vec::new();
        for s in &self.sans {
            sans.push(s.to_domain_string());
        }
        let sans_: Vec<&str> = sans.iter().map(|s| s.as_str()).collect();
        acc.new_order(&self.cn.to_domain_string().as_str(), sans_.as_slice())
    }
    pub fn get_auth_dns_servers(&self, config: &FaytheConfig) -> Result<HashSet<String>, SpecError> {
        let mut res = HashSet::new();
        res.insert(self.cn.find_zone(&config)?.server.clone());
        for s in &self.sans {
            res.insert(s.find_zone(&config)?.server.clone());
        }
        Ok(res)
    }
}

pub trait Persistable {
    fn persist(&self, cert: Certificate) -> Result<(), PersistError>;
}

#[derive(Debug, Clone)]
pub struct KubernetesPersistSpec {
    pub name: String,
    pub namespace: String,
    pub host_label_key: String,
    pub host_label_value: String
}

#[derive(Debug, Clone)]
pub struct FilePersistSpec {
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf
}

#[derive(Debug, Clone)]
pub enum PersistSpec {
    KUBERNETES(KubernetesPersistSpec),
    FILE(FilePersistSpec),
    #[allow(dead_code)]
    DONTPERSIST
}

impl Persistable for CertSpec {
    fn persist(&self, cert: Certificate) -> Result<(), PersistError> {
        match &self.persist_spec {
            PersistSpec::KUBERNETES(spec) => {
                Ok(kube::persist(&spec, &cert)?)
            }
            PersistSpec::FILE(spec) => {
                Ok(file::persist(&spec, &cert)?)
            }
            //PersistSpec::FILE(_spec) => { unimplemented!() },
            PersistSpec::DONTPERSIST => { Ok(()) }
        }
    }
}

impl std::convert::From<KubeError> for PersistError {
    fn from(err: KubeError) -> Self {
        PersistError::Kube(err)
    }
}

#[derive(Debug, Clone)]
pub struct Cert {
    pub cn: String,
    pub sans: Vec<String>,
    pub valid_from: time::Tm, // always utc
    pub valid_to: time::Tm // always utc
}

impl Cert {
    pub fn parse(pem_bytes: &Vec<u8>) -> Result<Cert, CertState> {
        if pem_bytes.len() == 0 {
            return Err(CertState::Empty)
        }

        match X509::from_pem(&pem_bytes) {
            Ok(x509) => {
                Ok(Cert {
                    cn: Self::get_cn(&x509)?,
                    sans: Self::get_sans(&x509),
                    valid_from: Self::get_timestamp(&x509.not_before())?,
                    valid_to: Self::get_timestamp(&x509.not_after())?
                })
            },
            Err(e) => {
                log::error("failed to parse pem-blob", &e);
                Err(CertState::ParseError)
            }
        }
    }

    fn get_cn(x509: &X509) -> Result<String, CertState> {
        match x509.subject_name().entries_by_nid(Nid::COMMONNAME).next() {
            Some(cn) => Ok(Self::get_string(cn)?),
            None => Err(CertState::ParseError)
        }
    }

    fn get_sans(x509: &X509) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if x509.subject_alt_names().is_some() {
            for n in x509.subject_alt_names().unwrap() {
                let dns_name = n.dnsname();
                if dns_name.is_some() { // ip sans etc. are not supported currently
                    out.push(String::from(dns_name.unwrap()))
                }
            }
        }
        out
    }

    fn get_string(name_ref: &X509NameEntryRef) -> Result<String, CertState> {
        match name_ref.data().as_utf8() {
            Ok(s) => Ok(s.to_string()),
            _ => Err(CertState::ParseError)
        }
    }

    // #cryhard rust openssl lib doesn't allow for a plain convertion from ASN-time to time::Tm or any
    // other rustlang time type. :( So... We to_string the ASNTime and re-parse it and hope for the best
    fn get_timestamp(time_ref: &Asn1TimeRef) -> Result<time::Tm, time::ParseError> {
        const IN_FORMAT: &str = "%b %e %H:%M:%S %Y %Z"; // May 31 15:21:16 2020 GMT
        time::strptime(&format!("{}", &time_ref), IN_FORMAT)
    }

    pub fn state(&self, config: &FaytheConfig) -> CertState {
        let now = time::now_utc();
        let state = match self.valid_to {
            to if now > to => CertState::Expired,
            to if now + time::Duration::days(config.renewal_threshold as i64) > to => CertState::ExpiresSoon,
            _ if now < self.valid_from => CertState::NotYetValid,
            to if now >= self.valid_from && now <= to => CertState::Valid,
            _ => CertState::Unknown,
        };
        log::info(&format!("State for cert: {}", &self.cn), &state);
        state
    }

    pub fn is_valid(&self, config: &FaytheConfig) -> bool {
        self.state(&config) == CertState::Valid
    }
}



pub enum PersistError {
    Kube(KubeError),
    File(FileError)
}

#[derive(Debug, Clone, PartialEq)]
pub enum CertState {
    Empty,
    ParseError,
    Expired,
    ExpiresSoon,
    NotYetValid,
    Valid,
    Unknown,
}

pub trait ValidityVerifier {
    fn is_valid(&self, config: &FaytheConfig) -> bool;
}

pub trait CertSpecable: IssueSource {
    fn to_cert_spec(&self, config: &ConfigContainer) -> Result<CertSpec, SpecError>;
    fn touch(&self, config: &ConfigContainer) -> Result<(), TouchError>;
    fn should_retry(&self, config: &ConfigContainer) -> bool;
    fn normalize(&self, config: &FaytheConfig) -> Result<DNSName, SpecError>  {
        let cn = self.get_cn()?;
        let sans = self.get_sans()?;
        let zone = cn.generic_checks(&config)?;
        if zone.issue_wildcard_certs && sans.len() > 0 {
            return Err(SpecError::SansNotSupportedWithAutoWildcardIssuingEnabled)
        }
        for s in sans {
            s.generic_checks(&config)?;
        }

        Ok(match zone.issue_wildcard_certs {
            true => cn.to_wildcard()?,
            false => cn
        })
    }
}

pub trait IssueSource {
    fn get_raw_cn(&self) -> String;
    fn get_raw_sans(&self) -> Vec<String>;
    fn get_cn(&self) -> Result<DNSName, SpecError> {
        DNSName::try_from(&self.get_raw_cn())
    }
    fn get_sans(&self) -> Result<Vec<DNSName>, SpecError> {
        let mut out = Vec::new();
        for s in &self.get_raw_sans() {
            out.push(DNSName::try_from(s)?)
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum SpecError {
    InvalidHostname,
    NonAuthoritativeDomain(DNSName),
    WildcardHostnameNotAllowedWithAutoWildcardIssuingEnabled,
    SansNotSupportedWithAutoWildcardIssuingEnabled,
    InvalidConfig
}

#[derive(Debug, Clone)]
pub enum TouchError {
    RecentlyTouched,
    Failed,
}

impl std::convert::From<SpecError> for TouchError {
    fn from(_: SpecError) -> Self {
        TouchError::Failed
    }
}

impl std::convert::From<time::ParseError> for CertState {
    fn from(_: time::ParseError) -> Self {
        CertState::ParseError
    }
}

#[cfg(test)]
pub fn create_test_config(issue_wildcard_certs: bool) -> ConfigContainer {
    use crate::config::{KubeMonitorConfig, MonitorConfig};
    use std::collections::HashMap;

    let kube_monitor_config = KubeMonitorConfig {
        secret_namespace: String::new(),
        secret_hostlabel: String::new(),
        touch_annotation: None,
        wildcard_cert_prefix: String::from("wild---card")
    };
    let mut zones = HashMap::new();
    zones.insert(String::from("unit.test"), Zone{
        server: String::from("ns.unit.test"),
        key: String::new(),
        challenge_suffix: None,
        issue_wildcard_certs
    });
    zones.insert(String::from("alternative.unit.test"), Zone{
        server: String::from("ns.alternative.unit.test"),
        key: String::new(),
        challenge_suffix: None,
        issue_wildcard_certs
    });
    zones.insert(String::from("suffixed.unit.test"), Zone{
        server: String::from("ns.suffixed.unit.test"),
        key: String::new(),
        challenge_suffix: Some(String::from("acme.example.com")),
        issue_wildcard_certs
    });
    let faythe_config = FaytheConfig{
        kube_monitor_configs: vec![kube_monitor_config.clone()],
        file_monitor_configs: vec![],
        lets_encrypt_url: String::new(),
        lets_encrypt_proxy: None,
        lets_encrypt_email: String::new(),
        val_dns_servers: Vec::new(),
        monitor_interval: 0,
        renewal_threshold: 30,
        issue_grace: 0,
        zones
    };

    ConfigContainer{
        faythe_config,
        monitor_config: MonitorConfig::Kube(kube_monitor_config)
    }
}

#[cfg(test)]
const TIME_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%z"; // 2019-10-09T11:50:22+0200

#[test]
fn test_valid_pem() {
    let bytes = include_bytes!("../test/longlived.pem");
    let cert = Cert::parse(&bytes.to_vec()).unwrap();

    assert_eq!(cert.cn, "cn.longlived");
    assert_eq!(cert.sans, vec!["san1.longlived", "san2.longlived"]);

    /*
        Not Before: Mar  3 12:09:22 2020 GMT
        Not After : Feb 24 12:09:22 2050 GMT
    */
    assert_eq!(cert.valid_from, time::strptime("2020-03-03T12:09:22+0000", TIME_FORMAT).unwrap());
    assert_eq!(cert.valid_to, time::strptime("2050-02-24T12:09:22+0000", TIME_FORMAT).unwrap());

    let config = create_test_config(false).faythe_config;
    assert_eq!(cert.state(&config), CertState::Valid);
    assert!(cert.is_valid(&config));
}

#[test]
fn test_expired_pem() {
    let bytes = include_bytes!("../test/expired.pem");
    let cert = Cert::parse(&bytes.to_vec()).unwrap();

    assert_eq!(cert.cn, "cn.expired");
    assert_eq!(cert.sans, vec!["san1.expired", "san2.expired"]);

    /*
        Not Before: Mar  3 13:18:46 2020 GMT
        Not After : Mar  4 13:18:46 2020 GMT
    */
    assert_eq!(cert.valid_from, time::strptime("2020-03-03T13:18:46+0000", TIME_FORMAT).unwrap());
    assert_eq!(cert.valid_to, time::strptime("2020-03-04T13:18:46+0000", TIME_FORMAT).unwrap());

    let config = create_test_config(false).faythe_config;
    assert!(cert.state(&config) == CertState::ExpiresSoon || cert.state(&config) == CertState::Expired);
    assert!(!cert.is_valid(&config));
}

#[test]
fn test_find_zone() {
    use crate::common;

    {
        let config = common::create_test_config(false);

        let host: DNSName = DNSName::try_from(&String::from("host1.subdivision.unit.wrongtest")).unwrap();
        let z = host.find_zone(&config.faythe_config);
        assert!(z.is_err());

        let host: DNSName = DNSName::try_from(&String::from("host1.subdivision.foo.test")).unwrap();
        let z = host.find_zone(&config.faythe_config);
        assert!(z.is_err());

        let host: DNSName = DNSName::try_from(&String::from("test")).unwrap();
        let z = host.find_zone(&config.faythe_config);
        assert!(z.is_err());

        let host: DNSName = DNSName::try_from(&String::from("google.com")).unwrap();
        let z = host.find_zone(&config.faythe_config);
        assert!(z.is_err());

        let host: DNSName = DNSName::try_from(&String::from("host1.subdivision.unit.test")).unwrap();
        let z = host.find_zone(&config.faythe_config);
        assert!(z.is_ok());
    }

    {
        let config = common::create_test_config(false);

        let host: DNSName = DNSName::try_from(&String::from("host1.subdivision.unit.test")).unwrap();
        let z = host.find_zone(&config.faythe_config).unwrap();
        assert_eq!(z.server, "ns.unit.test");

        let host: DNSName = DNSName::try_from(&String::from("host1.subdivision.alternative.unit.test")).unwrap();
        let z = host.find_zone(&config.faythe_config).unwrap();
        assert_eq!(z.server, "ns.alternative.unit.test");

        let host: DNSName = DNSName::try_from(&String::from("host1.subdivision.other-alternative.unit.test")).unwrap();
        let z = host.find_zone(&config.faythe_config).unwrap();
        assert_eq!(z.server, "ns.unit.test");

        let host: DNSName = DNSName::try_from(&String::from("unit.test")).unwrap();
        let z = host.find_zone(&config.faythe_config).unwrap();
        assert_eq!(z.server, "ns.unit.test");
    }
}
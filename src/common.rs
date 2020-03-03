extern crate regex;
extern crate openssl;

use acme_lib::persist::Persist;
use acme_lib::order::NewOrder;
use acme_lib::{Account, Certificate};
use regex::Regex;
use crate::config::{FaytheConfig, ConfigContainer};
use crate::log;
use serde::export::Formatter;
use crate::kube;
use crate::kube::KubeError;
use std::convert::TryFrom;
use crate::file;
use crate::file::FileError;
use std::path::PathBuf;
use self::openssl::x509::{X509, X509NameEntryRef};
use self::openssl::nid::Nid;
use self::openssl::asn1::Asn1TimeRef;

#[derive(Debug, Clone)]
pub struct CertSpec {
    pub cn: DNSName,
    pub sans: Vec<DNSName>,
    pub persist_spec: PersistSpec,
    pub needs_issuing: bool
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

    fn to_string(&self, include_asterisk: bool) -> String {
        if self.is_wildcard && include_asterisk {
            format!("*.{name}",name=self.name)
        } else {
            self.name.clone()
        }
    }

    pub fn has_suffix(&self, suffix: &String) -> bool {
        self.name.ends_with(suffix)
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
        match self.valid_to {
            to if now > to => CertState::Expired,
            to if now + time::Duration::days(config.renewal_threshold as i64) > to => CertState::ExpiresSoon,
            _ if now < self.valid_from => CertState::NotYetValid,
            to if now >= self.valid_from && now <= to => CertState::Valid,
            _ => CertState::Unknown,
        }
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
    fn to_cert_spec(&self, config: &ConfigContainer, needs_issuing: bool) -> Result<CertSpec, SpecError>;
    fn touch(&self, config: &ConfigContainer) -> Result<(), TouchError>;
    fn should_retry(&self, config: &ConfigContainer) -> bool;
    fn prerequisites(&self, config: &FaytheConfig) -> Result<DNSName, SpecError>  {
        let dns_name_ = DNSName::try_from(&self.get_raw_cn())?;
        if dns_name_.is_wildcard {
            return Err(SpecError::WildcardHostnameNotAllowed)
        }
        if ! dns_name_.has_suffix(&config.auth_dns_zone) {
            return Err(SpecError::NonAuthoritativeDomain)
        }

        Ok(match config.issue_wildcard_certs {
            true => dns_name_.to_wildcard()?,
            false => dns_name_
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

#[derive(Debug, Clone)]
pub enum SpecError {
    InvalidHostname,
    NonAuthoritativeDomain,
    WildcardHostnameNotAllowed,
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

    let kube_monitor_config = KubeMonitorConfig {
        secret_namespace: String::new(),
        secret_hostlabel: String::new(),
        touch_annotation: None,
        wildcard_cert_prefix: String::from("wild---card")
    };
    let faythe_config = FaytheConfig{
        kube_monitor_configs: vec![kube_monitor_config.clone()],
        file_monitor_configs: vec![],
        lets_encrypt_url: String::new(),
        lets_encrypt_proxy: None,
        lets_encrypt_email: String::new(),
        auth_dns_server: String::from("ns.unit.test"),
        auth_dns_key: String::new(),
        val_dns_servers: Vec::new(),
        auth_dns_zone: String::from("unit.test"),
        monitor_interval: 0,
        renewal_threshold: 0,
        issue_grace: 0,
        issue_wildcard_certs,
    };

    ConfigContainer{
        faythe_config,
        monitor_config: MonitorConfig::Kube(kube_monitor_config)
    }
}

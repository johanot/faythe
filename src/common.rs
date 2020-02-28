extern crate regex;

use acme_lib::persist::Persist;
use acme_lib::order::NewOrder;
use acme_lib::{Account, Certificate};
use regex::Regex;
use std::io::Cursor;
use crate::config::{FaytheConfig, ConfigContainer};
use crate::log;
use x509_parser::pem::Pem;
use serde::export::Formatter;
use crate::kube;
use crate::kube::KubeError;
use std::convert::TryFrom;
use crate::file;
use crate::file::FileError;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct CertSpec {
    pub cn: DNSName,
    pub sans: Vec<DNSName>,
    pub persist_spec: PersistSpec,
    pub needs_issuing: bool
}

#[derive(Debug, Clone)]
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
    pub fn to_acme_order<P>(&self, acc: &Account<P>) -> Result<NewOrder<P>, acme_lib::Error> where P: Persist {
        acc.new_order(&self.cn.to_domain_string().as_str(), &[])
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

pub type Cert = Vec<u8>;

pub fn is_valid(config: &FaytheConfig, cert: &Cert) -> Result<(), CertError> {
    // no cert, it's probably a first time issue
    if cert.len() == 0 {
        //TODO: log::info perhaps?
        return Err(CertError::Empty)
    }

    let reader = Cursor::new(&cert);
    match Pem::read(reader) {
        Ok((pem, _)) => match pem.parse_x509() {
            Ok(x509) => {
                if x509.tbs_certificate.validity.not_after.to_utc() > time::now_utc() + time::Duration::days(config.renewal_threshold as i64) {
                    Ok(())
                } else {
                    Err(CertError::Expired)
                }
            }
            Err(e) => {
                log::error("failed to parse x509 fields", &e);
                Err(CertError::Parse)
            }
        },
        Err(e) => {
            log::error("failed to read pem-blob", &e);
            Err(CertError::Parse)
        }
    }
}

pub enum PersistError {
    Kube(KubeError),
    File(FileError)
}

pub enum CertError {
    Empty,
    Parse,
    Expired,
    //MismatchingSpec //TODO: check common + sans names as well
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

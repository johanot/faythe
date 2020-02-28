extern crate time;

use crate::config::{FileMonitorConfig, FaytheConfig, ConfigContainer};
use std::collections::HashMap;
use crate::common::{ValidityVerifier, CertSpecable, CertSpec, SpecError, PersistSpec, TouchError, IssueSource, FilePersistSpec, Cert, PersistError};
use crate::common;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use acme_lib::Certificate;
use std::io::Write;
use std::io::Read;
use std::time::SystemTime;
use std::os::unix::fs::PermissionsExt;

pub fn read_certs(config: &FileMonitorConfig) -> Result<HashMap<String, FileCert>, FileError> {
    let mut certs = HashMap::new();
    for s in &config.specs {
        let names = default_file_names(&s);
        certs.insert(s.name.clone(), FileCert{
            cert: read_file(absolute_path(&config, &names.cert).as_path()).unwrap_or(vec![])
        });
    }
    Ok(certs)
}

fn default_file_names(spec: &FileSpec) -> FileNames {
    let cert = match &spec.cert_file_name {
        Some(n) => Some(n.clone()),
        None => Some(format!("{name}.pem",name=spec.name))
    }.unwrap();
    let key = match &spec.key_file_name {
        Some(n) => Some(n.clone()),
        None => Some(format!("{name}-key.pem",name=spec.name))
    }.unwrap();
    let meta = format!("{name}.faythe",name=cert);

    FileNames {
        cert,
        key,
        meta
    }
}

fn read_file(path: &Path) -> Result<Vec<u8>, FileError> {
    let mut data: Vec<u8> = Vec::new();
    let mut file = File::open(path)?;
    file.read(&mut data)?;
    Ok(data)
}

#[derive(Clone, Debug)]
pub struct FileCert {
    pub cert: Cert
}

impl ValidityVerifier for FileCert {
    fn is_valid(&self, config: &FaytheConfig) -> bool {
        common::is_valid(config, &self.cert).is_ok()
    }
}

#[derive(Clone, Deserialize, Debug)]
pub struct FileSpec {
    pub name: String,
    pub cn: String,
    #[serde(default)]
    pub sans: Vec<String>,
    #[serde(default)]
    pub cert_file_name: Option<String>,
    #[serde(default)]
    pub key_file_name: Option<String>,
}

impl IssueSource for FileSpec {
    fn get_raw_cn(&self) -> String {
        self.cn.clone()
    }
    fn get_raw_sans(&self) -> Vec<String> {
        self.sans.clone()
    }
}

impl CertSpecable for FileSpec {
    fn to_cert_spec(&self, config: &ConfigContainer, needs_issuing: bool) -> Result<CertSpec, SpecError> {
        self.prerequisites(&config.faythe_config)?;
        let monitor_config = config.get_file_monitor_config()?;
        let names = default_file_names(&self);
        Ok(CertSpec{
            cn: self.get_cn()?,
            sans: self.get_sans()?,
            persist_spec: PersistSpec::FILE(FilePersistSpec{
                private_key_path: absolute_path(&monitor_config, &names.key),
                public_key_path: absolute_path(&monitor_config,&names.cert),
            }),
            needs_issuing
        })
    }

    fn touch(&self, config: &ConfigContainer) -> Result<(), TouchError> {
        let names = default_file_names(&self);
        let file_path = absolute_path(config.get_file_monitor_config()?, &names.meta);
        let mut file = OpenOptions::new().append(true).create(true).open(file_path)?;
        file.flush()?;
        Ok(())
    }

    fn should_retry(&self, config: &ConfigContainer) -> bool {
        use std::time::Duration;

        match || -> Result<(), TouchError> {
            let monitor_config = config.get_file_monitor_config()?;
            let names = default_file_names(&self);
            let file = File::open(absolute_path(&monitor_config, &names.meta))?;
            let metadata = file.metadata()?;
            let modified = metadata.modified()?;
            let diff: Duration = SystemTime::now().duration_since(modified)?;
            match diff > Duration::from_millis(config.faythe_config.issue_grace as u64) {
                true => Ok(()),
                false => Err(TouchError::RecentlyTouched)
            }
        }() {
            Err(TouchError::RecentlyTouched) => false,
            _ => true,
        }
    }
}

fn absolute_path(config: &FileMonitorConfig, name: &String) -> PathBuf {
    Path::new(&config.directory).join(&name)
}

#[derive(Clone, Debug)]
struct FileNames {
    cert: String,
    key: String,
    meta: String
}

pub enum FileError {
    IO
}

pub fn persist(spec: &FilePersistSpec, cert: &Certificate) -> Result<(), PersistError> {
    let mut pub_file = File::create(&spec.public_key_path)?;
    let mut priv_file = File::create(&spec.private_key_path)?;
    let pub_buf = cert.certificate().as_bytes();
    let priv_buf = cert.private_key().as_bytes();
    pub_file.write_all(pub_buf)?;
    priv_file.write_all(priv_buf)?;
    let mut priv_permissions = priv_file.metadata()?.permissions();
    priv_permissions.set_mode(0o600); // rw-------
    Ok(())
}

impl std::convert::From<std::io::Error> for FileError {
    fn from(_: std::io::Error) -> Self {
        FileError::IO
    }
}

impl std::convert::From<std::io::Error> for PersistError {
    fn from(_: std::io::Error) -> Self {
        PersistError::File(FileError::IO)
    }
}

impl std::convert::From<std::io::Error> for TouchError {
    fn from(_: std::io::Error) -> Self {
        TouchError::Failed
    }
}

impl std::convert::From<std::time::SystemTimeError> for TouchError {
    fn from(_: std::time::SystemTimeError) -> Self {
        TouchError::Failed
    }
}

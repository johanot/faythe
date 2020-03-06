extern crate time;

use crate::config::{FileMonitorConfig, FaytheConfig, ConfigContainer};
use std::collections::{HashMap, HashSet};
use crate::common::{ValidityVerifier, CertSpecable, CertSpec, SpecError, PersistSpec, TouchError, IssueSource, FilePersistSpec, Cert, PersistError};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use acme_lib::Certificate;
use std::io::Write;
use std::io::Read;
use std::time::SystemTime;
use std::os::unix::fs::PermissionsExt;
use crate::log;
use std::fs;

pub fn read_certs(config: &FileMonitorConfig) -> Result<HashMap<String, FileCert>, FileError> {
    let mut certs = HashMap::new();
    let mut wanted_files = HashSet::new();
    for s in &config.specs {
        let names = default_file_names(&s);
        names.insert_into(&mut wanted_files);
        let raw = read_file(absolute_path(&config, &names.cert).as_path()).unwrap_or(vec![]);
        let cert = Cert::parse(&raw);
        if cert.is_ok() {
            certs.insert(s.name.clone(), FileCert{
                cert: cert.unwrap()
            });
        } else {
            log::info("dropping secret due to invalid cert", &names.cert);
        }
    }
    maybe_prune(&config, &wanted_files);
    Ok(certs)
}

fn maybe_prune(config: &FileMonitorConfig, wanted_files: &HashSet<String>) {
    if config.prune {
        match fs::read_dir(&config.directory) {
            Ok(dir) => {
                for entry_ in dir {
                    let file_name = match &entry_ {
                        Ok(e) => String::from(e.file_name().to_str().unwrap_or("")),
                        _ => String::new()
                    };
                    match || -> Result<Option<()>, std::io::Error> {
                        let entry = entry_?;
                        match entry.file_type() {
                            Ok(ft) => {
                                if ft.is_file() && !wanted_files.contains(&file_name) {
                                    fs::remove_file(&entry.path())?;
                                    Ok(Some(()))
                                } else {
                                    Ok(None)
                                }
                            },
                            Err(e) => Err(e)
                        }
                    }() {
                        Ok(Some(_)) => log::info("pruned file", &file_name),
                        Ok(None) => {},
                        Err(e) => log::error("failed to prune file", &format!("{:?}", &e))
                    }
                }
            },
            Err(e) => { log::error(&format!("failed to read dir: {}", &config.directory), &format!("{:?}", &e)); }
        }
    }
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
    file.read_to_end(&mut data)?;
    Ok(data)
}

#[derive(Clone, Debug)]
pub struct FileCert {
    pub cert: Cert
}

impl ValidityVerifier for FileCert {
    fn is_valid(&self, config: &FaytheConfig) -> bool {
        self.cert.is_valid(&config)
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
        let mut _file = OpenOptions::new().truncate(true).write(true).create(true).open(file_path)?;
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

impl FileNames {
    fn insert_into(&self, set: &mut HashSet<String>) {
        set.insert(self.cert.clone());
        set.insert(self.key.clone());
        set.insert(self.meta.clone());
    }
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
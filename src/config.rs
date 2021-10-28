

use std::fs::File;
use std::io::Read;
use std::prelude::v1::Vec;
use crate::file::FileSpec;
use crate::common::SpecError;
use std::collections::HashMap;
use std::path::PathBuf;
use serde::{Deserialize, Deserializer};

#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct FaytheConfig {
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
    pub lets_encrypt_url: String,
    pub lets_encrypt_proxy: Option<String>,
    pub lets_encrypt_email: String,
    pub zones: HashMap<String, Zone>,
    pub val_dns_servers: Vec<String>,
    #[serde(default = "default_interval")]
    pub monitor_interval: u64,
    #[serde(default = "default_renewal_threshold")]
    pub renewal_threshold: u16,
    #[serde(default = "default_issue_grace")]
    pub issue_grace: u64,
    #[serde(default)]
    pub kube_monitor_configs: Vec<KubeMonitorConfig>,
    #[serde(default)]
    pub file_monitor_configs: Vec<FileMonitorConfig>,
    pub vault: Option<VaultConfig>,
    #[serde(default = "default_secret_temp_path")]
    pub secret_temp_path: PathBuf,
}

#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    pub addr: String,
    pub app_role_env_file: PathBuf,
    #[serde(deserialize_with = "deserialize_trim_slashes")]
    pub kv_mount: String,
    #[serde(deserialize_with = "deserialize_trim_slashes")]
    pub kv_prefix: String,
}

fn deserialize_trim_slashes<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
     let raw: &str = Deserialize::deserialize(deserializer)?;
     Ok(raw.trim_matches('/').to_string())
}

#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct KubeMonitorConfig {
    pub secret_namespace: String,
    pub secret_hostlabel: String,
    #[serde(default = "default_wildcard_cert_k8s_prefix")]
    pub wildcard_cert_prefix: String,
    #[serde(default = "default_k8s_touch_annotation")]
    pub touch_annotation: Option<String>
}

#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct FileMonitorConfig {
    pub directory: String,
    pub specs: Vec<FileSpec>,
    pub prune: bool
}

pub enum MonitorConfig {
    Kube(KubeMonitorConfig),
    File(FileMonitorConfig)
}

pub struct ConfigContainer {
    pub faythe_config: FaytheConfig,
    pub monitor_config: MonitorConfig
}

#[derive(Clone, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Zone {
    pub server: String,
    pub key: String,
    pub challenge_suffix: Option<String>,
    #[serde(default = "default_issue_wildcard_certs")]
    pub issue_wildcard_certs: bool,
}

impl ConfigContainer {
    pub fn get_kube_monitor_config(&self) -> Result<&KubeMonitorConfig, SpecError> {
        Ok(match &self.monitor_config {
            MonitorConfig::Kube(c) => Ok(c),
            _ => Err(SpecError::InvalidConfig)
        }?)
    }
    pub fn get_file_monitor_config(&self) -> Result<&FileMonitorConfig, SpecError> {
        Ok(match &self.monitor_config {
            MonitorConfig::File(c) => Ok(c),
            _ => Err(SpecError::InvalidConfig)
        }?)
    }
}

// millis (5 seconds)
fn default_interval() -> u64 {
    5 * 1000
}

// millis (8 hours)
fn default_issue_grace() -> u64 {
    60*60*8000
}

// days
fn default_renewal_threshold() -> u16 { 30 }

fn default_issue_wildcard_certs() -> bool { false }

fn default_wildcard_cert_k8s_prefix() -> String { "wild--card".to_string() }

fn default_k8s_touch_annotation() -> Option<String> { Some("faythe.touched".to_string()) }

fn default_metrics_port() -> u16 { 9105 }

fn default_secret_temp_path() -> PathBuf { PathBuf::from("/tmp") } // to make backward-compatibility easier, but you should really use a memory-based mount

pub fn parse_config_file(file: &str) -> serde_json::Result<FaytheConfig> {
    let path = std::path::Path::new(&file);
    let mut file = File::open(path).unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();

    let c: serde_json::Result<FaytheConfig> = serde_json::from_str(&data);
    c
}

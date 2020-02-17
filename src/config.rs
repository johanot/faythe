

use std::fs::File;
use std::io::Read;

#[derive(Clone, Deserialize, Debug)]
pub struct FaytheConfig {
    pub kube_monitor_configs: Vec<KubeMonitorConfig>,
    pub lets_encrypt_url: String,
    pub lets_encrypt_proxy: Option<String>,
    pub lets_encrypt_email: String,
    pub auth_dns_server: String,
    pub auth_dns_key: String,
    pub val_dns_servers: Vec<String>,
    pub auth_dns_zone: String,
    #[serde(default = "default_interval")]
    pub monitor_interval: u64,
    #[serde(default = "default_renewal_threshold")]
    pub renewal_threshold: u16,
    #[serde(default = "default_issue_grace")]
    pub issue_grace: u64,
    #[serde(default = "default_issue_wildcard_certs")]
    pub issue_wildcard_certs: bool,
}

#[derive(Clone, Deserialize, Debug)]
pub struct KubeMonitorConfig {
    pub secret_namespace: String,
    pub secret_hostlabel: String,
    #[serde(default = "default_wildcard_cert_k8s_prefix")]
    pub wildcard_cert_prefix: String,
    #[serde(default = "default_k8s_touch_annotation")]
    pub touch_annotation: Option<String>
}

pub enum MonitorConfig {
    Kube(KubeMonitorConfig)
}

pub struct ConfigContainer {
    pub faythe_config: FaytheConfig,
    pub monitor_config: MonitorConfig
}

impl ConfigContainer {
    pub fn get_kube_monitor_config(&self) -> Result<&KubeMonitorConfig, ()> {
        Ok(match &self.monitor_config {
            MonitorConfig::Kube(c) => c,
        })
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

pub fn parse_config_file(file: &str) -> FaytheConfig {
    let path = std::path::Path::new(&file);
    let mut file = File::open(path).unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();

    let c: serde_json::Result<FaytheConfig> = serde_json::from_str(&data);
    c.unwrap()
}

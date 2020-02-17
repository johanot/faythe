
extern crate serde;
extern crate serde_json;
extern crate base64;
extern crate time;

use serde_json::{Value};
use serde_json::json;
use std::process::{Command, Stdio};
use std::result::Result;
use std::option::Option;
use crate::{FaytheConfig, exec};

use std::collections::HashMap;

use crate::exec::{SpawnOk, OpenStdin, Wait, ExecErrorInfo};
use crate::log;
use self::base64::DecodeError;
use crate::common::{is_valid, Cert, KubernetesPersistSpec, DNSName, IssueSource, ValidityVerifier};
use acme_lib::Certificate;

#[derive(Debug, Clone)]
pub struct Ingress {
    pub name: String,
    pub namespace: String,
    pub hosts: Vec<String>,
    pub touched: time::Tm,
}

#[derive(Debug, Clone)]
pub struct Secret {
    pub name: String,
    pub namespace: String,
    pub cert: Cert,
    pub key: Vec<u8>,
}

const TIME_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%z"; // 2019-10-09T11:50:22+0200

pub fn get_secrets(config: &FaytheConfig) -> Result<HashMap<String, Secret>, KubeError> {

    let v = kubectl(&["get", "secrets",
        "-l", config.secret_hostlabel.as_str(),
        "-n", config.secret_namespace.as_str()])?;


    let mut secrets = HashMap::new();
    for i in vec(&v["items"])? {
        let key = base64_decode(&i["data"]["key"])?;
        let cert = base64_decode(&i["data"]["cert"])?;
        let host = &i["metadata"]["labels"][&config.secret_hostlabel];
        secrets.insert(sr(host)?, Secret{
            name: sr(&i["metadata"]["name"])?,
            namespace: sr(&i["metadata"]["namespace"])?,
            cert,
            key
        });
    };

    Ok(secrets)
}

pub fn get_ingresses(config: &FaytheConfig) -> Result<Vec<Ingress>, KubeError> {
    let v = kubectl(&["get", "ingresses", "--all-namespaces"])?;

    let mut ingresses :Vec<Ingress> = Vec::new();
    for i in vec(&v["items"])? {
        let rules = vec(&i["spec"]["rules"])?;
        let touched = match &config.k8s_touch_annotation {
            Some(a) => tm(i["metadata"]["annotations"].get(&a)),
            None => time::empty_tm()
        };
        ingresses.push(Ingress{
            name: sr(&i["metadata"]["name"])?,
            namespace: sr(&i["metadata"]["namespace"])?,
            hosts: rules
                    .iter()
                    .map(|r| sr(&r["host"]).unwrap_or(String::new()))
                    .collect(),
            touched
        });
    };

    Ok(ingresses)
}

fn kubectl(args: &[&str]) -> Result<Value, KubeError> {
    let mut cmd = Command::new("kubectl");
    let mut child = cmd.args(args)
        .arg("-o")
        .arg("json")
        .spawn_ok()?;

    Ok(child.output_json()?)
}

fn kubectl_apply(args: &[&str], doc: &Value) -> Result<(), ExecErrorInfo> {
    let mut cmd = Command::new("kubectl");
    let mut child = cmd.arg("apply")
        .args(args)
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn_ok()?;

    {
        child.stdin_write(&format!("{}", doc))?;
    }

    child.wait()
}

fn vec(subject: &Value) -> Result<Vec<Value>, KubeError> {
    let a = subject.as_array();
    match a {
        Some(a) => Ok(a.to_vec()),
        _ => Err(KubeError::Format)
    }
}

fn sr(subject: &Value) -> Result<String, KubeError> {
    let a = subject.as_str();
    match a {
        Some(a) => Ok(String::from(a)),
        _ => Err(KubeError::Format)
    }
}

fn tm(subject: Option<&Value>) -> time::Tm {
    let a = subject.and_then(|s| s.as_str());
    match a {
        // assume "now" if there is something non-parsable in there
        Some(a) => time::strptime(&a, self::TIME_FORMAT).unwrap_or(time::now_utc()),
        _ => time::empty_tm()
    }
}

fn base64_decode(subject: &Value) -> Result<Vec<u8>, KubeError> {
    let s = match subject.as_str() {
        Some(s) => Ok(s),
        _ => Err(KubeError::Format)
    }?;
    Ok(base64::decode(&s)?)
}

fn base64_encode(subject: &Vec<u8>) -> String {
    base64::encode(&subject)
}

pub trait K8SAddressable {
    fn name(&self) -> String;
    fn namespace(&self) -> String;
    fn object(&self) -> String;
}

impl K8SAddressable for Ingress {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn namespace(&self) -> String {
        self.namespace.clone()
    }

    fn object(&self) -> String {
        String::from("ingress")
    }
}


pub trait K8SObject {
    fn touch(&self, config: &FaytheConfig) -> Result<(), KubeError>;
    fn annotate(&self, key: &String, value: &String) -> Result<(), KubeError>;
}

impl<T: K8SAddressable> K8SObject for T {
    fn touch(&self, config: &FaytheConfig) -> Result<(), KubeError> {
        match &config.k8s_touch_annotation {
            Some(a) => self.annotate(&a,
                                     &time::strftime(TIME_FORMAT, &time::now_utc())?),
            None => Ok(())
        }
    }

    fn annotate(&self, key: &String, value: &String) -> Result<(), KubeError> {
        kubectl(&[
            "annotate",
            "--overwrite",
            "-n", self.namespace().as_str(),
            self.object().as_str(),
            self.name().as_str(),
            format!("{}={}", key, value).as_str()  // la la no escape-args
        ]).and(Ok(()))
    }
}

pub fn persist_secret(persist_spec: &KubernetesPersistSpec, cert: &Certificate) -> Result<(), KubeError> {

    let doc = json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": &persist_spec.name,
                "namespace": &persist_spec.namespace,
                "labels": {
                    &persist_spec.host_label_key: &persist_spec.host_label_value
                }
            },
            "type": "Opaque",
            "data": {
                "cert": base64_encode(&cert.certificate().as_bytes().to_vec()),
                "key": base64_encode(&cert.private_key().as_bytes().to_vec())
            }
        });

    Ok(kubectl_apply(&[
        "-n",
        persist_spec.namespace.as_str()
    ], &doc)?)
}

impl ValidityVerifier for Secret {
    fn is_valid(&self, config: &FaytheConfig) -> bool {
        is_valid(&config, &self.cert).is_ok()
    }
}

impl IssueSource for Ingress {
    fn get_raw_cn(&self) -> String {
        // for now, we only support a single hostname in ingress resources
        self.hosts[0].clone()
    }

    fn get_raw_sans(&self) -> Vec<String> {
        unimplemented!()
    }
}

impl DNSName {
    pub fn to_kube_secret_name(&self, config: &FaytheConfig) -> String {
        if self.is_wildcard {
            format!("{prefix}.{host}",
                    prefix=config.wildcard_cert_k8s_prefix,
                    host=self.name)
        } else {
            self.name.clone()
        }
    }
}

#[derive(Debug)]
pub enum KubeError {
    Exec,
    Format
}

impl std::convert::From<exec::ExecErrorInfo> for KubeError {
    fn from(err: ExecErrorInfo) -> Self {
        log::error("Failed to exec kubectl command", (&err).to_log_data());
        KubeError::Exec
    }
}

impl std::convert::From<base64::DecodeError> for KubeError {
    fn from(err: DecodeError) -> Self {
        log::error("Failed to base64 decode secrets", &err);
        KubeError::Format
    }
}
impl std::convert::From<time::ParseError> for KubeError {
    fn from(err: time::ParseError) -> Self {
        log::error("Failed to parse timestamp", &err);
        KubeError::Format
    }
}
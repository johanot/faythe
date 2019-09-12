
extern crate serde;
extern crate serde_json;
extern crate base64;

use serde_json::{Value};
use std::process::Command;
use std::result::Result;
use crate::FaytheConfig;

use std::process::{Stdio};
use std::collections::HashMap;



pub struct Ingress {
    pub name: String,
    pub namespace: String,
    pub hosts: Vec<String>,
}

pub struct Secret {
    pub name: String,
    pub namespace: String,
    pub host: String,
    pub cert: Vec<u8>,
    key: Vec<u8>,
}

custom_error!{ pub KubeError
    StringConvertion{source: std::string::FromUtf8Error} = "string error",
    Deserialize{source: serde_json::Error} = "parse error",
    Exec{source: std::io::Error} = "exec error",
    Format = "format error",
    Base64Decode{source: base64::DecodeError} = "base64 decode"
}

pub fn get_secrets(config: &FaytheConfig) -> Result<HashMap<String, Secret>, KubeError> {

    let v = kubectl(&["get", "secrets",
        "-l", config.secret_hostlabel.as_str(),
        "-n", config.secret_namespace.as_str()])?;


    let mut secrets = HashMap::new();
    for i in vec(&v["items"])? {
        let key = base64_decode(&i["data"]["key"])?;
        let cert = base64_decode(&i["data"]["cert"])?;
        let host = &i["metadata"]["labels"][&config.secret_hostlabel];
        secrets.insert(host.to_string(), Secret{
            name: i["metadata"]["name"].to_string(),
            namespace: i["metadata"]["namespace"].to_string(),
            host: host.to_string(),
            cert,
            key
        });
    };

    Ok(secrets)
}

pub fn get_ingresses() -> Result<Vec<Ingress>, KubeError> {

    let v = kubectl(&["get", "ingresses", "--all-namespaces"])?;

    let mut ingresses :Vec<Ingress> = Vec::new();
    for i in vec(&v["items"])? {

        //TODO: Discard if no hostname is defined

        let rules = vec(&i["spec"]["rules"])?;
        ingresses.push(Ingress{
            name: i["metadata"]["name"].to_string(),
            namespace: i["metadata"]["namespace"].to_string(),
            hosts: rules.iter().map(|r| r["host"].to_string()).collect()
        });
    };

    Ok(ingresses)
}

fn kubectl(args: &[&str]) -> Result<Value, KubeError> {

    let cmd = Command::new("kubectl")
        .args(args)
        .arg("-o")
        .arg("json")
        .output()?;

    let v = serde_json::from_str(&String::from_utf8(cmd.stdout)?);
    Ok(v?)
}

fn vec(subject: &Value) -> Result<Vec<Value>, KubeError> {
    let a = subject.as_array();
    match a {
        Some(a) => Ok(a.to_vec()),
        _ => Err(KubeError::Format)
    }
}

fn sr(subject: &Value) -> Result<&str, KubeError> {
    let a = subject.as_str();
    match a {
        Some(a) => Ok(a),
        _ => Err(KubeError::Format)
    }
}

fn base64_decode(subject: &Value) -> Result<Vec<u8>, KubeError> {
    let s = match subject.as_str() {
        Some(s) => Ok(s),
        _ => Err(KubeError::Format)
    }?;
    Ok(base64::decode(&s)?)
}

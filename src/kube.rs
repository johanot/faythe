
extern crate serde;
extern crate serde_json;
extern crate base64;
extern crate time;

use serde_json::{Value};
use std::process::Command;
use std::result::Result;
use std::option::Option;
use crate::FaytheConfig;

use std::collections::HashMap;

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
    pub host: String,
    pub cert: Vec<u8>,
    key: Vec<u8>,
    pub challenge: String,
}

//TODO: get rid of this macro, I thought is was smart, I was wrong
custom_error!{ pub KubeError
    StringConvertion{source: std::string::FromUtf8Error} = "string error",
    Deserialize{source: serde_json::Error} = "parse error",
    Exec{source: std::io::Error} = "exec error",
    Format = "format error",
    Base64Decode{source: base64::DecodeError} = "base64 decode",
    ParseError{source: time::ParseError} = "failed to parse timestamp"
}

const TIME_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%z"; // 2019-10-09T11:50:22+0200
const TOUCH_ANNOTATION_NAME: &str = "faythe.touched";

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
            host: sr(host)?,
            challenge: String::new(),
            cert,
            key
        });
    };

    Ok(secrets)
}

pub fn get_ingresses(host_suffix: &String) -> Result<Vec<Ingress>, KubeError> {

    let v = kubectl(&["get", "ingresses", "--all-namespaces"])?;

    let mut ingresses :Vec<Ingress> = Vec::new();
    for i in vec(&v["items"])? {
        let rules = vec(&i["spec"]["rules"])?;
        ingresses.push(Ingress{
            name: sr(&i["metadata"]["name"])?,
            namespace: sr(&i["metadata"]["namespace"])?,
            hosts: rules
                    .iter()
                    .map(|r| sr(&r["host"]).unwrap_or(String::new()))
                    .filter(|h| h.ends_with(host_suffix))
                    .collect(),
            touched: tm(i["metadata"]["annotations"].get(TOUCH_ANNOTATION_NAME)),
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
    fn touch(&self) -> Result<(), KubeError>;
    fn annotate(&self, key: &String, value: &String) -> Result<(), KubeError>;
}

impl<T: K8SAddressable> K8SObject for T {
    fn touch(&self) -> Result<(), KubeError> {
         self.annotate(&TOUCH_ANNOTATION_NAME.to_string(),
                       &time::strftime(TIME_FORMAT, &time::now_utc())?)
    }

    fn annotate(&self, key: &String, value: &String) -> Result<(), KubeError> {
        kubectl(&[
            "annotate",
            "--overwrite",
            "-n", self.namespace().as_str(),
            self.object().as_str(),
            self.name().as_str(),
            format!("{}='{}'", key, value).as_str()  // la la no escape-args
        ]).and(Ok(()))
    }
}

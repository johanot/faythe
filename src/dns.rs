
use std::process::{Command, Stdio};
use std::result::Result;
use crate::FaytheConfig;

use std::convert::From;

use crate::exec::{SpawnOk, OpenStdin, Wait, ExecErrorInfo};
use crate::log;
use crate::common::{CertSpec, DNSName};

pub enum DNSError {
    Exec,
    OutputFormat,
    WrongAnswer
}

pub fn add(config: &FaytheConfig, spec: &CertSpec, proof: &String) -> Result<(), DNSError> {
    let command = add_cmd(&config, &spec, &proof);
    update_dns(&command, &config)
}

fn add_cmd(config: &FaytheConfig, spec: &CertSpec, proof: &String) -> String {
    format!("server {server}\n\
             prereq nxdomain {host} TXT\n\
             update add {host} 120 TXT \"{proof}\"\n\
             send\n",
            server=&config.auth_dns_server,
            host=&challenge_host(&spec.cn), //TODO: sans not supported so far
            proof=&proof)
}

pub fn delete(config: &FaytheConfig, spec: &CertSpec) -> Result<(), DNSError> {
    let command = delete_cmd(&config, &spec);
    update_dns(&command, &config)
}

fn delete_cmd(config: &FaytheConfig, spec: &CertSpec) -> String {
    format!("server {server}\n\
             update delete {host} TXT\n\
             send\n",
            server=&config.auth_dns_server,
            host=challenge_host(&spec.cn)) //TODO: sans not supported so far
}

pub fn query(server: &String, host: &DNSName, proof: &String) -> Result<(), DNSError> {
    let mut cmd = Command::new("dig");
    let mut child = cmd.arg(format!("@{}", server))
        .arg("+short")
        .arg("-t")
        .arg("TXT")
        .arg(challenge_host(host))
        .spawn_ok()?;

    let out = child.wait_for_output()?;
    let output = String::from_utf8(out.stdout)?;

    let trim_chars: &[_] = &['"', '\n'];
    match &output.trim_matches(trim_chars) == proof {
        true => Ok(()),
        false => Err(DNSError::WrongAnswer)
    }
}

fn challenge_host(host: &DNSName) -> String {
    format!("_acme-challenge.{}.", &host.to_parent_domain_string())
}

fn update_dns(command: &String, config: &FaytheConfig) -> Result<(), DNSError> {
    let mut cmd = Command::new("nsupdate");
    let mut child = cmd.arg("-k")
        .arg(&config.auth_dns_key)
        .stdin(Stdio::piped())
        .spawn_ok()?;
    {
        child.stdin_write(command)?;
    }

    Ok(child.wait()?)
}


impl From<std::io::Error> for DNSError {
    fn from(_: std::io::Error) -> DNSError {
        DNSError::Exec
    }
}

impl From<std::string::FromUtf8Error> for DNSError {
    fn from(_: std::string::FromUtf8Error) -> DNSError {
        DNSError::OutputFormat
    }
}

impl std::convert::From<ExecErrorInfo> for DNSError {
    fn from(err: ExecErrorInfo) -> Self {
        log::error("Failed to exec dns command", (&err).to_log_data());
        DNSError::Exec
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use crate::common::PersistSpec::DONTPERSIST;
    use std::convert::TryFrom;
    use crate::common;

    fn create_cert_spec(cn: &String) -> CertSpec {
        let dns_name = DNSName::try_from(cn).unwrap();
        CertSpec{
            cn: dns_name,
            sans: Vec::new(),
            persist_spec: DONTPERSIST,
            needs_issuing: false
        }
    }

    #[test]
    fn test_add_normal() {
        let config = common::create_test_config(false);
        let spec = create_cert_spec(&String::from("moo.unit.test"));
        let proof = String::from("abcdef1234");

        assert_eq!(add_cmd(&config.faythe_config, &spec, &proof),
                   "server ns.unit.test\nprereq nxdomain _acme-challenge.moo.unit.test. TXT\nupdate add _acme-challenge.moo.unit.test. 120 TXT \"abcdef1234\"\nsend\n")
    }

    #[test]
    fn test_add_wildcard() {
        let config = common::create_test_config(false);
        let spec = create_cert_spec(&String::from("*.unit.test"));
        let proof = String::from("abcdef1234");

        assert_eq!(add_cmd(&config.faythe_config, &spec, &proof),
                   "server ns.unit.test\nprereq nxdomain _acme-challenge.unit.test. TXT\nupdate add _acme-challenge.unit.test. 120 TXT \"abcdef1234\"\nsend\n")
    }

    #[test]
    fn test_delete_normal() {
        let config = common::create_test_config(false);
        let spec = create_cert_spec(&String::from("moo.unit.test"));
        assert_eq!(delete_cmd(&config.faythe_config, &spec),
                   "server ns.unit.test\nupdate delete _acme-challenge.moo.unit.test. TXT\nsend\n")
    }

    #[test]
    fn test_delete_wildcard() {
        let config = common::create_test_config(false);
        let spec = create_cert_spec(&String::from("*.unit.test"));

        assert_eq!(delete_cmd(&config.faythe_config, &spec),
                   "server ns.unit.test\nupdate delete _acme-challenge.unit.test. TXT\nsend\n")
    }
}

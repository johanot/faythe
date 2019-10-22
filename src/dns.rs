
use std::process::{ExitStatus, Command, Stdio};
use std::result::Result;
use crate::FaytheConfig;
use crate::kube::Secret;

use std::collections::HashMap;

use std::io::Write;

use std::convert::From;

pub enum DNSError {
    EXEC,
    EXITCODE(i32),
    OutputFormat,
    WrongAnswer
}

pub fn add(config: &FaytheConfig, secret: &Secret) -> Result<(), DNSError> {
    let host = challenge_host(&secret.host);
    let command = format!("server {server}\n\
                           prereq nxdomain {host} TXT\n\
                           update add {host} 120 TXT \"{challenge}\"\n\
                           send\n",
                          server=&config.auth_dns_server,
                          host=&host,
                          challenge=&secret.challenge);

    update_dns(&command, &config, &secret)
}

pub fn delete(config: &FaytheConfig, secret: &Secret) -> Result<(), DNSError> {
    let command = format!("server {server}\n\
                           update delete {host} TXT\n\
                           send\n",
                          server=&config.auth_dns_server,
                          host=challenge_host(&secret.host));

    update_dns(&command, &config, &secret)
}

pub fn query(server: &String, host: &String, challenge: &String) -> Result<(), DNSError> {
    let cmd = Command::new("dig")
        .arg(format!("@{}", server))
        .arg("+short")
        .arg("-t")
        .arg("TXT")
        .arg(challenge_host(&host))
        .output()?;

    let output = String::from_utf8(cmd.stdout)?;

    let trim_chars: &[_] = &['"', '\n'];
    match &output.trim_matches(trim_chars) == challenge {
        true => Ok(()),
        false => Err(DNSError::WrongAnswer)
    }
}

fn challenge_host(host: &String) -> String {
    format!("_acme-challenge.{}.", &host)
}

fn update_dns(command: &String, config: &FaytheConfig, secret: &Secret) -> Result<(), DNSError> {
    let mut child = Command::new("nsupdate")
        .arg("-k")
        .arg(&config.auth_dns_key)
        .stdin(Stdio::piped())
        .spawn()?;
    {
        let stdin = match child.stdin.as_mut() {
            Some(s) => Ok(s),
            None => Err(DNSError::EXEC)
        }?;
        stdin.write_all(command.as_bytes())?;
    }

    let status = child.wait()?;
    match status.code() {
        Some(code) => if code == 0 {
            Ok(())
        } else {
            Err(DNSError::EXITCODE(code))
        },
        None => Err(DNSError::EXEC)
    }
}


impl From<std::io::Error> for DNSError {
    fn from(error: std::io::Error) -> DNSError {
        DNSError::EXEC
    }
}

impl From<std::string::FromUtf8Error> for DNSError {
    fn from(error: std::string::FromUtf8Error) -> DNSError {
        DNSError::OutputFormat
    }
}

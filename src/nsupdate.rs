
use std::process::{ExitStatus, Command, Stdio};
use std::result::Result;
use crate::FaytheConfig;
use crate::kube::Secret;

use std::collections::HashMap;

use std::io::Write;

use std::convert::From;

pub enum DNSError {
    EXEC,
    EXITCODE(i32)
}

pub fn add(config: &FaytheConfig, secret: &Secret) -> Result<(), DNSError> {
    let host = challenge_host(&secret);
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
                          host=challenge_host(&secret));

    update_dns(&command, &config, &secret)
}

fn challenge_host(secret: &Secret) -> String {
    format!("_acme-challenge.{}.", &secret.host)
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


use std::process::{ExitStatus, Command, Stdio};
use std::result::Result;
use crate::FaytheConfig;
use crate::kube::Secret;

use std::collections::HashMap;

use std::io::Write;

use std::convert::From;
use crate::monitor::Rewritable;

use crate::exec::{SpawnOk, OpenStdin, Wait, ExecErrorInfo};
use crate::log;

pub enum DNSError {
    Exec,
    OutputFormat,
    WrongAnswer
}

pub fn add(config: &FaytheConfig, secret: &Secret) -> Result<(), DNSError> {
    let command = format!("server {server}\n\
                           prereq nxdomain {host} TXT\n\
                           update add {host} 120 TXT \"{challenge}\"\n\
                           send\n",
                          server=&config.auth_dns_server,
                          host=&challenge_host(&config, &secret.host),
                          challenge=&secret.challenge);

    update_dns(&command, &config, &secret)
}

pub fn delete(config: &FaytheConfig, secret: &Secret) -> Result<(), DNSError> {
    let command = format!("server {server}\n\
                           update delete {host} TXT\n\
                           send\n",
                          server=&config.auth_dns_server,
                          host=challenge_host(&config, &secret.host));

    update_dns(&command, &config, &secret)
}

pub fn query(config: &FaytheConfig, server: &String, host: &String, challenge: &String) -> Result<(), DNSError> {
    let mut cmd = Command::new("dig");
    let mut child = cmd.arg(format!("@{}", server))
        .arg("+short")
        .arg("-t")
        .arg("TXT")
        .arg(challenge_host(&config, &host))
        .spawn_ok()?;

    let out = child.wait_for_output()?;
    let output = String::from_utf8(out.stdout)?;

    let trim_chars: &[_] = &['"', '\n'];
    match &output.trim_matches(trim_chars) == challenge {
        true => Ok(()),
        false => Err(DNSError::WrongAnswer)
    }
}

fn challenge_host(config: &FaytheConfig, host: &String) -> String {
    format!("_acme-challenge.{}.", &host.rewrite_dns(&config))
}

fn update_dns(command: &String, config: &FaytheConfig, secret: &Secret) -> Result<(), DNSError> {
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
    fn from(error: std::io::Error) -> DNSError {
        DNSError::Exec
    }
}

impl From<std::string::FromUtf8Error> for DNSError {
    fn from(error: std::string::FromUtf8Error) -> DNSError {
        DNSError::OutputFormat
    }
}

impl std::convert::From<ExecErrorInfo> for DNSError {
    fn from(err: ExecErrorInfo) -> Self {
        log::error("Failed to exec dns command", (&err).to_log_data());
        DNSError::Exec
    }
}


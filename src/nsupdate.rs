
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


pub fn update_dns(config: &FaytheConfig, secret: &Secret) -> Result<(), DNSError> {
    let command = format!("server {}\n\
                           update add _acme-challenge.{}. 360 TXT \"{}\"\n\
                           send\n",
                          &config.auth_dns_server,
                          &secret.host,
                          &secret.challenge);

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

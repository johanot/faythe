use std::process::{Command, Child, Output};
use crate::log::LogLevel::ERROR;
use serde_json::Value;
use std::error::Error;
use serde::export::fmt::Debug;
use std::fmt;
use std::io::Write;
use std::io::Read;
use std::process::Stdio;
use serde::ser::{Serialize, SerializeStruct, Serializer};
use crate::log::LogData;


#[derive(Debug)]
pub struct CommandWrapped<'l> {
    command: &'l mut Command,
    child: Child
}

#[derive(Debug)]
pub struct ExecErrorInfo {
    error: Box<dyn Error>,
    trace: String,
    output: Option<Box<Output>>,
}

#[derive(Debug)]
pub enum ExecError {
    NonZeroExitCode(i32),
    UnknownExitStatus,
    FailedToOpenStdin,
    UnknownError
}

impl Serialize for ExecErrorInfo {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        let mut s = serializer.serialize_struct("ExecErrorInfo", 4)?;
        s.serialize_field("error", &format!("{}", &self.error))?;
        if !self.trace.is_empty() {
            println!("Not empty");
            s.serialize_field("trace", &self.trace)?;
        }
        if self.output.is_some() {
            let o = self.output.as_ref().unwrap();
            unsafe {
                s.serialize_field("stdout", &String::from_utf8_unchecked((*o.stdout).to_vec()))?;
                s.serialize_field("stderr", &String::from_utf8_unchecked((*o.stderr).to_vec()))?;
            }
        }
        s.end()
    }
}

impl std::error::Error for ExecErrorInfo {

}

impl std::error::Error for ExecError {

}

impl fmt::Display for ExecErrorInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error: {:?}", self.error)?;
        if !self.trace.is_empty() {
            Ok(write!(f, "trace: {}", self.trace)?)
        } else {
            Ok(())
        }
    }
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self)
    }
}

impl ExecErrorInfo {
    fn new<E, D>(err: E, trace: &D, output: Option<Box<Output>>) -> ExecErrorInfo where E: 'static + Error, D: Debug {
        ExecErrorInfo {
            error: Box::new(err),
            trace: format!("{:?}", &trace),
            output
        }
    }

    pub fn to_log_data(&self) -> LogData<&ExecErrorInfo> {
        LogData {
            data: Some(&self)
        }
    }
}

impl CommandWrapped<'_> {
    fn new<'l>(command: &'l mut Command, child: Child) -> CommandWrapped<'l> {
        CommandWrapped {
            command,
            child
        }
    }
}

pub trait SpawnOk {
    fn spawn_ok<'s>(&'s mut self) -> Result<CommandWrapped<'s>, ExecErrorInfo>;
}

impl SpawnOk for Command {
    fn spawn_ok<'s>(&'s mut self) -> Result<CommandWrapped<'s>, ExecErrorInfo> {
        self.stdout(Stdio::piped()).stderr(Stdio::piped());
        match self.spawn() {
            Ok(c) => Ok(CommandWrapped::new(self, c)),
            Err(err) => Err(ExecErrorInfo::new(err, &String::new(), None))
        }
    }
}

pub trait OpenStdin {
    fn stdin_write(&mut self, content: &String) -> Result<(), ExecErrorInfo>;
}

impl OpenStdin for CommandWrapped<'_> {
    fn stdin_write(&mut self, content: &String) -> Result<(), ExecErrorInfo> {
        let i = match self.child.stdin.as_mut() {
            Some(i) => Ok(i),
            None => Err(ExecErrorInfo::new(ExecError::FailedToOpenStdin, &content, None))
        }?;

        match i.write_all(content.as_bytes()) {
            Ok(_) =>  Ok(()),
            Err(e) => Err(ExecErrorInfo::new(e, &content, None))
        }
    }
}

pub trait Wait {
    fn wait(&mut self) -> Result<(), ExecErrorInfo>;
    fn wait_for_output(&mut self) -> Result<Output, ExecErrorInfo>;
    fn output_json(&mut self) -> Result<Value, ExecErrorInfo>;
}

impl Wait for CommandWrapped<'_> {
    fn wait(&mut self) -> Result<(), ExecErrorInfo> {
        self.wait_for_output().and(Ok(()))
    }

    fn wait_for_output(&mut self) -> Result<Output, ExecErrorInfo> {
        let output = wait_for_output_re_impl(&mut self.child);
        match output {
            Ok(out) => match out.status.code() {
                Some(code) => if code == 0 {
                        Ok(out)
                    } else {
                        Err(ExecErrorInfo::new(ExecError::NonZeroExitCode(code), &String::new(), Some(Box::new(out))))
                    },
                None => Err(ExecErrorInfo::new(ExecError::UnknownExitStatus, &String::new(), Some(Box::new(out))))
            },
            Err(err) => Err(ExecErrorInfo::new(ExecError::UnknownError, &format!("{:?}", err), None))
        }
    }

    fn output_json(&mut self) -> Result<Value, ExecErrorInfo> {
        let out = self.wait_for_output()?;
        //yuk memcopy below, but from_utf8() needs ownership, for some reason
        let s = match String::from_utf8(out.stdout.clone()) {
            Ok(s) => Ok(s),
            Err(e) => Err(ExecErrorInfo::new(e, &out, None))
        }?;
        match serde_json::from_str(&s) {
            Ok(s) => Ok(s),
            Err(e) => Err(ExecErrorInfo::new(e, &out, None))
        }
    }
}

/**
    Upstream "wait_with_output" takes ownership of "child", which is unacceptable
    Thus, we re-implement "wait_with_output" below. We should PR Rust stdlib.
*/
fn wait_for_output_re_impl(child: &mut Child) -> Result<Output, std::io::Error> {
    drop(child.stdin.take());

    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    match (child.stdout.take(), child.stderr.take()) {
        (None, None) => {}
        (Some(mut out), None) => {
            let res = out.read_to_end(&mut stdout);
            res.unwrap();
        }
        (None, Some(mut err)) => {
            let res = err.read_to_end(&mut stderr);
            res.unwrap();
        }
        (Some(mut out), Some(mut err)) => {
            let res1 = out.read_to_end(&mut stdout);
            res1.unwrap();
            let res2 = err.read_to_end(&mut stderr);
            res2.unwrap();
        }
    }

    let status = child.wait()?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}
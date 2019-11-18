
extern crate time;

use serde_json::json;
use core::fmt::Debug;
use serde::ser::{Serialize, SerializeStruct, Serializer};
use std::default::Default;
use crate::exec::ExecErrorInfo;

#[derive(Serialize, Debug)]
pub enum LogLevel {
    INFO,
    ERROR
}

struct LogEntry<'se, T> where T: Serialize {
    timestamp: time::Tm,
    app: &'se str,
    level: LogLevel,
    message: &'se str,
    data: LogData<T>
}

#[derive(Serialize)]
pub struct LogData<T> where T: Serialize {
    pub data: Option<T>
}

impl <'se, T>std::convert::From<&'se T> for LogData<String> where T: Debug {
    fn from(from: &'se T) -> Self {
        LogData{
            data: Some(format!("{:?}", from))
        }
    }
}

impl LogData<String> {
    fn none() -> LogData<String> {
        LogData{
            data: None
        }
    }
}


impl <T>Serialize for LogEntry<'_, T> where T: Serialize {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let mut s = serializer.serialize_struct("LogEntry", 5)?;
        //2016-07-25T17:22:40.835692521+02:00, 2016-07-25T17:22:40.835Z
        s.serialize_field("timestamp", &self.timestamp.rfc3339().to_string())?;
        s.serialize_field("app", &self.app)?;
        s.serialize_field("level", &self.level)?;
        s.serialize_field("message", &self.message)?;
        if self.data.data.is_some() {
            s.serialize_field("data", &self.data)?;
        }
        s.end()
    }
}

fn log<T>(level: LogLevel, message: &str, data: LogData<T>) where T: Serialize {
    println!("{}", serde_json::to_string(&LogEntry{
        app: &"faythe",
        timestamp: time::now_utc(),
        level, message, data
    }).unwrap());
}

pub fn event(msg: &str) {
    log(LogLevel::INFO, msg, LogData::none());
}

pub fn info<T>(msg: &str, data: LogData<T>) where T: Serialize {
    log(LogLevel::INFO, msg, data);
}

pub fn error<T>(msg: &str, err: LogData<T>) where T: Serialize {
    log(LogLevel::ERROR, msg, err);
}

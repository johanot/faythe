
use serde_json::json;
use crate::kube;

use core::fmt::Debug;

pub fn event(msg: &str) {
    println!("{}", json!({
        "type": "event",
        "message": msg,
    }));
}

pub fn error(msg: &str, err: &kube::KubeError) {
    println!("{}", json!({
        "type": "error",
        "message": msg,
        "error": format!("{}", err)
    }));
}

//TODO: this is part of "new smarter generic error logging"(tm), rename this function when logging is refactored for realz
pub fn error_debug<T>(msg: &str, err: &T) where T: Debug {
    println!("{}", json!({
        "type": "error",
        "message": msg,
        "error": format!("{:?}", err)
    }));
}


use serde_json::json;
use crate::kube;

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

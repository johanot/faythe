
use serde_json::json;

pub fn event(msg: &str) {
    println!("{}", json!({
        "type": "event",
        "message": msg,
    }));
}

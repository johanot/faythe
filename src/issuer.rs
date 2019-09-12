
use std::thread;
use std::time::Duration;

use crate::log;


pub fn process_queue() {
    log::event("processing-started");
    thread::sleep(Duration::from_millis(10000));
}
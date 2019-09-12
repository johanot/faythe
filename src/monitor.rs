
extern crate time;

use std::thread;
use std::time::Duration;

use crate::{kube, FaytheConfig};
use crate::log;

use std::io::Cursor;
use x509_parser::pem::Pem;




pub fn monitor_ingresses(config: FaytheConfig) {
    log::event("monitoring-started");
    loop {
        let ingresses = kube::get_ingresses().unwrap();
        let secrets = kube::get_secrets(&config).unwrap();
        for i in &ingresses {
            for h in &i.hosts {
                println!("{}", &h);
                let s = &secrets[h];
                if !is_valid(s) {
                    println!("cert invalid");
                }
            }
        }
        thread::sleep(Duration::from_millis(10000));
    }
}

fn is_valid(secret: &kube::Secret) -> bool {
    let reader = Cursor::new(&secret.cert);
    let (pem,bytes_read) = Pem::read(reader).expect("Reading PEM failed");
    let x509 = pem.parse_x509().expect("X.509: decoding DER failed");
    let cert = x509.tbs_certificate;

    //TODO: check common name as well
    cert.validity.not_after.to_utc() > time::now_utc()
}

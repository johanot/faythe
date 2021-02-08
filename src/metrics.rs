
extern crate prometheus_exporter_base;

use prometheus_exporter_base::{render_prometheus, MetricType, PrometheusMetric};

use std::collections::HashMap;
use std::sync::RwLock;

use crate::log;

#[derive(Debug, Clone, Default)]
struct MyOptions {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MetricsType {
  Success,
  Failure,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MetricsEvent {
  pub cert_name: String,
  pub event_type: MetricsType,
}

lazy_static! {
  static ref EVENTS: RwLock<HashMap<MetricsEvent, u64>> = RwLock::new(HashMap::new());
}

pub fn new_event(cert_name: &str, event_type: MetricsType) {
  let event = MetricsEvent{
    cert_name: cert_name.to_string(),
    event_type,
  };
  let mut guard = EVENTS.write().unwrap();
  let new_value = match guard.remove(&event) {
    Some(old_value) => old_value+1,
    None => 1
  };
  guard.insert(event, new_value);
}

#[tokio::main]
pub async fn serve(port: u16) {
  let addr = ([0, 0, 0, 0], port).into();
  log::event(&format!("starting metrics server on port: {}", port));

  render_prometheus(addr, MyOptions::default(), |_request, _options| {
    async move {
        let successes = PrometheusMetric::new("faythe_issue_successes", MetricType::Counter, "Successfully issued certificates");
        let failures = PrometheusMetric::new("faythe_issue_failures", MetricType::Counter, "Failed certificate issue attempts");
        let mut s = successes.render_header();
        let mut f = failures.render_header();

        for (event, count) in EVENTS.read().unwrap().iter() {
            let attributes = vec!(("cert_name", event.cert_name.as_str()));
            let sample = match &event.event_type {
              MetricsType::Success => &successes,
              MetricsType::Failure => &failures,
            }.render_sample(Some(&attributes[..]), count.to_owned(), None);
            match &event.event_type {
              MetricsType::Success => &mut s,
              MetricsType::Failure => &mut f,
            }.push_str(&sample);
        }

        Ok(format!("{}\n{}", s, f))
    }
  }).await;
}

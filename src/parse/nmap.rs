//! nmap XML (-oX) parser. We standardise on XML because it is the one nmap
//! output format that is unambiguous to machine-read.

use crate::model::{Host, PortState, Service};
use anyhow::{Context, Result};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::BTreeMap;

fn attr(e: &quick_xml::events::BytesStart, key: &[u8]) -> Option<String> {
    let a = e.attributes().flatten().find(|a| a.key.as_ref() == key)?;
    // Decode XML entities (&#10; &amp; &quot; ...) that nmap packs into script output.
    match a.unescape_value() {
        Ok(v) => Some(v.into_owned()),
        Err(_) => Some(String::from_utf8_lossy(&a.value).into_owned()),
    }
}

/// Parse nmap -oX output into a list of hosts.
pub fn parse_nmap_xml(xml: &str) -> Result<Vec<Host>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut hosts = vec![];
    let mut cur: Option<Host> = None;
    let mut cur_svc: Option<Service> = None;
    // Are we inside <hostscript> (vs a <port>)?
    let mut in_hostscript = false;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf).context("nmap xml read")? {
            Event::Start(e) | Event::Empty(e) => match e.name().as_ref() {
                b"host" => cur = Some(Host::new("")),
                b"address" => {
                    if attr(&e, b"addrtype").as_deref() == Some("ipv4") {
                        if let (Some(h), Some(ip)) = (cur.as_mut(), attr(&e, b"addr")) {
                            h.ip = ip;
                        }
                    }
                }
                b"hostname" => {
                    if let (Some(h), Some(n)) = (cur.as_mut(), attr(&e, b"name")) {
                        if !h.hostnames.contains(&n) {
                            h.hostnames.push(n);
                        }
                    }
                }
                b"port" => {
                    let port: u16 = attr(&e, b"portid")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    let proto = attr(&e, b"protocol").unwrap_or_else(|| "tcp".into());
                    cur_svc = Some(Service {
                        port,
                        proto,
                        state: PortState::Filtered,
                        name: String::new(),
                        product: String::new(),
                        version: String::new(),
                        extra: String::new(),
                        scripts: BTreeMap::new(),
                    });
                    in_hostscript = false;
                }
                b"state" => {
                    if let Some(svc) = cur_svc.as_mut() {
                        svc.state = match attr(&e, b"state").as_deref() {
                            Some("open") => PortState::Open,
                            Some("closed") => PortState::Closed,
                            Some("open|filtered") => PortState::OpenFiltered,
                            _ => PortState::Filtered,
                        };
                    }
                }
                b"service" => {
                    if let Some(svc) = cur_svc.as_mut() {
                        svc.name = attr(&e, b"name").unwrap_or_default();
                        svc.product = attr(&e, b"product").unwrap_or_default();
                        svc.version = attr(&e, b"version").unwrap_or_default();
                        let mut extra = attr(&e, b"extrainfo").unwrap_or_default();
                        if let Some(tunnel) = attr(&e, b"tunnel") {
                            if !extra.contains(&tunnel) {
                                extra = format!("{tunnel} {extra}").trim().to_string();
                            }
                        }
                        svc.extra = extra;
                    }
                }
                b"hostscript" => in_hostscript = true,
                b"script" => {
                    let id = attr(&e, b"id").unwrap_or_default();
                    let output = attr(&e, b"output").unwrap_or_default();
                    if in_hostscript {
                        if let Some(h) = cur.as_mut() {
                            h.host_scripts.insert(id, output);
                        }
                    } else if let Some(svc) = cur_svc.as_mut() {
                        svc.scripts.insert(id, output);
                    }
                }
                b"osmatch" => {
                    if let (Some(h), Some(name)) = (cur.as_mut(), attr(&e, b"name")) {
                        if h.os.is_none() {
                            let acc = attr(&e, b"accuracy").unwrap_or_default();
                            h.os = Some(if acc.is_empty() {
                                name
                            } else {
                                format!("{name} ({acc}%)")
                            });
                        }
                    }
                }
                b"hop" => {
                    if let (Some(h), Some(ip)) = (cur.as_mut(), attr(&e, b"ipaddr")) {
                        h.traceroute.push(ip);
                    }
                }
                _ => {}
            },
            Event::End(e) => match e.name().as_ref() {
                b"port" => {
                    if let (Some(h), Some(s)) = (cur.as_mut(), cur_svc.take()) {
                        h.services.push(s);
                    }
                }
                b"hostscript" => in_hostscript = false,
                b"host" => {
                    if let Some(h) = cur.take() {
                        if !h.ip.is_empty() {
                            hosts.push(h);
                        }
                    }
                }
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(hosts)
}

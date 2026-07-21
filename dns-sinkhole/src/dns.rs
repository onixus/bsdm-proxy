//! Minimal DNS message codec (UDP, single question).

use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_FORMERR: u8 = 1;
#[allow(dead_code)]
pub const RCODE_SERVFAIL: u8 = 2;

#[derive(Debug, Clone)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub struct Query {
    pub id: u16,
    pub recursion_desired: bool,
    pub question: Question,
    /// Raw bytes of the question section (for echo in responses).
    pub question_bytes: Vec<u8>,
}

pub fn parse_query(buf: &[u8]) -> Result<Query, String> {
    if buf.len() < 12 {
        return Err("short header".into());
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount != 1 {
        return Err(format!("expected 1 question, got {qdcount}"));
    }
    let qr = (flags >> 15) & 1;
    if qr != 0 {
        return Err("not a query".into());
    }
    let rd = (flags & 0x0100) != 0;

    let (name, mut off) = read_name(buf, 12)?;
    if off + 4 > buf.len() {
        return Err("short question".into());
    }
    let qtype = u16::from_be_bytes([buf[off], buf[off + 1]]);
    let qclass = u16::from_be_bytes([buf[off + 2], buf[off + 3]]);
    off += 4;
    let question_bytes = buf[12..off].to_vec();

    Ok(Query {
        id,
        recursion_desired: rd,
        question: Question {
            name,
            qtype,
            qclass,
        },
        question_bytes,
    })
}

fn read_name(buf: &[u8], mut off: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut end_off = off;
    let mut hops = 0;
    loop {
        if off >= buf.len() {
            return Err("name OOB".into());
        }
        let len = buf[off];
        if len == 0 {
            if !jumped {
                end_off = off + 1;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if off + 1 >= buf.len() {
                return Err("bad pointer".into());
            }
            let ptr = (((len as u16) & 0x3F) << 8) | buf[off + 1] as u16;
            if !jumped {
                end_off = off + 2;
            }
            off = ptr as usize;
            jumped = true;
            hops += 1;
            if hops > 10 {
                return Err("pointer loop".into());
            }
            continue;
        }
        off += 1;
        let end = off + len as usize;
        if end > buf.len() {
            return Err("label OOB".into());
        }
        let label = std::str::from_utf8(&buf[off..end]).map_err(|e| format!("label utf8: {e}"))?;
        labels.push(label.to_ascii_lowercase());
        off = end;
        if !jumped {
            end_off = off;
        }
    }
    Ok((labels.join("."), end_off))
}

#[cfg(test)]
pub fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    if name.is_empty() || name == "." {
        out.push(0);
        return out;
    }
    for label in name.trim_end_matches('.').split('.') {
        let b = label.as_bytes();
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out.push(0);
    out
}

/// Build a response: NXDOMAIN or answers with A/AAAA.
pub fn build_response(
    query: &Query,
    rcode: u8,
    answers: &[(u16, u32, &[u8])], // (rtype, ttl, rdata)
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&query.id.to_be_bytes());
    // QR=1, Opcode=0, AA=1 if we answered, RD copy, RA=1, RCODE
    let mut flags: u16 = 0x8000; // QR
    if query.recursion_desired {
        flags |= 0x0100; // RD
    }
    flags |= 0x0080; // RA
    if !answers.is_empty() {
        flags |= 0x0400; // AA
    }
    flags |= rcode as u16;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&query.question_bytes);

    for (rtype, ttl, rdata) in answers {
        // pointer to question name at offset 12
        out.extend_from_slice(&[0xC0, 0x0C]);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
    }
    out
}

pub fn a_rdata(ip: Ipv4Addr) -> [u8; 4] {
    ip.octets()
}

pub fn aaaa_rdata(ip: Ipv6Addr) -> [u8; 16] {
    ip.octets()
}

pub fn formerr(id: u16) -> Vec<u8> {
    let mut out = vec![0u8; 12];
    out[0..2].copy_from_slice(&id.to_be_bytes());
    out[2] = 0x80; // QR
    out[3] = RCODE_FORMERR;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&0x1234u16.to_be_bytes());
        q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&encode_name(name));
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        q
    }

    #[test]
    fn roundtrip_query_and_a_answer() {
        let raw = sample_query("blocked.test", TYPE_A);
        let q = parse_query(&raw).unwrap();
        assert_eq!(q.question.name, "blocked.test");
        assert_eq!(q.question.qtype, TYPE_A);
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let resp = build_response(&q, 0, &[(TYPE_A, 300, &a_rdata(ip))]);
        assert_eq!(&resp[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(resp[3] & 0x0f, 0); // NOERROR
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1); // ANCOUNT
    }

    #[test]
    fn nxdomain_rcode() {
        let raw = sample_query("x.test", TYPE_A);
        let q = parse_query(&raw).unwrap();
        let resp = build_response(&q, RCODE_NXDOMAIN, &[]);
        assert_eq!(resp[3] & 0x0f, RCODE_NXDOMAIN);
    }
}

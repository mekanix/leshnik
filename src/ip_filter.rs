use std::net::{IpAddr, Ipv6Addr};

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpMatcher {
    Exact(IpAddr),
    Cidr {
        family: IpFamily,
        network: u128,
        prefix_len: u8,
    },
    Range {
        family: IpFamily,
        start: u128,
        end: u128,
    },
    Ipv6Prefix {
        network: u128,
        prefix_len: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

#[derive(Debug, Error)]
pub enum IpMatcherError {
    #[error("invalid IP matcher {0:?}")]
    Invalid(String),
    #[error("invalid CIDR prefix length in {0:?}")]
    InvalidCidrPrefix(String),
    #[error("IP range start is greater than end in {0:?}")]
    InvalidRange(String),
    #[error("IP range mixes IPv4 and IPv6 in {0:?}")]
    MixedRangeFamilies(String),
}

impl IpMatcher {
    pub fn parse(raw: &str) -> Result<Self, IpMatcherError> {
        if let Some((addr, prefix)) = raw.split_once('/') {
            return Self::parse_cidr(raw, addr, prefix);
        }
        if let Some((start, end)) = raw.split_once('-') {
            return Self::parse_range(raw, start, end);
        }
        if raw.ends_with("::") {
            return Self::parse_ipv6_prefix(raw);
        }
        raw.parse::<IpAddr>()
            .map(Self::Exact)
            .map_err(|_| IpMatcherError::Invalid(raw.to_owned()))
    }

    pub fn matches(&self, addr: IpAddr) -> bool {
        match self {
            Self::Exact(exact) => *exact == addr,
            Self::Cidr {
                family,
                network,
                prefix_len,
            } => match (family, addr) {
                (IpFamily::V4, IpAddr::V4(addr)) => {
                    masked(u32::from(addr) as u128, *prefix_len, 32) == *network
                }
                (IpFamily::V6, IpAddr::V6(addr)) => {
                    masked(u128::from(addr), *prefix_len, 128) == *network
                }
                _ => false,
            },
            Self::Range { family, start, end } => match (family, addr) {
                (IpFamily::V4, IpAddr::V4(addr)) => {
                    let addr = u32::from(addr) as u128;
                    *start <= addr && addr <= *end
                }
                (IpFamily::V6, IpAddr::V6(addr)) => {
                    let addr = u128::from(addr);
                    *start <= addr && addr <= *end
                }
                _ => false,
            },
            Self::Ipv6Prefix {
                network,
                prefix_len,
            } => match addr {
                IpAddr::V6(addr) => masked(u128::from(addr), *prefix_len, 128) == *network,
                IpAddr::V4(_) => false,
            },
        }
    }

    fn parse_cidr(raw: &str, addr: &str, prefix: &str) -> Result<Self, IpMatcherError> {
        let addr = addr
            .parse::<IpAddr>()
            .map_err(|_| IpMatcherError::Invalid(raw.to_owned()))?;
        let prefix_len = prefix
            .parse::<u8>()
            .map_err(|_| IpMatcherError::InvalidCidrPrefix(raw.to_owned()))?;
        let (family, bits, value) = match addr {
            IpAddr::V4(addr) if prefix_len <= 32 => (IpFamily::V4, 32, u32::from(addr) as u128),
            IpAddr::V6(addr) if prefix_len <= 128 => (IpFamily::V6, 128, u128::from(addr)),
            _ => return Err(IpMatcherError::InvalidCidrPrefix(raw.to_owned())),
        };
        Ok(Self::Cidr {
            family,
            network: masked(value, prefix_len, bits),
            prefix_len,
        })
    }

    fn parse_range(raw: &str, start: &str, end: &str) -> Result<Self, IpMatcherError> {
        let start = start
            .parse::<IpAddr>()
            .map_err(|_| IpMatcherError::Invalid(raw.to_owned()))?;
        let end = end
            .parse::<IpAddr>()
            .map_err(|_| IpMatcherError::Invalid(raw.to_owned()))?;
        let (family, start, end) = match (start, end) {
            (IpAddr::V4(start), IpAddr::V4(end)) => (
                IpFamily::V4,
                u32::from(start) as u128,
                u32::from(end) as u128,
            ),
            (IpAddr::V6(start), IpAddr::V6(end)) => {
                (IpFamily::V6, u128::from(start), u128::from(end))
            }
            _ => return Err(IpMatcherError::MixedRangeFamilies(raw.to_owned())),
        };
        if start > end {
            return Err(IpMatcherError::InvalidRange(raw.to_owned()));
        }
        Ok(Self::Range { family, start, end })
    }

    fn parse_ipv6_prefix(raw: &str) -> Result<Self, IpMatcherError> {
        let hextet_count = raw
            .trim_end_matches(':')
            .split(':')
            .filter(|part| !part.is_empty())
            .count();
        let prefix_len = (hextet_count * 16) as u8;
        let addr = raw
            .parse::<Ipv6Addr>()
            .map(u128::from)
            .map_err(|_| IpMatcherError::Invalid(raw.to_owned()))?;
        Ok(Self::Ipv6Prefix {
            network: masked(addr, prefix_len, 128),
            prefix_len,
        })
    }
}

fn masked(value: u128, prefix_len: u8, bits: u8) -> u128 {
    if prefix_len == 0 {
        return 0;
    }
    let host_bits = bits - prefix_len;
    let mask = (!0_u128) << host_bits;
    value & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_exact_ipv4_and_ipv6() {
        assert!(IpMatcher::parse("192.168.1.10")
            .unwrap()
            .matches("192.168.1.10".parse().unwrap()));
        assert!(IpMatcher::parse("2001:db8::1")
            .unwrap()
            .matches("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn matches_cidr() {
        assert!(IpMatcher::parse("192.168.1.0/24")
            .unwrap()
            .matches("192.168.1.42".parse().unwrap()));
        assert!(IpMatcher::parse("2001:db8::/32")
            .unwrap()
            .matches("2001:db8:1::1".parse().unwrap()));
    }

    #[test]
    fn matches_ipv6_range() {
        let matcher = IpMatcher::parse("2001:db8::10-2001:db8::20").unwrap();
        assert!(matcher.matches("2001:db8::15".parse().unwrap()));
        assert!(!matcher.matches("2001:db8::21".parse().unwrap()));
    }

    #[test]
    fn matches_ipv4_range() {
        let matcher = IpMatcher::parse("192.168.1.10-192.168.1.20").unwrap();
        assert!(matcher.matches("192.168.1.15".parse().unwrap()));
        assert!(!matcher.matches("192.168.1.21".parse().unwrap()));
        assert!(!matcher.matches("2001:db8::15".parse().unwrap()));
    }

    #[test]
    fn matches_ipv6_prefix() {
        let matcher = IpMatcher::parse("2001:db8:abcd::").unwrap();
        assert!(matcher.matches("2001:db8:abcd:1::1".parse().unwrap()));
        assert!(!matcher.matches("2001:db8:abce::1".parse().unwrap()));
    }
}

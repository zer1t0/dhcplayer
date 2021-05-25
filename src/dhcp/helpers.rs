use nom::bytes::complete::take;
use nom::number::complete::be_u32;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use super::err::{IResult, Error};

pub fn parse_ipv4(raw: &[u8]) -> IResult<&[u8], Ipv4Addr> {
    be_u32(raw).map(|(r, i)| (r, Ipv4Addr::from(i)))
}

pub fn parse_mac(raw: &[u8]) -> IResult<&[u8], MacAddr> {
    let (r, addr) = take(6u8)(raw)?;
    Ok((
        r,
        MacAddr::new(addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]),
    ))
}


pub fn parse_utf8(raw: &[u8]) -> Result<String, Error<&[u8]>> {
    match std::str::from_utf8(raw) {
        Ok(s) => Ok(s.to_string()),
        Err(_) => {
            return Err(Error::NonUtf8String)
        }
    }
}

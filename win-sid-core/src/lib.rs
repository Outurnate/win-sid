#![forbid(unsafe_code)]

#[cfg(test)]
mod tests;
mod maybe_heap;

use byteorder::{BigEndian, ByteOrder};
use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    character::complete::{digit1, hex_digit1},
    combinator::{map_res, recognize},
    multi::{many0, many_m_n},
    number::complete::le_u32,
    Finish, IResult,
};
#[cfg(feature = "serde")]
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    fmt::{Debug, Display, Write}, hash::Hash, str::FromStr
};
use thiserror::Error;
use const_for::const_for;
use maybe_heap::MaybeHeap;

fn use_parse_str<T>(parser_result: IResult<&str, T>) -> Result<T, SecurityIdentifierError> {
    let (remainder, value) = parser_result.finish()?;
    if !remainder.is_empty() {
        Err(SecurityIdentifierError::UnexpectedContent(remainder.to_owned()))
    } else {
        Ok(value)
    }
}

/// A type representing the first value after the SID version.
/// 
/// The value is a single 48 bit integer.  Almost all SIDs encoutered "in the wild" will be less than u32.
/// 
/// # Panics
/// 
/// Converting to u64 is infallible, however, converting to u32 may panic if the value exceeds 2^32.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub struct IdentifierAuthority([u8; 6]);

impl IdentifierAuthority {
    fn parse_str(input: &str) -> IResult<&str, Self> {
        let mut identifier_authority = [0u8; 6];
        let (input, _) = tag("-")(input)?;
        let (input, value) = alt((hex_u64, dec_u64))(input)?;
        BigEndian::write_u48(&mut identifier_authority, value);
        Ok((input, Self(identifier_authority)))
    }
}

impl From<u32> for IdentifierAuthority {
    fn from(value: u32) -> Self {
        let mut identifier_authority = [0u8; 6];
        BigEndian::write_u48(&mut identifier_authority, value as u64);
        Self(identifier_authority)
    }
}

impl From<IdentifierAuthority> for u64 {
    fn from(value: IdentifierAuthority) -> Self {
        BigEndian::read_u48(&value.0)
    }
}

impl Display for IdentifierAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0[0] == 0x00 && self.0[1] == 0x00 {
            f.write_fmt(format_args!("{}", BigEndian::read_u32(&self.0[2..6])))?;
        } else {
            f.write_fmt(format_args!("{:#X}", BigEndian::read_u48(&self.0)))?;
        }
        Ok(())
    }
}

impl FromStr for IdentifierAuthority {
    type Err = SecurityIdentifierError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        use_parse_str(Self::parse_str(input))
    }
}

const COMMON_SIZE: usize = 6;

/// Core type representing Windows security identifiers ("SID"s).  Type represents version one SIDs, which consist of a single 48 bit identifier authority, followed by up to 256 sub-authorities.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub struct SecurityIdentifier {
    identifier_authority: IdentifierAuthority,
    sub_authority: MaybeHeap<COMMON_SIZE>,
}

impl SecurityIdentifier {
    /// Constructs a new SID manually.
    /// 
    /// Version number is hard-coded to one, as no other version presently exists.
    /// 
    /// # Panics
    /// 
    /// Will panic if an attempt is made to construct a SID with more than 256 sub-authorities.
    pub fn new(identifier_authority: impl Into<IdentifierAuthority>, sub_authority: &[u32]) -> Self {
        if sub_authority.len() > 256 {
            panic!("SIDs do not support more than 256 sub-authorities.  An attempt was made to construct a SID with {} sub-authorities", sub_authority.len())
        }
        Self {
            identifier_authority: identifier_authority.into(),
            sub_authority: sub_authority.to_vec().into(),
        }
    }

    /// Constructs a new SID manually (const version)
    /// 
    /// Version number is hard-coded to one, as no other version presently exists.  See the sid macro for a friendlier adapter to this function.
    /// 
    /// # Panics
    /// 
    /// Will panic if an attempt is made to construct a SID with more than 6 sub-authorities.
    pub const fn new_const<const N: usize>(identifier_authority: u64, sub_authority: [u32; N]) -> Self {
        let mut stack_sub_authorities = [0u32; COMMON_SIZE];
        assert!(N <= COMMON_SIZE);
        const_for!(i in 0..COMMON_SIZE => {
            if N > i {
                stack_sub_authorities[i] = sub_authority[i];
            }
        });
        Self {
            identifier_authority: IdentifierAuthority([
                (identifier_authority >> 40) as u8,
                (identifier_authority >> 32) as u8,
                (identifier_authority >> 24) as u8,
                (identifier_authority >> 16) as u8,
                (identifier_authority >> 8) as u8,
                identifier_authority as u8
            ]),
            sub_authority: MaybeHeap::Stack(stack_sub_authorities, N),
        }
    }

    /// Reads a SID from a slice of bytes.
    /// 
    /// SID must be in binary format - for text SIDs, first parse into a string.
    pub fn from_bytes(input: &[u8]) -> Result<Self, SecurityIdentifierError> {
        let (remainder, sid) = parse_sid_bytes(input).finish()?;
        if !remainder.is_empty() {
            Err(SecurityIdentifierError::UnexpectedContent(format!("{:?}", remainder)))
        } else {
            Ok(sid)
        }
    }

    /// Writes a SID in binary format and returns a Vec containing the binary representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(8 + (self.sub_authority.as_slice().len() * 4));
        result.push(1);
        result.push(self.sub_authority.as_slice().len() as u8);
        for byte in self.identifier_authority.0 {
            result.push(byte)
        }
        for sub_authority in self.sub_authority.as_slice() {
            for byte in sub_authority.to_le_bytes() {
                result.push(byte);
            }
        }
        result
    }

    /// Constructs an LDAP predicate that represents the objectSID attribute being equal to this SID.
    pub fn to_ldap_predicate(&self) -> String {
        let bytes = self.to_bytes();
        // 12 for predicate fixed text, 3 for each byte encoded as hex and prefixed with \
        let mut predicate = String::with_capacity(12 + (bytes.len() * 3));
        let _ = write!(predicate, "(objectSID=");
        for byte in bytes {
            let _ = write!(predicate, "\\{:02x}", byte);
        }
        let _ = write!(predicate, ")");
        predicate
    }

    /// Retrieves the last sub-authority, if there are any.  This is commonly referred to as the "resource identifier" or RID.
    pub fn get_resource_identifier(&self) -> Option<&u32> {
        self.sub_authority.as_slice().last()
    }

    /// Retrieves the mandatory identifier authority
    pub fn get_identifier_authority(&self) -> &IdentifierAuthority {
        &self.identifier_authority
    }

    /// Retrieves sub-authorities
    pub fn get_identifier_sub_authority(&self) -> &[u32] {
        self.sub_authority.as_slice()
    }

    fn parse_str(input: &str) -> IResult<&str, Self> {
        let (input, _) = tag::<_, _, nom::error::Error<_>>("S-1")(input)?;

        let (input, identifier_authority) = IdentifierAuthority::parse_str(input)?;
        let (input, sub_authority) = many0(sid_segment)(input)?;

        Ok((
            input,
            Self {
                identifier_authority,
                sub_authority : sub_authority.into(),
            },
        ))
    }
}

impl Display for SecurityIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("S-1-{}", self.identifier_authority))?;
        for sub_authority in self.sub_authority.as_slice() {
            f.write_fmt(format_args!("-{}", sub_authority))?;
        }
        Ok(())
    }
}

impl FromStr for SecurityIdentifier {
    type Err = SecurityIdentifierError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        use_parse_str(Self::parse_str(input))
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SecurityIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        SecurityIdentifier::from_str(&String::deserialize(deserializer)?).map_err(|err| D::Error::custom(err.to_string()))
    }
}

#[cfg(feature = "serde")]
impl Serialize for SecurityIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

fn dec_u64(input: &str) -> IResult<&str, u64> {
    map_res(recognize(digit1), str::parse)(input)
}

fn hex_u64(input: &str) -> IResult<&str, u64> {
    let (input, _) = tag("0x")(input)?;
    map_res(recognize(hex_digit1), |x| u64::from_str_radix(x, 16))(input)
}

fn dec_u32(input: &str) -> IResult<&str, u32> {
    map_res(recognize(digit1), str::parse)(input)
}

fn hex_u32(input: &str) -> IResult<&str, u32> {
    let (input, _) = tag("0x")(input)?;
    map_res(recognize(hex_digit1), |x| u32::from_str_radix(x, 16))(input)
}

fn sid_segment(input: &str) -> IResult<&str, u32> {
    let (input, _) = tag("-")(input)?;
    let (input, value) = alt((hex_u32, dec_u32))(input)?;
    Ok((input, value))
}

fn parse_sid_bytes(input: &[u8]) -> IResult<&[u8], SecurityIdentifier> {
    let (input, _) = tag([1])(input)?;

    let (input, sub_authority_count) = nom::number::complete::u8(input)?;
    let (input, identifier_authority) = take(6usize)(input)?;
    let (input, sub_authority) = many_m_n(sub_authority_count as usize, sub_authority_count as usize, le_u32)(input)?;

    Ok((
        input,
        SecurityIdentifier {
            identifier_authority: IdentifierAuthority(identifier_authority.try_into().unwrap()),
            sub_authority: sub_authority.into(),
        },
    ))
}

/// Represents all errors that may be encountered during either binary or string parsing of a SID.
#[derive(Error, Debug)]
pub enum SecurityIdentifierError {
    /// Only version one SIDs are supported.  These are also the only SID version known to exist.
    #[error("bad revision")]
    BadRevision,

    /// Generic parsing failure, such as premature ends.
    #[error("parsing error: {0}")]
    ParseError(String),

    /// Additional or invalid content was found in the SID.
    #[error("unexpected content: {0}")]
    UnexpectedContent(String),
}

impl<E> From<nom::error::Error<E>> for SecurityIdentifierError
where
    E: Debug,
{
    fn from(value: nom::error::Error<E>) -> Self {
        Self::ParseError(format!("{:?}: {:?}", value.code, value.input))
    }
}

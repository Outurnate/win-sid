use std::str::FromStr;
use ::win_sid_core as win_sid;

use super::*;

#[test]
fn const_is_sane() {
  assert_eq!(SecurityIdentifier::from_str("S-1-5-32-544").unwrap(), sid!("S-1-5-32-544"));
  assert_eq!(SecurityIdentifier::from_str("S-1-5-21-1004336348-1177238915-682003330-512").unwrap(), sid!("S-1-5-21-1004336348-1177238915-682003330-512"));
  assert_eq!(SecurityIdentifier::from_str("S-1-0-0").unwrap(), sid!("S-1-0-0"));
  assert_eq!(SecurityIdentifier::from_str("S-1-3-2").unwrap(), sid!("S-1-3-2"));
  assert_eq!(SecurityIdentifier::from_str("S-1-5-80-0").unwrap(), sid!("S-1-5-80-0"));
  assert_eq!(SecurityIdentifier::from_str("S-1-0x10000002A-0").unwrap(), sid!("S-1-0x10000002A-0"));
  assert_eq!(SecurityIdentifier::from_str("S-1-5").unwrap(), sid!("S-1-5"));
  assert_eq!(SecurityIdentifier::from_str("S-1-5-113").unwrap(), sid!("S-1-5-113"));
  assert_eq!(SecurityIdentifier::from_str("S-1-5-32-555").unwrap(), sid!("S-1-5-32-555"));
}
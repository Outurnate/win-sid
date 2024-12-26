#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

use std::str::FromStr;

use proc_macro2::TokenStream;
use proc_macro2_diagnostics::{Diagnostic, Level};
use quote::quote;
use syn::{parse_macro_input, LitStr};
use win_sid_core::SecurityIdentifier;

extern crate proc_macro;

/// The sid macro will parse/validate a SID at compile time.  SIDs require heap allocation, and thus, cannot be created in const contexts.  The recommended approach for static SIDs is to wrap the call in a `std::sync::LazyLock`.
#[proc_macro]
pub fn sid(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let constant_value = parse_macro_input!(input as LitStr);
    match sid_inner(constant_value) {
        Ok(tokens) => tokens.into(),
        Err(diag) => diag.emit_as_expr_tokens().into(),
    }
}

fn sid_inner(constant_value: LitStr) -> Result<TokenStream, Diagnostic> {
    let sid = SecurityIdentifier::from_str(&constant_value.value()).map_err(|err| Diagnostic::new(Level::Error, err.to_string()))?;
    let identifier_authorities: u64 = sid.get_identifier_authority().to_owned().into();
    let sub_authorities = sid.get_identifier_sub_authority();
    Ok(quote!(
        win_sid::SecurityIdentifier::new_const((#identifier_authorities as u64), [#( #sub_authorities ),*])
    ))
}

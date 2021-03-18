#![feature(external_doc)]
#![allow(non_snake_case, non_upper_case_globals)]
#![deny(
    clippy::absurd_extreme_comparisons,
    clippy::almost_swapped,
    clippy::approx_constant,
    clippy::async_yields_async,
    clippy::bad_bit_mask,
    clippy::cast_ref_to_mut,
    clippy::clone_double_ref,
    clippy::cmp_nan,
    clippy::deprecated_semver,
    clippy::derive_hash_xor_eq,
    clippy::derive_ord_xor_partial_ord,
    clippy::drop_copy,
    clippy::drop_ref,
    clippy::enum_clike_unportable_variant,
    clippy::eq_op,
    clippy::erasing_op,
    clippy::float_cmp,
    clippy::float_equality_without_abs,
    clippy::fn_address_comparisons,
    clippy::for_loops_over_fallibles,
    clippy::forget_copy,
    clippy::forget_ref,
    clippy::if_let_mutex,
    clippy::if_same_then_else,
    clippy::ifs_same_cond,
    clippy::ineffective_bit_mask,
    clippy::infinite_iter,
    clippy::inherent_to_string_shadow_display,
    clippy::inline_fn_without_body,
    clippy::invalid_atomic_ordering,
    clippy::invalid_regex,
    clippy::invisible_characters,
    clippy::iter_next_loop,
    clippy::iterator_step_by_zero,
    clippy::let_underscore_lock,
    clippy::logic_bug,
    clippy::mem_discriminant_non_enum,
    clippy::mem_replace_with_uninit,
    clippy::min_max,
    clippy::mismatched_target_os,
    clippy::mistyped_literal_suffixes,
    clippy::modulo_one,
    clippy::mut_from_ref,
    clippy::mutable_key_type,
    clippy::never_loop,
    clippy::nonsensical_open_options,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::option_env_unwrap,
    clippy::out_of_bounds_indexing,
    clippy::panicking_unwrap,
    clippy::possible_missing_comma,
    clippy::reversed_empty_ranges,
    clippy::self_assignment,
    clippy::serde_api_misuse,
    clippy::size_of_in_element_count,
    clippy::suspicious_arithmetic_impl,
    clippy::suspicious_op_assign_impl,
    clippy::to_string_in_display,
    clippy::transmuting_null,
    clippy::undropped_manually_drops,
    clippy::uninit_assumed_init,
    clippy::unit_cmp,
    clippy::unit_return_expecting_ord,
    clippy::unsound_collection_transmute,
    clippy::unused_io_amount,
    clippy::useless_attribute,
    clippy::vec_resize_to_zero,
    clippy::vtable_address_comparisons,
    clippy::while_immutable_condition,
    clippy::wrong_transmute,
    clippy::zst_offset
)]
use sha3::{
    digest::{ExtendableOutput, Update},
    Shake256,
};

pub use crate::error::Ed448Error;

pub use private_key::PrivateKey;
pub use public_key::PublicKey;

mod error;
mod point;
mod private_key;
mod public_key;

#[doc(include = "../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;

pub type Result<T> = core::result::Result<T, Ed448Error>;

pub const KEY_LENGTH: usize = 57;
pub const SIG_LENGTH: usize = 114;

/// Indicate if the message need to be pre-hashed before being signed/verified
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum PreHash {
    /// Pre-hash the message
    True,
    /// Leave the message unchanged
    False,
}

impl From<PreHash> for u8 {
    fn from(hash: PreHash) -> Self {
        match hash {
            PreHash::False => 0,
            PreHash::True => 1,
        }
    }
}

/// Produce a Shake256 for signing/verifying signatures
fn shake256(items: Vec<&[u8]>, ctx: &[u8], pre_hash: PreHash) -> Box<[u8]> {
    let mut shake = Shake256::default()
        .chain(b"SigEd448")
        .chain(&[pre_hash.into(), ctx.len() as u8])
        .chain(ctx);
    for item in items {
        shake.update(item);
    }
    shake.finalize_boxed(114)
}

fn array_to_key(byte: &[u8]) -> [u8; KEY_LENGTH] {
    let key: *const [u8; KEY_LENGTH] = byte.as_ptr() as *const [u8; KEY_LENGTH];
    unsafe { std::mem::transmute(*key) }
}

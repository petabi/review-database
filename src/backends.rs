//! Supported database backends.
//!
//! This module chooses, at compile-time, one of the supported backends as the
//! database.

#[cfg(test)]
pub(crate) mod memory;
mod postgres;

#[cfg(test)]
use memory as backend;
#[cfg(not(test))]
use postgres as backend;

pub(super) use backend::{ConnectionPool, Transaction, Value};

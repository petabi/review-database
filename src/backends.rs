//! Supported database backends.
//!
//! This module chooses, at compile-time, one of the supported backends as the
//! database.

mod postgres;

use postgres as backend;

pub(super) use backend::{ConnectionPool, Value};

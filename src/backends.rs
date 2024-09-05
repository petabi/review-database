//! Supported database backends.
//!
//! This module chooses, at compile-time, one of the supported backends as the
//! database.

mod postgres;

pub(super) use backend::ConnectionPool;
use postgres as backend;

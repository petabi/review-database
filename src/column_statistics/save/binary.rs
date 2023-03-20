use crate::{backends::Transaction, Type};
use std::convert::TryFrom;
use structured::{ColumnStatistics, Element};
use tracing::error;

pub(super) async fn insert_binary<'a>(
    transaction: &Transaction<'a>,
    description_id: i32,
    column_stats: &ColumnStatistics,
    mode: &[u8],
) {
    if let Err(e) = transaction
        .insert_into(
            "description_binary",
            &[("description_id", Type::INT4), ("mode", Type::BYTEA)],
            &[&description_id, &mode],
        )
        .await
    {
        error!("Failed to insert description_binary: {:#}", e);
    }

    for e in column_stats.n_largest_count.top_n() {
        let value = if let Element::Binary(binary) = &e.value {
            Some(binary.clone())
        } else {
            None
        };
        let count = i64::try_from(e.count).expect("Must be less than i64::MAX");

        if let Err(e) = transaction
            .insert_into(
                "top_n_binary",
                &[
                    ("description_id", Type::INT4),
                    ("value", Type::BYTEA),
                    ("count", Type::INT8),
                ],
                &[&description_id, &value, &count],
            )
            .await
        {
            error!("Failed to insert top_n_binary: {:#}", e);
        }
    }
}

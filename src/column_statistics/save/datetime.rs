use crate::{backends::Transaction, Type};
use chrono::NaiveDateTime;
use std::convert::TryFrom;
use structured::{ColumnStatistics, Element};
use tracing::error;

pub(super) async fn insert_datetime<'a>(
    transaction: &Transaction<'a>,
    description_id: i32,
    column_stats: &ColumnStatistics,
    mode: &NaiveDateTime,
) {
    if let Err(e) = transaction
        .insert_into(
            "description_datetime",
            &[("description_id", Type::INT4), ("mode", Type::TIMESTAMP)],
            &[&description_id, &mode],
        )
        .await
    {
        error!("Failed to insert description_datetime: {:#}", e);
    }

    for e in column_stats.n_largest_count.top_n() {
        let value = if let Element::DateTime(datetime) = &e.value {
            Some(*datetime)
        } else {
            tracing::warn!("NULL VALUE2");
            continue;
        };
        let count = i64::try_from(e.count).expect("Must be less than i64::MAX");

        if let Err(e) = transaction
            .insert_into(
                "top_n_datetime",
                &[
                    ("description_id", Type::INT4),
                    ("value", Type::TIMESTAMP),
                    ("count", Type::INT8),
                ],
                &[&description_id, &value, &count],
            )
            .await
        {
            error!("Failed to insert top_n_datetime: {:#}", e);
        }
    }
}

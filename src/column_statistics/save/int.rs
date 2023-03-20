use crate::{backends::Transaction, Type};
use std::convert::TryFrom;
use structured::{ColumnStatistics, Element};
use tracing::error;

pub(super) async fn insert_int<'a>(
    transaction: &Transaction<'a>,
    description_id: i32,
    column_stats: &ColumnStatistics,
    mode: i64,
) {
    let min = if let Some(Element::Int(v)) = &column_stats.description.min() {
        Some(*v)
    } else {
        None
    };
    let max = if let Some(Element::Int(v)) = &column_stats.description.max() {
        Some(*v)
    } else {
        None
    };

    if let Err(e) = transaction
        .insert_into(
            "description_int",
            &[
                ("description_id", Type::INT4),
                ("min", Type::INT8),
                ("max", Type::INT8),
                ("mean", Type::FLOAT8),
                ("s_deviation", Type::FLOAT8),
                ("mode", Type::INT8),
            ],
            &[
                &description_id,
                &min,
                &max,
                &column_stats.description.mean(),
                &column_stats.description.std_deviation(),
                &mode,
            ],
        )
        .await
    {
        error!("Failed to insert description_int: {:#}", e);
    }

    for e in column_stats.n_largest_count.top_n() {
        let value = match &e.value {
            Element::Int(v) => Some(*v),
            _ => None,
        };
        let count = i64::try_from(e.count).expect("Must be less than i64::MAX");
        if let Err(e) = transaction
            .insert_into(
                "top_n_int",
                &[
                    ("description_id", Type::INT4),
                    ("value", Type::INT8),
                    ("count", Type::INT8),
                ],
                &[&description_id, &value, &count],
            )
            .await
        {
            error!("Failed to insert top_n_int: {:#}", e);
        }
    }
}

use crate::{backends::Transaction, Type};
use std::convert::TryFrom;
use structured::{ColumnStatistics, Element, FloatRange};
use tracing::error;

pub(super) async fn insert_float<'a>(
    transaction: &Transaction<'a>,
    description_id: i32,
    column_stats: &ColumnStatistics,
    mode: &FloatRange,
) {
    let min = if let Some(Element::Float(min)) = &column_stats.description.min() {
        Some(*min)
    } else {
        None
    };
    let max = if let Some(Element::Float(max)) = &column_stats.description.max() {
        Some(*max)
    } else {
        None
    };

    if let Err(e) = transaction
        .insert_into(
            "description_float",
            &[
                ("description_id", Type::INT4),
                ("min", Type::FLOAT8),
                ("max", Type::FLOAT8),
                ("mean", Type::FLOAT8),
                ("s_deviation", Type::FLOAT8),
                ("mode_smallest", Type::FLOAT8),
                ("mode_largest", Type::FLOAT8),
            ],
            &[
                &description_id,
                &min,
                &max,
                &column_stats.description.mean(),
                &column_stats.description.std_deviation(),
                &mode.smallest,
                &mode.largest,
            ],
        )
        .await
    {
        error!("Failed to insert description_float: {:#}", e);
    }

    for e in column_stats.n_largest_count.top_n() {
        let (value_smallest, value_largest) = if let Element::FloatRange(fr) = &e.value {
            (Some(fr.smallest), Some(fr.largest))
        } else {
            (None, None)
        };
        let count = i64::try_from(e.count).expect("Must be less than i64::MAX");

        if let Err(e) = transaction
            .insert_into(
                "top_n_float",
                &[
                    ("description_id", Type::INT4),
                    ("value_smallest", Type::FLOAT8),
                    ("value_largest", Type::FLOAT8),
                    ("count", Type::INT8),
                ],
                &[&description_id, &value_smallest, &value_largest, &count],
            )
            .await
        {
            error!("Failed to insert top_n_float: {:#}", e);
        }
    }
}

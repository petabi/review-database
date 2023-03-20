use crate::{backends::Transaction, Type};
use std::convert::TryFrom;
use structured::{ColumnStatistics, Element};
use tracing::error;

pub(super) async fn insert_ipaddr<'a>(
    transaction: &Transaction<'a>,
    description_id: i32,
    column_stats: &ColumnStatistics,
    mode: &std::net::IpAddr,
) {
    if let Err(e) = transaction
        .insert_into(
            "description_ipaddr",
            &[("description_id", Type::INT4), ("mode", Type::TEXT)],
            &[&description_id, &mode.to_string()],
        )
        .await
    {
        error!("Failed to insert description_ipaddr: {:#}", e);
    }

    for e in column_stats.n_largest_count.top_n() {
        let value = if let Element::IpAddr(ipaddr) = &e.value {
            Some(ipaddr.to_string())
        } else {
            None
        };
        let count = i64::try_from(e.count).expect("Must be less than i64::MAX");

        if let Err(e) = transaction
            .insert_into(
                "top_n_ipaddr",
                &[
                    ("description_id", Type::INT4),
                    ("value", Type::TEXT),
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

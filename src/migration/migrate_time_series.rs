use anyhow::Result;
use chrono::NaiveDateTime;

use crate::Database;
use crate::tables::TimeSeries;

pub(crate) async fn run(database: &Database, store: &crate::Store) -> Result<()> {
    let models = super::migrate_column_stats::retrieve_model_to_migrate(database).await?;
    tracing::info!(
        "Migrating Time Series for a total of {} models from PostgreSQL to RocksDb",
        models.len()
    );
    for &model in &models {
        tracing::info!("Migrating Time Series for model {model}");
        if let Err(e) = migrate_time_series_for_model(database, store, model).await {
            tracing::error!("Migration for model {model} failed");
            return Err(e);
        }
        if let Err(e) = remove_time_series(database, model).await {
            tracing::error!("Removing time series for {model} in PostgresQL failed");
            return Err(e);
        }
    }
    tracing::info!("Time series data migration done.");
    Ok(())
}

async fn migrate_time_series_for_model(
    database: &Database,
    store: &crate::Store,
    model: i32,
) -> Result<()> {
    let time_series = get_time_series(database, model).await?;
    let map = store.time_series_map();
    let txn = map.transaction();
    for ts in time_series {
        map.put_with_transaction(&ts, &txn)?;
    }
    txn.commit()?;
    Ok(())
}

async fn get_time_series(database: &Database, model_id: i32) -> Result<Vec<TimeSeries>> {
    use diesel_async::RunQueryDsl;

    use crate::diesel::{ExpressionMethods, JoinOnDsl, QueryDsl};
    use crate::schema::{cluster::dsl as c_d, time_series::dsl as t_d};

    let mut conn = database.pool.get().await?;
    Ok(c_d::cluster
        .inner_join(t_d::time_series.on(t_d::cluster_id.eq(c_d::id)))
        .filter(c_d::model_id.eq(model_id))
        .select((c_d::id, t_d::time, t_d::count_index, t_d::value, t_d::count))
        .load::<(i32, NaiveDateTime, Option<i32>, NaiveDateTime, i64)>(&mut conn)
        .await?
        .into_iter()
        .filter_map(|(cluster_id, time, count_index, value, count)| {
            let time = time.and_utc().timestamp_nanos_opt()?;
            let value = value.and_utc().timestamp_nanos_opt()?;
            let count = usize::try_from(count).ok()?;
            Some(TimeSeries {
                model_id,
                cluster_id,
                time,
                value,
                count_index,
                count,
            })
        })
        .collect())
}

async fn remove_time_series(database: &Database, model_id: i32) -> Result<()> {
    use diesel_async::RunQueryDsl;

    use crate::diesel::{ExpressionMethods, QueryDsl};
    use crate::schema::{cluster::dsl as c_d, time_series::dsl as t_d};

    let mut conn = database.pool.get().await?;
    diesel::delete(t_d::time_series)
        .filter(
            t_d::cluster_id.eq_any(
                c_d::cluster
                    .select(c_d::id)
                    .filter(c_d::model_id.eq(model_id)),
            ),
        )
        .execute(&mut conn)
        .await?;
    Ok(())
}

use std::collections::HashMap;

use anyhow::Result;
use chrono::NaiveDateTime;
use diesel::{ExpressionMethods, QueryDsl, dsl::exists, select};
use diesel_async::RunQueryDsl;

use crate::{Database, column_statistics::Statistics};

pub(crate) async fn run(database: &Database, store: &crate::Store) -> Result<()> {
    use crate::schema::column_description::dsl as cd;
    let mut conn = database.pool.get().await?;

    // First check if there are any column descriptions to migrate
    let has_records: bool = select(exists(cd::column_description.select(cd::id)))
        .get_result(&mut conn)
        .await?;

    // No column descriptions found in PostgreSQL, skipping migration
    if !has_records {
        return Ok(());
    }

    let models = retrieve_model_to_migrate(database).await?;
    tracing::info!(
        "Migrating column statistics for a total of {} models from PostgreSQL to RocksDb",
        models.len()
    );
    for &model in &models {
        if let Err(e) = migrate_column_stats_for_model(database, store, model).await {
            tracing::error!("Migration for model {model} failed");
            return Err(e);
        }
    }
    tracing::info!("Removing column statistics in PostgresQL");
    remove_column_stats(database, models).await?;
    tracing::info!("Column statistics data migration done.");
    Ok(())
}

async fn remove_column_stats(database: &Database, models: Vec<i32>) -> Result<()> {
    use crate::schema::{
        cluster::dsl as cluster_table, column_description::dsl as cd,
        description_binary::dsl as db, description_datetime::dsl as dd,
        description_enum::dsl as de, description_float::dsl as df, description_int::dsl as di,
        description_ipaddr::dsl as dip, description_text::dsl as dt,
    };
    let mut conn = database.pool.get().await?;
    let clusters: Vec<i32> = cluster_table::cluster
        .select(cluster_table::id)
        .filter(cluster_table::model_id.eq_any(models))
        .load(&mut conn)
        .await?;
    let descriptions: Vec<i32> = cd::column_description
        .select(cd::id)
        .filter(cd::cluster_id.eq_any(&clusters))
        .load(&mut conn)
        .await?;
    diesel::delete(db::description_binary.filter(db::description_id.eq_any(&descriptions)))
        .execute(&mut conn)
        .await?;
    diesel::delete(dd::description_datetime.filter(dd::description_id.eq_any(&descriptions)))
        .execute(&mut conn)
        .await?;
    diesel::delete(de::description_enum.filter(de::description_id.eq_any(&descriptions)))
        .execute(&mut conn)
        .await?;
    diesel::delete(df::description_float.filter(df::description_id.eq_any(&descriptions)))
        .execute(&mut conn)
        .await?;
    diesel::delete(di::description_int.filter(di::description_id.eq_any(&descriptions)))
        .execute(&mut conn)
        .await?;
    diesel::delete(dip::description_ipaddr.filter(dip::description_id.eq_any(&descriptions)))
        .execute(&mut conn)
        .await?;
    diesel::delete(dt::description_text.filter(dt::description_id.eq_any(&descriptions)))
        .execute(&mut conn)
        .await?;
    diesel::delete(cd::column_description.filter(cd::id.eq_any(&descriptions)))
        .execute(&mut conn)
        .await?;

    Ok(())
}

pub(crate) async fn retrieve_model_to_migrate(database: &Database) -> Result<Vec<i32>> {
    use crate::schema::model::dsl;
    let mut conn = database.pool.get().await?;
    Ok(dsl::model
        .select(dsl::id)
        .order_by(dsl::id)
        .load(&mut conn)
        .await?)
}

async fn migrate_column_stats_for_model(
    database: &Database,
    store: &crate::Store,
    model: i32,
) -> Result<()> {
    let stats = retrieve_column_stats_for_model(database, model).await?;
    save_column_stats_for_model(store, model, stats)
}

async fn retrieve_column_stats_for_model(
    database: &Database,
    model: i32,
) -> Result<Vec<(i32, Vec<Statistics>)>> {
    use crate::schema::cluster::dsl;

    let mut conn = database.pool.get().await?;
    let query = dsl::cluster
        .select(dsl::id)
        .filter(dsl::model_id.eq(&model))
        .order_by(dsl::id);
    let clusters: Vec<_> = query.load::<i32>(&mut conn).await?;

    let mut result = vec![];
    for cluster in clusters {
        result.push((
            cluster,
            database.get_column_statistics(cluster, vec![]).await?,
        ));
    }

    Ok(result)
}

fn save_column_stats_for_model(
    store: &crate::Store,
    model: i32,
    stats: Vec<(i32, Vec<Statistics>)>,
) -> Result<()> {
    let map = store.column_stats_map();
    for (cluster, stats) in stats {
        let cluster = u32::try_from(cluster)?;
        let converted = convert_stats_for_cluster(stats);
        for (batch_ts, columns) in converted {
            map.insert_column_statistics(vec![(cluster, columns)], model, batch_ts)?;
        }
    }
    Ok(())
}

fn convert_stats_for_cluster(
    stats: Vec<Statistics>,
) -> Vec<(NaiveDateTime, Vec<structured::ColumnStatistics>)> {
    let mut grouped_stats: HashMap<NaiveDateTime, Vec<(u32, structured::ColumnStatistics)>> =
        HashMap::new();
    for stat in stats {
        if let Ok(column_index) = u32::try_from(stat.column_index) {
            grouped_stats
                .entry(stat.batch_ts)
                .or_default()
                .push((column_index, stat.column_stats));
        }
    }

    grouped_stats
        .into_iter()
        .map(|(batch_ts, mut columns)| {
            columns.sort_unstable_by_key(|(index, _)| *index);
            (
                batch_ts,
                columns.into_iter().map(|(_, stats)| stats).collect(),
            )
        })
        .collect()
}

use anyhow::Result;

use crate::Database;
use crate::tables::Cluster;

pub(crate) async fn run(database: &Database, store: &crate::Store) -> Result<()> {
    let models = super::migrate_time_series::retrieve_model_to_migrate(database).await?;
    tracing::info!(
        "Migrating Clusters for a total of {} models from PostgreSQL to RocksDb",
        models.len()
    );
    for &model in &models {
        tracing::info!("Migrating Clusters for model {model}");
        if let Err(e) = migrate_clusters_for_model(database, store, model).await {
            tracing::error!("Migration for model {model} failed");
            return Err(e);
        }
        if let Err(e) = remove_clusters(database, model).await {
            tracing::error!("Removing clusters for {model} in PostgresQL failed");
            return Err(e);
        }
    }
    tracing::info!("Clusters data migration done.");
    Ok(())
}

async fn remove_clusters(database: &Database, model: i32) -> Result<()> {
    use diesel::ExpressionMethods;
    use diesel_async::RunQueryDsl;

    use crate::diesel::QueryDsl;
    use crate::schema::cluster::dsl;
    let mut conn = database.pool.get().await?;
    diesel::delete(dsl::cluster.filter(dsl::model_id.eq(model)))
        .execute(&mut conn)
        .await?;
    Ok(())
}

async fn migrate_clusters_for_model(
    database: &Database,
    store: &crate::Store,
    model: i32,
) -> Result<()> {
    let clusters = retrieve_cluster_to_migrate(database, model).await?;
    let map = store.cluster_map();
    let txn = map.transaction();
    for c in clusters {
        map.put_with_transaction(&c, &txn)?;
    }
    txn.commit()?;
    Ok(())
}

#[allow(deprecated)]
async fn retrieve_cluster_to_migrate(
    database: &Database,
    model: i32,
) -> Result<Vec<crate::Cluster>> {
    Ok(database
        .load_clusters(
            model,
            None,
            None,
            None,
            None,
            &None,
            &None,
            false,
            usize::MAX,
        )
        .await?
        .into_iter()
        .map(|c| Cluster {
            model_id: model,
            id: c.cluster_id,
            category_id: c.category_id,
            detector_id: c.detector_id,
            event_ids: c.event_ids,
            labels: c.labels,
            last_modification_time: c.last_modification_time,
            qualifier_id: c.qualifier_id,
            score: c.score,
            signature: c.signature,
            size: c.size,
            status_id: c.status_id,
            sensors: c.sensors,
        })
        .collect())
}

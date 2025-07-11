use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;

use crate::{Database, Error, classifier_fs::ClassifierFsError, schema::model::dsl};

#[derive(PartialEq)]
enum MigrationResult {
    Success, // if migration completed successfully
    Skipped, // if the classifier already exists or is empty
}

/// Migrates all classifiers from PostgreSQL to the file system.
///
/// This is the main migration function that orchestrates the following process:
/// 1. Retrieves all model metadata from PostgreSQL
/// 2. Migrates each classifier individually to the file system
/// 3. Removes successfully migrated classifiers from PostgreSQL
///
/// The migration is designed to be resilient - individual failures don't stop
/// the entire process, and only successfully migrated classifiers are removed
/// from PostgreSQL to ensure data integrity.
///
/// # Errors
///
/// Returns `crate::Error` if critical operations fail, such as:
/// - Database connection failures
/// - Metadata retrieval failures
/// - Batch removal operations from PostgreSQL
///
/// Individual model migration failures are logged but don't stop the process.
pub(crate) async fn run_migration(database: &Database) -> Result<(), Error> {
    let model_metadata = get_model_metadata(database).await?;
    let model_len = model_metadata.len();

    if model_len == 0 {
        return Ok(());
    }

    tracing::info!("Migrating {model_len} model classifier(s) from PostgreSQL to file system");

    // Migrate each classifier individually to file system
    let mut successful_ids = Vec::new();
    for (id, name) in model_metadata {
        match migrate_single_classifier(database, id, &name).await {
            Ok(result) => {
                if result == MigrationResult::Success {
                    successful_ids.push(id);
                }
            }
            Err(e) => {
                tracing::error!("Failed to migrate model {name} (id={id}): {e}");
            }
        }
    }

    // Remove successfully migrated classifiers from PostgreSQL
    if !successful_ids.is_empty() {
        let mut total = 0;
        // Process in chunks of 1000
        for chunk in successful_ids.chunks(1000) {
            match remove_classifier_in_postgres(database, chunk).await {
                Ok(counts) => total += counts,
                Err(e) => {
                    tracing::error!("Failed to remove classifier data from PostgreSQL: {e}");
                }
            }
        }
        tracing::info!("{total} classifier data removed from PostgreSQL");
    }

    tracing::info!(
        "Migration summary: {} successful, {} skipped/failed out of {model_len} total models",
        successful_ids.len(),
        model_len - successful_ids.len(),
    );

    Ok(())
}

/// Migrates a single classifier from PostgreSQL to the file system.
///
/// This function handles the complete migration process for one model:
/// 1. Checks if the classifier already exists in the file system
/// 2. Retrieves the classifier data from PostgreSQL
/// 3. Stores the classifier data to the file system
/// 4. Verifies the file system storage was successful
///
/// # Errors
///
/// Returns various `ClassifierFsError` variants if any step of the migration fails,
/// including database queries, file system operations, or verification failures.
async fn migrate_single_classifier(
    database: &Database,
    id: i32,
    name: &str,
) -> Result<MigrationResult, Error> {
    // Skip if classifier already exists in file system
    if database.classifier_fm.classifier_exists(id, name) {
        tracing::info!("model {name} (id={id}) already exists in the file system");
        return Ok(MigrationResult::Skipped);
    }

    // Retrieve classifier data from PostgreSQL
    let classifier = get_classifier(database, id).await?;

    // Skip if classifier is None or empty
    let Some(classifier) = classifier else {
        tracing::info!("model {name} (id={id}) is empty");
        return Ok(MigrationResult::Skipped);
    };
    if classifier.is_empty() {
        tracing::info!("model {name} (id:{id}) is empty");
        return Ok(MigrationResult::Skipped);
    }

    tracing::info!("Migrating model {name} (id={id}) to the file system...");

    // Store classifier data to file system
    database
        .classifier_fm
        .store_classifier(id, name, &classifier)
        .await?;

    // Verify file system storage was successful
    if !database.classifier_fm.classifier_exists(id, name) {
        return Err(Error::Classifier(ClassifierFsError::FileNotFound(
            id,
            name.to_string(),
        )));
    }

    tracing::info!("Successfully migrated model {name} (id={id}) to the file system");

    Ok(MigrationResult::Success)
}

/// Retrieves all model metadata (id and name pairs) from PostgreSQL using
/// pagination.
///
/// This function queries the model table in batches of 1000 records to
/// avoid loading all models into memory at once. It uses cursor-based
/// pagination with the model ID as the cursor.
///
/// # Errors
///
/// Returns `crate::Error::Connection` if database connection fails, or
/// `crate::Error::Query` if the database query fails.
pub(crate) async fn get_model_metadata(database: &Database) -> Result<Vec<(i32, String)>, Error> {
    let mut conn = database.pool.get().await?;
    let mut metadata = Vec::new();
    let mut after = None;

    // Use cursor-based pagination to handle large numbers of models
    loop {
        let mut query = dsl::model
            .select((dsl::id, dsl::name))
            .filter(dsl::classifier.is_not_null())
            .limit(1000)
            .order_by(dsl::id.asc())
            .into_boxed();
        if let Some(after) = after {
            query = query.filter(dsl::id.gt(after));
        }

        let result = query.get_results::<(i32, String)>(&mut conn).await?;
        let should_break = result.len() != 1000;
        after = result.last().as_ref().map(|m| m.0);
        metadata.extend(result);

        if should_break {
            break;
        }
    }

    Ok(metadata)
}

/// Retrieves a classifier binary data from PostgreSQL for a specific model.
///
/// # Errors
///
/// Returns `crate::Error::Connection` if database connection fails, or
/// `crate::Error::Query` if the database query fails.
async fn get_classifier(database: &Database, id: i32) -> Result<Option<Vec<u8>>, Error> {
    let mut conn = database.pool.get().await?;
    Ok(dsl::model
        .select(dsl::classifier)
        .filter(dsl::id.eq(id))
        .get_result(&mut conn)
        .await?)
}

/// Removes classifier data from PostgreSQL for multiple models by setting
/// them to NULL.
///
/// This function is called after successful file system migration to clean
/// up classifier data from the database. It processes multiple model IDs in
/// a single transaction for efficiency.
///
/// # Errors
///
/// Returns `crate::Error::Connection` if database connection fails, or
/// `crate::Error::Query` if the database update fails.
async fn remove_classifier_in_postgres(database: &Database, ids: &[i32]) -> Result<usize, Error> {
    let mut conn = database.pool.get().await?;
    Ok(diesel::update(dsl::model.filter(dsl::id.eq_any(ids)))
        .set(dsl::classifier.eq(None::<Vec<u8>>))
        .execute(&mut conn)
        .await?)
}

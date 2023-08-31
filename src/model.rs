use super::{Database, Error, Type};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Queryable)]
pub struct Digest {
    pub id: i32,
    pub name: String,
    pub version: i32,
    pub data_source_id: i32,
    pub classification_id: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize, Queryable)]
pub struct Model {
    pub id: i32,
    pub name: String,
    pub version: i32,
    pub kind: String,
    pub serialized_classifier: Vec<u8>,
    pub max_event_id_num: i32,
    pub data_source_id: i32,
    pub classification_id: i64,
    pub batch_info: Vec<crate::types::ModelBatchInfo>,
    pub scores: crate::types::ModelScores,
}

impl Model {
    #[must_use]
    pub fn into_storage(
        self,
    ) -> (
        SqlModel,
        Vec<crate::batch_info::BatchInfo>,
        crate::scores::Scores,
    ) {
        let sql = SqlModel {
            id: self.id,
            name: self.name,
            version: self.version,
            kind: self.kind,
            serialized_classifier: self.serialized_classifier,
            max_event_id_num: self.max_event_id_num,
            data_source_id: self.data_source_id,
            classification_id: self.classification_id,
        };
        let batch_info = self
            .batch_info
            .into_iter()
            .map(|b| crate::batch_info::BatchInfo::new(self.id, b))
            .collect();
        let scores = crate::scores::Scores::new(self.id, self.scores);
        (sql, batch_info, scores)
    }

    pub fn from_storage(
        (model, batch_info, scores): (
            SqlModel,
            Vec<crate::batch_info::BatchInfo>,
            crate::scores::Scores,
        ),
    ) -> Self {
        let batch_info = batch_info
            .into_iter()
            .map(crate::batch_info::BatchInfo::into_inner)
            .collect();
        let scores = scores.into_inner();
        Self {
            id: model.id,
            name: model.name,
            version: model.version,
            kind: model.kind,
            serialized_classifier: model.serialized_classifier,
            max_event_id_num: model.max_event_id_num,
            data_source_id: model.data_source_id,
            classification_id: model.classification_id,
            batch_info,
            scores,
        }
    }
}

#[derive(Deserialize, Queryable)]
#[allow(clippy::module_name_repetitions)]
pub struct SqlModel {
    pub id: i32,
    name: String,
    version: i32,
    kind: String,
    serialized_classifier: Vec<u8>,
    max_event_id_num: i32,
    data_source_id: i32,
    classification_id: i64,
}

impl Database {
    const CSV_COLUMN_TYPES: &[&'static str] = &[
        "binary", "datetime", "enum", "float", "int", "ipaddr", "text",
    ];

    fn type_tables(prefix: &str) -> Vec<String> {
        Self::CSV_COLUMN_TYPES
            .iter()
            .map(|t| format!("{prefix}_{t}"))
            .collect()
    }

    /// Adds a new model to the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the model already exists or if a database operation fails.
    pub async fn add_model(&self, model: &SqlModel) -> Result<i32, Error> {
        let conn = self.pool.get().await?;
        let n = conn
            .insert_into(
                "model",
                &[
                    ("name", Type::TEXT),
                    ("version", Type::INT4),
                    ("kind", Type::TEXT),
                    ("classifier", Type::BYTEA),
                    ("max_event_id_num", Type::INT4),
                    ("data_source_id", Type::INT4),
                    ("classification_id", Type::INT8),
                ],
                &[
                    &model.name,
                    &model.version,
                    &model.kind,
                    &model.serialized_classifier,
                    &model.max_event_id_num,
                    &model.data_source_id,
                    &model.classification_id,
                ],
            )
            .await
            .map_err(|_| Error::InvalidInput(format!("model \"{}\" already exists", model.name)))?;
        if n == 0 {
            Err(Error::InvalidInput("failed to insert model".into()))
        } else {
            Ok(n)
        }
    }

    /// Deletes the model with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or if a database operation fails.
    pub async fn delete_model(&self, name: &str) -> Result<i32, Error> {
        let conn = self.pool.get().await?;
        let query_result = conn
            .select_one_opt_from::<i32>("model", &["id"], &[("name", Type::TEXT)], &[&name])
            .await?;
        let Some(id) = query_result else {
            return Err(Error::InvalidInput(format!("The model {name} not found")));
        };
        conn.delete_from("model", &[("id", Type::INT4)], &[&id])
            .await?;
        conn.delete_from("csv_column_list", &[("model_id", Type::INT4)], &[&id])
            .await?;
        conn.delete_from("csv_column_extra", &[("model_id", Type::INT4)], &[&id])
            .await?;

        self.delete_csv_entries_under_model_name(name).await?;

        self.delete_stats(id).await?;

        Ok(id)
    }

    async fn delete_csv_entries_under_model_name(&self, model_name: &str) -> Result<(), Error> {
        let conn = self.pool.get().await?;

        let tables_and_key: &[(&str, &str)] =
            &[("csv_indicator", "name"), ("csv_whitelist", "name")];

        for (t, k) in tables_and_key {
            conn.delete_from(t, &[(k, Type::TEXT)], &[&model_name])
                .await?;
        }

        Ok(())
    }

    async fn delete_stats(&self, id: i32) -> Result<(), Error> {
        let conn = self.pool.get().await?;

        conn.delete_from("outlier", &[("model_id", Type::INT4)], &[&id])
            .await?;

        let cluster_ids: Vec<i32> = conn
            .select_in(
                "cluster",
                &["id"],
                &[("model_id", Type::INT4)],
                &[],
                &[],
                &[&id],
            )
            .await?;
        if cluster_ids.is_empty() {
            return Ok(());
        }

        conn.delete_from("cluster", &[("model_id", Type::INT4)], &[&id])
            .await?;

        conn.delete_in(
            "time_series",
            &[],
            &[("cluster_id", Type::INT4_ARRAY)],
            &[&cluster_ids],
        )
        .await?;

        let event_range_ids: Vec<i32> = conn
            .select_in(
                "event_range",
                &["id"],
                &[],
                &[("cluster_id", Type::INT4_ARRAY)],
                &[],
                &[&cluster_ids],
            )
            .await?;
        conn.delete_in(
            "event_range",
            &[],
            &[("id", Type::INT4_ARRAY)],
            &[&event_range_ids],
        )
        .await?;

        let column_description_ids: Vec<i32> = conn
            .select_in(
                "column_description",
                &["id"],
                &[],
                &[],
                &[("event_range_ids", Type::INT4_ARRAY, Some("&&"))],
                &[&event_range_ids],
            )
            .await?;
        conn.delete_in(
            "column_description",
            &[],
            &[("id", Type::INT4_ARRAY)],
            &[&column_description_ids],
        )
        .await?;

        let prefixes = &["top_n", "description"];
        for p in prefixes {
            let tables = Self::type_tables(p);
            for t in tables {
                conn.delete_in(
                    &t,
                    &[],
                    &[("description_id", Type::INT4_ARRAY)],
                    &[&column_description_ids],
                )
                .await?;
            }
        }

        Ok(())
    }

    /// Returns the number of models.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub async fn count_models(&self) -> Result<i64, Error> {
        let conn = self.pool.get().await?;
        conn.count("model", &[], &[], &[]).await
    }

    /// Returns the maximum number of outliers of the model with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or if a database operation fails.
    pub async fn get_max_event_id_num(&self, model_name: &str) -> Result<i32, Error> {
        let conn = self.pool.get().await?;
        conn.select_one_from(
            "model",
            &["max_event_id_num"],
            &[("name", Type::TEXT)],
            &[&model_name],
        )
        .await
    }

    /// Returns the model with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or if a database operation fails.
    pub async fn load_model(&self, id: i32) -> Result<Digest, Error> {
        let conn = self.pool.get().await?;
        conn.select_one_from::<Digest>(
            "model",
            &[
                "id",
                "name",
                "version",
                "data_source_id",
                "classification_id",
            ],
            &[("id", super::Type::INT4)],
            &[&id],
        )
        .await
    }

    /// Returns the model with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or if a database operation fails.
    pub async fn load_model_by_name(&self, name: &str) -> Result<SqlModel, Error> {
        let conn = self.pool.get().await?;
        conn.select_one_from::<SqlModel>(
            "model",
            &[
                "id",
                "name",
                "version",
                "kind",
                "classifier",
                "max_event_id_num",
                "data_source_id",
                "classification_id",
            ],
            &[("name", super::Type::TEXT)],
            &[&name],
        )
        .await
    }

    /// Returns the models between `after` and `before`.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub async fn load_models(
        &self,
        after: &Option<(i32, String)>,
        before: &Option<(i32, String)>,
        is_first: bool,
        limit: usize,
    ) -> Result<Vec<Digest>, Error> {
        use super::schema::model::dsl;
        use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;

        let limit = i64::try_from(limit).map_err(|_| Error::InvalidInput("limit".into()))? + 1;
        let mut query = dsl::model
            .select((
                dsl::id,
                dsl::name,
                dsl::version,
                dsl::data_source_id,
                dsl::classification_id,
            ))
            .limit(limit)
            .into_boxed();

        if let Some(after) = after {
            query = query.filter(
                dsl::name
                    .eq(&after.1)
                    .and(dsl::id.gt(after.0))
                    .or(dsl::name.gt(&after.1)),
            );
        }
        if let Some(before) = before {
            query = query.filter(
                dsl::name
                    .eq(&before.1)
                    .and(dsl::id.lt(before.0))
                    .or(dsl::name.lt(&before.1)),
            );
        }
        if is_first {
            query = query.order_by(dsl::name.asc()).then_order_by(dsl::id.asc());
        } else {
            query = query
                .order_by(dsl::name.desc())
                .then_order_by(dsl::id.desc());
        }

        let mut conn = self.pool.get_diesel_conn().await?;
        let rows = query.get_results::<Digest>(&mut conn).await?;
        if is_first {
            Ok(rows)
        } else {
            Ok(rows.into_iter().rev().collect())
        }
    }

    /// Updates the model with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or if a database operation fails.
    pub async fn update_model<'a>(&self, model: &SqlModel) -> Result<i32, Error> {
        let conn = self.pool.get().await?;

        conn.update(
            "model",
            model.id,
            &[
                ("name", Type::TEXT),
                ("version", Type::INT4),
                ("kind", super::Type::TEXT),
                ("classifier", Type::BYTEA),
                ("max_event_id_num", Type::INT4),
                ("data_source_id", Type::INT4),
                ("classification_id", Type::INT8),
            ],
            &[
                &model.name,
                &model.version,
                &model.kind,
                &model.serialized_classifier,
                &model.max_event_id_num,
                &model.data_source_id,
                &model.classification_id,
            ],
        )
        .await
        .map_err(|e| {
            Error::InvalidInput(format!("failed to update model \"{}\": {e}", model.name))
        })?;
        Ok(model.id)
    }
}

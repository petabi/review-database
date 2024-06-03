use anyhow::Result;
use bincode::Options;
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};

use super::{Database, Error, Type};

#[derive(Deserialize, Queryable)]
pub struct Digest {
    pub id: i32,
    pub name: String,
    pub version: i32,
    pub data_source_id: i32,
    pub classification_id: Option<i64>,
}

#[derive(Debug, Queryable)]
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
            classifier: self.serialized_classifier,
            max_event_id_num: self.max_event_id_num,
            data_source_id: self.data_source_id,
            classification_id: Some(self.classification_id),
        };
        let batch_info = self
            .batch_info
            .into_iter()
            .map(|b| crate::batch_info::BatchInfo::new(self.id, b))
            .collect();
        let scores = crate::scores::Scores::new(self.id, self.scores);
        (sql, batch_info, scores)
    }

    #[must_use]
    pub fn from_storage(model: SqlModel) -> Self {
        Self {
            id: model.id,
            name: model.name,
            version: model.version,
            kind: model.kind,
            serialized_classifier: model.classifier,
            max_event_id_num: model.max_event_id_num,
            data_source_id: model.data_source_id,
            classification_id: model.classification_id.unwrap_or_default(),
            batch_info: vec![],
            scores: crate::types::ModelScores::new(),
        }
    }

    fn header(&self) -> Result<MagicHeader> {
        use std::str::FromStr;
        Ok(MagicHeader {
            tag: MagicHeader::MAGIC_STRING.to_vec(),
            format: MagicHeader::FORMAT_VERSION,
            kind: ClusteringMethod::from_str(&self.kind)?,
            version: self.version,
        })
    }

    /// # Errors
    ///
    /// Returns an error if format version doesn't match `MagicHeader::FORMAT_VERSION` or
    /// if deserialization process failed.  
    pub fn from_serialized(serialized: &[u8]) -> Result<Self> {
        use anyhow::anyhow;

        let header = MagicHeader::try_from(&serialized[..MagicHeader::MAGIC_SIZE])?;
        if header.format != MagicHeader::FORMAT_VERSION {
            return Err(anyhow!(
                "Model format mismatch: {:?} (Expecting: {:?})",
                header.format,
                MagicHeader::FORMAT_VERSION
            ));
        }
        let version = header.version;
        let kind = header.kind.to_string();
        let model: Body =
            bincode::DefaultOptions::new().deserialize(&serialized[MagicHeader::MAGIC_SIZE..])?;
        Ok(Self {
            id: model.id,
            name: model.name,
            version,
            kind,
            serialized_classifier: model.serialized_classifier,
            max_event_id_num: model.max_event_id_num,
            data_source_id: model.data_source_id,
            classification_id: model.classification_id,
            batch_info: model.batch_info,
            scores: model.scores,
        })
    }

    /// # Errors
    ///
    /// Returns an error if serialization process failed.  
    pub fn into_serialized(self) -> Result<Vec<u8>> {
        let mut buf = <Vec<u8>>::from(self.header()?);
        let model = Body {
            id: self.id,
            name: self.name,
            serialized_classifier: self.serialized_classifier,
            max_event_id_num: self.max_event_id_num,
            data_source_id: self.data_source_id,
            classification_id: self.classification_id,
            batch_info: self.batch_info,
            scores: self.scores,
        };
        buf.extend(bincode::DefaultOptions::new().serialize(&model)?);
        Ok(buf)
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize, EnumString, Display)]
enum ClusteringMethod {
    Distribution = 0,
    Multifield = 1, // This corresponds to ClusteringMethod::Multidimention in REconverge
    Prefix = 2,
    Timeseries = 3,
}

impl TryFrom<u32> for ClusteringMethod {
    type Error = anyhow::Error;

    fn try_from(input: u32) -> Result<Self> {
        use anyhow::anyhow;

        match input {
            0 => Ok(Self::Distribution),
            1 => Ok(Self::Multifield),
            2 => Ok(Self::Prefix),
            3 => Ok(Self::Timeseries),
            _ => Err(anyhow!("Unexpected clustering method {input}")),
        }
    }
}

#[derive(Debug, PartialEq)]
struct MagicHeader {
    tag: Vec<u8>,
    format: u32,
    kind: ClusteringMethod,
    version: i32,
}

impl MagicHeader {
    const FORMAT_VERSION: u32 = 1;
    const MAGIC_STRING: &'static [u8] = b"RCM\0";
    const MAGIC_SIZE: usize = 16;
}

impl From<MagicHeader> for Vec<u8> {
    fn from(val: MagicHeader) -> Self {
        let mut buf = val.tag.clone();
        buf.extend(val.format.to_le_bytes().iter());
        buf.extend((val.kind as u32).to_le_bytes().iter());
        buf.extend(val.version.to_le_bytes().iter());
        buf
    }
}

impl TryFrom<&[u8]> for MagicHeader {
    type Error = anyhow::Error;

    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        use anyhow::anyhow;

        if v.len() < MagicHeader::MAGIC_SIZE {
            return Err(anyhow!("length should be > {}", MagicHeader::MAGIC_SIZE));
        }

        let tag = (v[..4]).to_vec();
        if tag.as_slice() != MagicHeader::MAGIC_STRING {
            return Err(anyhow!("wrong magic string"));
        }
        let format = u32::from_le_bytes(v[4..8].try_into()?);
        let kind = u32::from_le_bytes(v[8..12].try_into()?).try_into()?;
        let version = i32::from_le_bytes(v[12..].try_into()?);

        Ok(MagicHeader {
            tag,
            format,
            kind,
            version,
        })
    }
}

#[derive(Deserialize, Serialize)]
struct Body {
    id: i32,
    name: String,
    serialized_classifier: Vec<u8>,
    max_event_id_num: i32,
    data_source_id: i32,
    classification_id: i64,
    batch_info: Vec<crate::types::ModelBatchInfo>,
    scores: crate::types::ModelScores,
}

#[derive(Deserialize, Queryable)]
#[allow(clippy::module_name_repetitions)]
pub struct SqlModel {
    pub id: i32,
    name: String,
    version: i32,
    kind: String,
    classifier: Vec<u8>,
    max_event_id_num: i32,
    data_source_id: i32,
    classification_id: Option<i64>,
}

impl Database {
    const CSV_COLUMN_TYPES: &'static [&'static str] = &[
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
                    &model.classifier,
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

        let column_description_ids: Vec<i32> = conn
            .select_in(
                "column_description",
                &["id"],
                &[],
                &[("cluster_id", Type::INT4_ARRAY)],
                &[],
                &[&cluster_ids],
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
        use diesel::{ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;

        use super::schema::model::dsl;

        let query = dsl::model
            .select((
                dsl::id,
                dsl::name,
                dsl::version,
                dsl::kind,
                dsl::classifier,
                dsl::max_event_id_num,
                dsl::data_source_id,
                dsl::classification_id,
            ))
            .filter(dsl::name.eq(name));

        let mut conn = self.pool.get_diesel_conn().await?;
        Ok(query.get_result::<SqlModel>(&mut conn).await?)
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
        use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;

        use super::schema::model::dsl;

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
                &model.classifier,
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

#[cfg(test)]
mod tests {

    fn example() -> (super::Model, super::Body) {
        (
            super::Model {
                id: 1,
                name: "example".to_owned(),
                version: 2,
                kind: "Multifield".to_owned(),
                serialized_classifier: b"test".to_vec(),
                max_event_id_num: 123,
                data_source_id: 1,
                classification_id: 0,
                batch_info: vec![],
                scores: crate::types::ModelScores::default(),
            },
            super::Body {
                id: 1,
                name: "example".to_owned(),
                serialized_classifier: b"test".to_vec(),
                max_event_id_num: 123,
                data_source_id: 1,
                classification_id: 0,
                batch_info: vec![],
                scores: crate::types::ModelScores::default(),
            },
        )
    }

    #[test]
    fn header() {
        let (model, _) = example();
        let header = model.header().unwrap();
        assert_eq!(header.kind, super::ClusteringMethod::Multifield);
        assert_eq!(header.version, 2);
        assert_eq!(header.format, super::MagicHeader::FORMAT_VERSION);

        let serialized: Vec<u8> = header.try_into().unwrap();
        assert_eq!(&serialized[..4], super::MagicHeader::MAGIC_STRING);
        assert_eq!(
            &serialized[4..8],
            super::MagicHeader::FORMAT_VERSION.to_le_bytes()
        );
        assert_eq!(
            &serialized[8..12],
            (super::ClusteringMethod::Multifield as u32).to_le_bytes()
        );
        assert_eq!(&serialized[12..], 2_u32.to_le_bytes());

        let deserialized = super::MagicHeader::try_from(serialized.as_slice()).unwrap();
        assert_eq!(deserialized, model.header().unwrap());
    }

    #[test]
    fn serialized_model() {
        use bincode::Options;

        let (model, body) = example();
        let header = model.header().unwrap();
        let s_header: Vec<u8> = header.try_into().unwrap();
        let s_body = bincode::DefaultOptions::new().serialize(&body).unwrap();

        let serialized = model.into_serialized().unwrap();
        assert_eq!(&serialized[..super::MagicHeader::MAGIC_SIZE], &s_header);
        assert_eq!(&serialized[super::MagicHeader::MAGIC_SIZE..], &s_body);

        let d_model = super::Model::from_serialized(&serialized).unwrap();
        let (model, _body) = example();
        assert_eq!(d_model.id, model.id);
        assert_eq!(d_model.serialized_classifier, model.serialized_classifier);
    }
}

use anyhow::Result;
use bincode::Options;
use diesel::{BoolExpressionMethods, ExpressionMethods, OptionalExtension, QueryDsl};
use diesel_async::{RunQueryDsl, pg::AsyncPgConnection};
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};

use super::{Database, Error, schema::model::dsl};

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
    fn from_storage(model: SqlModel, serialized_classifier: Vec<u8>) -> Self {
        Self {
            id: model.id,
            name: model.name,
            version: model.version,
            kind: model.kind,
            serialized_classifier,
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
struct SqlModel {
    id: i32,
    name: String,
    version: i32,
    kind: String,
    max_event_id_num: i32,
    data_source_id: i32,
    classification_id: Option<i64>,
}

impl Database {
    /// Adds a new model to the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the model already exists or if a database operation fails.
    pub async fn add_model(&self, model: &Model) -> Result<i32, Error> {
        let mut conn = self.pool.get().await?;
        let n = diesel::insert_into(dsl::model)
            .values((
                dsl::name.eq(&model.name),
                dsl::version.eq(model.version),
                dsl::kind.eq(&model.kind),
                dsl::max_event_id_num.eq(model.max_event_id_num),
                dsl::data_source_id.eq(model.data_source_id),
                dsl::classification_id.eq(model.classification_id),
            ))
            .returning(dsl::id)
            .get_result(&mut conn)
            .await
            .map_err(|_| Error::InvalidInput(format!("model \"{}\" already exists", model.name)))?;
        if n == 0 {
            Err(Error::InvalidInput("failed to insert model".into()))
        } else {
            self.classifier_fm
                .store_classifier(n, &model.name, &model.serialized_classifier)
                .await?;
            Ok(n)
        }
    }

    /// Deletes the model with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or if a database operation fails.
    pub async fn delete_model(&self, name: &str) -> Result<i32, Error> {
        let mut conn = self.pool.get().await?;
        let id = diesel::delete(dsl::model)
            .filter(dsl::name.eq(name))
            .returning(dsl::id)
            .get_result(&mut conn)
            .await
            .optional()?;
        let Some(id) = id else {
            return Err(Error::InvalidInput(format!("The model {name} not found")));
        };

        self.classifier_fm.delete_classifier(id, name).await?;

        self.delete_stats(id, &mut conn).await?;

        Ok(id)
    }

    async fn delete_stats(&self, id: i32, conn: &mut AsyncPgConnection) -> Result<(), Error> {
        use super::schema::{cluster::dsl as cluster, time_series::dsl as time_series};

        let cluster_ids: Vec<i32> = diesel::delete(cluster::cluster)
            .filter(cluster::model_id.eq(id))
            .returning(cluster::id)
            .get_results(conn)
            .await?;
        if cluster_ids.is_empty() {
            return Ok(());
        }

        diesel::delete(time_series::time_series)
            .filter(time_series::cluster_id.eq_any(&cluster_ids))
            .execute(conn)
            .await?;

        Ok(())
    }

    /// Returns the number of models.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub async fn count_models(&self) -> Result<i64, Error> {
        let mut conn = self.pool.get().await?;
        Ok(dsl::model.count().get_result(&mut conn).await?)
    }

    /// Returns the model with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or if a database operation fails.
    pub async fn load_model(&self, id: i32) -> Result<Digest, Error> {
        let mut conn = self.pool.get().await?;
        Ok(dsl::model
            .select((
                dsl::id,
                dsl::name,
                dsl::version,
                dsl::data_source_id,
                dsl::classification_id,
            ))
            .filter(dsl::id.eq(id))
            .get_result(&mut conn)
            .await?)
    }

    /// Returns the model with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or if a database operation fails.
    pub async fn load_model_by_name(&self, name: &str) -> Result<Model, Error> {
        let query = dsl::model
            .select((
                dsl::id,
                dsl::name,
                dsl::version,
                dsl::kind,
                dsl::max_event_id_num,
                dsl::data_source_id,
                dsl::classification_id,
            ))
            .filter(dsl::name.eq(name));

        let mut conn = self.pool.get().await?;
        let model = query.get_result::<SqlModel>(&mut conn).await?;
        if !self.classifier_fm.classifier_exists(model.id, name) {
            return Err(Error::Classifier(
                super::classifier_fs::ClassifierFsError::FileNotFound(model.id, name.into()),
            ));
        }
        let classifier = self.classifier_fm.load_classifier(model.id, name).await?;
        Ok(Model::from_storage(model, classifier))
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

        let mut conn = self.pool.get().await?;
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
    pub async fn update_model(&self, model: &Model) -> Result<i32, Error> {
        let mut conn = self.pool.get().await?;

        diesel::update(dsl::model.filter(dsl::id.eq(model.id)))
            .set((
                dsl::name.eq(&model.name),
                dsl::version.eq(model.version),
                dsl::kind.eq(&model.kind),
                dsl::max_event_id_num.eq(model.max_event_id_num),
                dsl::data_source_id.eq(model.data_source_id),
                dsl::classification_id.eq(model.classification_id),
            ))
            .execute(&mut conn)
            .await
            .map_err(|e| {
                Error::InvalidInput(format!("failed to update model \"{}\": {e}", model.name))
            })?;
        self.classifier_fm
            .store_classifier(model.id, &model.name, &model.serialized_classifier)
            .await?;

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

        let serialized: Vec<u8> = header.into();
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
        let s_header: Vec<u8> = header.into();
        let s_body = bincode::DefaultOptions::new().serialize(&body).unwrap();

        let serialized = model.into_serialized().unwrap();
        assert_eq!(&serialized[..super::MagicHeader::MAGIC_SIZE], &s_header);
        assert_eq!(&serialized[super::MagicHeader::MAGIC_SIZE..], &s_body);

        let d_model = super::Model::from_serialized(&serialized).unwrap();
        let (model, _body) = example();
        assert_eq!(d_model.id, model.id);
    }
}

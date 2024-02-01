use crate::{Database, Error};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Default)]
#[allow(clippy::module_name_repetitions)]
pub struct CsvColumnExtra {
    pub id: u32,
    pub model_id: i32,
    pub column_alias: Option<Vec<String>>,
    pub column_display: Option<Vec<bool>>,
    pub column_top_n: Option<Vec<bool>>,
    pub column_1: Option<Vec<bool>>,
    pub column_n: Option<Vec<bool>>,
}

#[derive(Queryable)]
struct CsvColumnExtraRow {
    pub id: i32,
    pub model_id: i32,
    pub column_alias: Option<Vec<Option<String>>>,
    pub column_display: Option<Vec<Option<bool>>>,
    pub column_top_n: Option<Vec<Option<bool>>>,
    pub column_1: Option<Vec<Option<bool>>>,
    pub column_n: Option<Vec<Option<bool>>>,
}

impl From<CsvColumnExtraRow> for CsvColumnExtra {
    fn from(entry: CsvColumnExtraRow) -> Self {
        let filtered = |v: Vec<_>| v.into_iter().flatten().collect();
        Self {
            id: u32::try_from(entry.id).expect("illegal id"),
            model_id: entry.model_id,
            column_alias: entry
                .column_alias
                .map(|v| v.into_iter().flatten().collect()),
            column_display: entry.column_display.map(filtered),
            column_top_n: entry.column_top_n.map(filtered),
            column_1: entry.column_1.map(filtered),
            column_n: entry.column_n.map(filtered),
        }
    }
}

impl Database {
    /// Loads extra information regarding the columns of a CSV model.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection to the database fails.
    pub(super) async fn load_csv_column_extras(&self) -> Result<Vec<CsvColumnExtra>, Error> {
        use super::schema::csv_column_extra::dsl;
        use diesel::{ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;

        let query = dsl::csv_column_extra
            .select((
                dsl::id,
                dsl::model_id,
                dsl::column_alias,
                dsl::column_display,
                dsl::column_top_n,
                dsl::column_1,
                dsl::column_n,
            ))
            .order_by(dsl::id.asc());
        let mut conn = self.pool.get_diesel_conn().await?;
        Ok(query
            .get_results::<CsvColumnExtraRow>(&mut conn)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }
}

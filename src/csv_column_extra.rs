use crate::{Database, Error, Type, Value};
use serde::Deserialize;

#[derive(Deserialize)]
#[allow(clippy::module_name_repetitions)]
pub struct CsvColumnExtraConfig {
    pub id: u32,
    pub model_id: i32,
    pub column_alias: Option<Vec<String>>,
    pub column_display: Option<Vec<bool>>,
    pub column_top_n: Option<Vec<bool>>,
    pub column_1: Option<Vec<bool>>,
    pub column_n: Option<Vec<bool>>,
}

impl Database {
    pub async fn add_column_extra(
        &self,
        model_id: i32,
        column_alias: Option<&[String]>,
        column_display: Option<&[bool]>,
        column_top_n: Option<&[bool]>,
        column_1: Option<&[bool]>,
        column_n: Option<&[bool]>,
    ) -> Result<i32, Error> {
        let conn = self.pool.get().await?;
        conn.insert_into(
            "csv_column_extra",
            &[
                ("model_id", Type::INT4),
                ("column_alias", Type::TEXT_ARRAY),
                ("column_display", Type::BOOL_ARRAY),
                ("column_top_n", Type::BOOL_ARRAY),
                ("column_1", Type::BOOL_ARRAY),
                ("column_n", Type::BOOL_ARRAY),
            ],
            &[
                &model_id,
                &column_alias,
                &column_display,
                &column_top_n,
                &column_1,
                &column_n,
            ],
        )
        .await
    }

    pub async fn load_csv_column_extra_config(
        &self,
        model_id: i32,
    ) -> Result<Option<CsvColumnExtraConfig>, Error> {
        let conn = self.pool.get().await?;
        conn.select_one_opt_from::<CsvColumnExtraConfig>(
            "csv_column_extra",
            &[
                "id",
                "model_id",
                "column_alias",
                "column_display",
                "column_top_n",
                "column_1",
                "column_n",
            ],
            &[("model_id", super::Type::INT4)],
            &[&model_id],
        )
        .await
    }

    pub async fn update_csv_column_extra(
        &self,
        id: i32,
        column_alias: Option<&[String]>,
        column_display: Option<&[bool]>,
        column_top_n: Option<&[bool]>,
        column_1: Option<&[bool]>,
        column_n: Option<&[bool]>,
    ) -> Result<(), Error> {
        let mut columns = Vec::new();
        let mut values = Vec::<&Value>::new();
        if column_alias.is_some() {
            columns.push(("column_alias", Type::TEXT_ARRAY));
            values.push(&column_alias);
        }
        if column_display.is_some() {
            columns.push(("column_display", Type::BOOL_ARRAY));
            values.push(&column_display);
        }
        if column_top_n.is_some() {
            columns.push(("column_top_n", Type::BOOL_ARRAY));
            values.push(&column_top_n);
        }
        if column_1.is_some() {
            columns.push(("column_1", Type::BOOL_ARRAY));
            values.push(&column_1);
        }
        if column_n.is_some() {
            columns.push(("column_n", Type::BOOL_ARRAY));
            values.push(&column_n);
        }

        if columns.is_empty() {
            Err(Error::InvalidInput("no column to update".to_string()))
        } else {
            let conn = self.pool.get().await?;
            conn.update("csv_column_extra", id, &columns, &values)
                .await?;
            Ok(())
        }
    }
}

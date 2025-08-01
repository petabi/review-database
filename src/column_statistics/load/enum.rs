use std::collections::HashMap;

use chrono::NaiveDateTime;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{RunQueryDsl, pg::AsyncPgConnection};
use structured::{Description, Element, ElementCount, NLargestCount};

use super::{
    BatchTimestamp, ColumnIndex, DescriptionIndex, Error, Statistics, ToDescription,
    ToElementCount, ToNLargestCount,
    schema::{
        column_description::dsl as cd, description_enum::dsl as desc, top_n_enum::dsl as top_n,
    },
};

#[derive(Debug, Queryable)]
struct DescriptionEnum {
    id: i32,
    column_index: i32,
    batch_ts: NaiveDateTime,
    count: i64,
    unique_count: i64,
    mode: String,
}

impl ColumnIndex for DescriptionEnum {
    fn column_index(&self) -> i32 {
        self.column_index
    }
}

impl BatchTimestamp for DescriptionEnum {
    fn batch_ts(&self) -> NaiveDateTime {
        self.batch_ts
    }
}

impl DescriptionIndex for DescriptionEnum {
    fn description_index(&self) -> i32 {
        self.id
    }
}

impl ToDescription for DescriptionEnum {
    fn to_description(&self) -> Description {
        Description::new(
            usize::try_from(self.count).unwrap_or_default(),
            None,
            None,
            None,
            None,
        )
    }
}

impl ToNLargestCount for DescriptionEnum {
    fn to_n_largest_count(self, ec: Vec<ElementCount>) -> NLargestCount {
        NLargestCount::new(
            usize::try_from(self.unique_count).unwrap_or_default(),
            ec,
            Some(Element::Enum(self.mode)),
        )
    }
}

#[derive(Debug, Queryable)]
struct TopNEnum {
    description_id: i32,
    value: String,
    count: i64,
}

impl DescriptionIndex for TopNEnum {
    fn description_index(&self) -> i32 {
        self.description_id
    }
}

impl ToElementCount for TopNEnum {
    fn to_element_count(self) -> ElementCount {
        ElementCount {
            value: Element::Enum(self.value),
            count: usize::try_from(self.count).unwrap_or_default(),
        }
    }
}

pub(super) async fn get_enum_statistics(
    mut conn: AsyncPgConnection,
    description_ids: &[i32],
) -> Result<Vec<Statistics>, Error> {
    let column_descriptions = cd::column_description
        .select((
            cd::id,
            cd::column_index,
            cd::batch_ts,
            cd::count,
            cd::unique_count,
        ))
        .filter(cd::id.eq_any(description_ids))
        .order_by((cd::id.asc(), cd::column_index.asc(), cd::count.desc()))
        .load::<(i32, i32, NaiveDateTime, i64, i64)>(&mut conn)
        .await?;

    let modes: HashMap<_, _> = desc::description_enum
        .select((desc::description_id, desc::mode))
        .filter(desc::description_id.eq_any(description_ids))
        .load::<(i32, String)>(&mut conn)
        .await?
        .into_iter()
        .collect();

    let column_descriptions: Vec<DescriptionEnum> = column_descriptions
        .into_iter()
        .filter_map(|(id, column_index, batch_ts, count, unique_count)| {
            modes.get(&id).map(|mode| DescriptionEnum {
                id,
                column_index,
                batch_ts,
                count,
                unique_count,
                mode: mode.clone(),
            })
        })
        .collect();

    let top_n = top_n::top_n_enum
        .select((top_n::description_id, top_n::value, top_n::count))
        .filter(top_n::description_id.eq_any(description_ids))
        .order_by(top_n::description_id.asc())
        .load::<TopNEnum>(&mut conn)
        .await?;

    Ok(super::build_column_statistics(column_descriptions, top_n))
}

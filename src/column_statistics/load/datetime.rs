use std::collections::HashMap;

use chrono::NaiveDateTime;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{RunQueryDsl, pg::AsyncPgConnection};
use structured::{Description, Element, ElementCount, NLargestCount};

use super::{
    BatchTimestamp, ColumnIndex, DescriptionIndex, Error, Statistics, ToDescription,
    ToElementCount, ToNLargestCount,
    schema::{
        column_description::dsl as cd, description_datetime::dsl as desc,
        top_n_datetime::dsl as top_n,
    },
};

#[derive(Debug, Queryable)]
struct DescriptionDateTime {
    id: i32,
    column_index: i32,
    batch_ts: NaiveDateTime,
    count: i64,
    unique_count: i64,
    mode: NaiveDateTime,
}

impl ColumnIndex for DescriptionDateTime {
    fn column_index(&self) -> i32 {
        self.column_index
    }
}

impl BatchTimestamp for DescriptionDateTime {
    fn batch_ts(&self) -> NaiveDateTime {
        self.batch_ts
    }
}

impl DescriptionIndex for DescriptionDateTime {
    fn description_index(&self) -> i32 {
        self.id
    }
}

impl ToDescription for DescriptionDateTime {
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

impl ToNLargestCount for DescriptionDateTime {
    fn to_n_largest_count(self, ec: Vec<ElementCount>) -> NLargestCount {
        NLargestCount::new(
            usize::try_from(self.unique_count).unwrap_or_default(),
            ec,
            Some(Element::DateTime(self.mode)),
        )
    }
}

#[derive(Debug, Queryable)]
struct TopNDateTime {
    id: i32,
    value: NaiveDateTime,
    count: i64,
}

impl DescriptionIndex for TopNDateTime {
    fn description_index(&self) -> i32 {
        self.id
    }
}

impl ToElementCount for TopNDateTime {
    fn to_element_count(self) -> ElementCount {
        ElementCount {
            value: Element::DateTime(self.value),
            count: usize::try_from(self.count).unwrap_or_default(),
        }
    }
}

pub(super) async fn get_datetime_statistics(
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

    let modes: HashMap<_, _> = desc::description_datetime
        .select((desc::description_id, desc::mode))
        .filter(desc::description_id.eq_any(description_ids))
        .load::<(i32, NaiveDateTime)>(&mut conn)
        .await?
        .into_iter()
        .collect();

    let column_descriptions: Vec<DescriptionDateTime> = column_descriptions
        .into_iter()
        .filter_map(|(id, column_index, batch_ts, count, unique_count)| {
            modes.get(&id).map(|mode| DescriptionDateTime {
                id,
                column_index,
                batch_ts,
                count,
                unique_count,
                mode: *mode,
            })
        })
        .collect();

    let top_n = top_n::top_n_datetime
        .select((top_n::description_id, top_n::value, top_n::count))
        .filter(top_n::description_id.eq_any(description_ids))
        .order_by(top_n::description_id.asc())
        .load::<TopNDateTime>(&mut conn)
        .await?;

    Ok(super::build_column_statistics(column_descriptions, top_n))
}

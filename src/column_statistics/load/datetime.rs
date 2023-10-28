use super::{
    schema::{
        column_description::dsl as cd, description_datetime::dsl as desc,
        top_n_datetime::dsl as top_n,
    },
    ColumnIndex, DescriptionIndex, Error, Statistics, ToDescription, ToElementCount,
    ToNLargestCount,
};
use chrono::NaiveDateTime;
use diesel::{ExpressionMethods, JoinOnDsl, QueryDsl};
use diesel_async::{pg::AsyncPgConnection, RunQueryDsl};
use structured::{Description, Element, ElementCount, NLargestCount};

#[derive(Debug, Queryable)]
struct DescriptionDateTime {
    id: i32,
    column_index: i32,
    count: i64,
    unique_count: i64,
    mode: NaiveDateTime,
}

impl ColumnIndex for DescriptionDateTime {
    fn column_index(&self) -> i32 {
        self.column_index
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
    let column_descriptions = desc::description_datetime
        .inner_join(cd::column_description.on(cd::id.eq(desc::description_id)))
        .select((
            cd::id,
            cd::column_index,
            cd::count,
            cd::unique_count,
            desc::mode,
        ))
        .filter(cd::id.eq_any(description_ids))
        .order_by((cd::id, cd::column_index.asc(), cd::count.desc()))
        .load::<DescriptionDateTime>(&mut conn)
        .await?;

    dbg!(column_descriptions
        .iter()
        .map(|c| c.column_index)
        .collect::<Vec<_>>());

    let top_n = top_n::top_n_datetime
        .select((top_n::description_id, top_n::value, top_n::count))
        .filter(top_n::description_id.eq_any(description_ids))
        .order_by(top_n::description_id.asc())
        .load::<TopNDateTime>(&mut conn)
        .await?;

    Ok(super::build_column_statistics(column_descriptions, top_n))
}

use super::{
    schema::{
        column_description::dsl as cd, description_text::dsl as desc, top_n_text::dsl as top_n,
    },
    BatchTimestamp, ColumnIndex, DescriptionIndex, Error, Statistics, ToDescription,
    ToElementCount, ToNLargestCount,
};
use chrono::NaiveDateTime;
use diesel::{ExpressionMethods, JoinOnDsl, QueryDsl};
use diesel_async::{pg::AsyncPgConnection, RunQueryDsl};
use structured::{Description, Element, ElementCount, NLargestCount};

#[derive(Debug, Queryable)]
struct DescriptionText {
    id: i32,
    column_index: i32,
    batch_ts: NaiveDateTime,
    count: i64,
    unique_count: i64,
    mode: String,
}

impl ColumnIndex for DescriptionText {
    fn column_index(&self) -> i32 {
        self.column_index
    }
}

impl BatchTimestamp for DescriptionText {
    fn batch_ts(&self) -> NaiveDateTime {
        self.batch_ts
    }
}

impl DescriptionIndex for DescriptionText {
    fn description_index(&self) -> i32 {
        self.id
    }
}

impl ToDescription for DescriptionText {
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

impl ToNLargestCount for DescriptionText {
    fn to_n_largest_count(self, ec: Vec<ElementCount>) -> NLargestCount {
        NLargestCount::new(
            usize::try_from(self.unique_count).unwrap_or_default(),
            ec,
            Some(Element::Text(self.mode)),
        )
    }
}

#[derive(Debug, Queryable)]
struct TopNText {
    description_id: i32,
    value: String,
    count: i64,
}

impl DescriptionIndex for TopNText {
    fn description_index(&self) -> i32 {
        self.description_id
    }
}

impl ToElementCount for TopNText {
    fn to_element_count(self) -> ElementCount {
        ElementCount {
            value: Element::Text(self.value),
            count: usize::try_from(self.count).unwrap_or_default(),
        }
    }
}

pub(super) async fn get_text_statistics(
    mut conn: AsyncPgConnection,
    description_ids: &[i32],
) -> Result<Vec<Statistics>, Error> {
    let column_descriptions = desc::description_text
        .inner_join(cd::column_description.on(cd::id.eq(desc::description_id)))
        .select((
            cd::id,
            cd::column_index,
            cd::batch_ts,
            cd::count,
            cd::unique_count,
            desc::mode,
        ))
        .filter(cd::id.eq_any(description_ids))
        .order_by((cd::id, cd::column_index.asc(), cd::count.desc()))
        .load::<DescriptionText>(&mut conn)
        .await?;

    let top_n = top_n::top_n_text
        .select((top_n::description_id, top_n::value, top_n::count))
        .filter(top_n::description_id.eq_any(description_ids))
        .order_by(top_n::description_id.asc())
        .load::<TopNText>(&mut conn)
        .await?;

    Ok(super::build_column_statistics(column_descriptions, top_n))
}

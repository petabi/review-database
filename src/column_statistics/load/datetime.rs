use super::{
    schema::{
        column_description::dsl as cd, description_datetime::dsl as desc,
        top_n_datetime::dsl as top_n,
    },
    BlockingPgConn, ColumnIndex, Error, Statistics, ToDescription, ToElementCount, ToNLargestCount,
};
use chrono::NaiveDateTime;
use diesel::{ExpressionMethods, JoinOnDsl, QueryDsl};
use structured::{Description, Element, ElementCount, NLargestCount};

#[derive(Debug, Queryable)]
struct DescriptionDateTime {
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
    column_index: i32,
    value: NaiveDateTime,
    count: i64,
}

impl ColumnIndex for TopNDateTime {
    fn column_index(&self) -> i32 {
        self.column_index
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

pub(super) fn get_datetime_statistics(
    conn: &mut BlockingPgConn,
    description_ids: &[i32],
) -> Result<Vec<Statistics>, Error> {
    let (column_descriptions, top_n) = load(conn, description_ids)?;
    Ok(super::build_column_statistics(column_descriptions, top_n))
}

fn load(
    conn: &mut BlockingPgConn,
    description_ids: &[i32],
) -> Result<(Vec<DescriptionDateTime>, Vec<TopNDateTime>), diesel::result::Error> {
    use diesel::RunQueryDsl;

    let column_descriptions = desc::description_datetime
        .inner_join(cd::column_description.on(cd::id.eq(desc::description_id)))
        .select((cd::column_index, cd::count, cd::unique_count, desc::mode))
        .filter(cd::id.eq_any(description_ids))
        .order_by((cd::column_index.asc(), cd::count.desc()))
        .load::<DescriptionDateTime>(conn)?;

    let top_n = top_n::top_n_datetime
        .inner_join(cd::column_description.on(cd::id.eq(top_n::description_id)))
        .select((cd::column_index, top_n::value, top_n::count))
        .filter(cd::id.eq_any(description_ids))
        .order_by(cd::column_index.asc())
        .load::<TopNDateTime>(conn)?;

    Ok((column_descriptions, top_n))
}

pub(super) async fn async_get_datetime_statistics(
    mut conn: diesel_async::pg::AsyncPgConnection,
    description_ids: &[i32],
) -> Result<Vec<Statistics>, Error> {
    use diesel_async::RunQueryDsl;

    let column_descriptions = desc::description_datetime
        .inner_join(cd::column_description.on(cd::id.eq(desc::description_id)))
        .select((cd::column_index, cd::count, cd::unique_count, desc::mode))
        .filter(cd::id.eq_any(description_ids))
        .order_by((cd::column_index.asc(), cd::count.desc()))
        .load::<DescriptionDateTime>(&mut conn)
        .await?;

    let top_n = top_n::top_n_datetime
        .inner_join(cd::column_description.on(cd::id.eq(top_n::description_id)))
        .select((cd::column_index, top_n::value, top_n::count))
        .filter(cd::id.eq_any(description_ids))
        .order_by(cd::column_index.asc())
        .load::<TopNDateTime>(&mut conn)
        .await?;

    Ok(super::build_column_statistics(column_descriptions, top_n))
}

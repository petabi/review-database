use super::{
    schema::{
        column_description::dsl as cd, description_binary::dsl as desc, top_n_binary::dsl as top_n,
    },
    BlockingPgConn, ColumnIndex, Error, Statistics, ToDescription, ToElementCount, ToNLargestCount,
};
use diesel::{ExpressionMethods, JoinOnDsl, QueryDsl};
use structured::{Description, Element, ElementCount, NLargestCount};

#[derive(Debug, Queryable)]
struct DescriptionBinary {
    column_index: i32,
    count: i64,
    unique_count: i64,
    mode: Vec<u8>,
}

impl ColumnIndex for DescriptionBinary {
    fn column_index(&self) -> i32 {
        self.column_index
    }
}

impl ToDescription for DescriptionBinary {
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

impl ToNLargestCount for DescriptionBinary {
    fn to_n_largest_count(self, ec: Vec<ElementCount>) -> NLargestCount {
        NLargestCount::new(
            usize::try_from(self.unique_count).unwrap_or_default(),
            ec,
            Some(Element::Binary(self.mode)),
        )
    }
}

#[derive(Debug, Queryable)]
struct TopNBinary {
    column_index: i32,
    value: Vec<u8>,
    count: i64,
}

impl ColumnIndex for TopNBinary {
    fn column_index(&self) -> i32 {
        self.column_index
    }
}

impl ToElementCount for TopNBinary {
    fn to_element_count(self) -> ElementCount {
        ElementCount {
            value: Element::Binary(self.value),
            count: usize::try_from(self.count).unwrap_or_default(),
        }
    }
}

pub(super) fn get_binary_statistics(
    conn: &mut BlockingPgConn,
    description_ids: &[i32],
) -> Result<Vec<Statistics>, Error> {
    let (column_descriptions, top_n) = load(conn, description_ids)?;
    Ok(super::build_column_statistics(column_descriptions, top_n))
}

fn load(
    conn: &mut BlockingPgConn,
    description_ids: &[i32],
) -> Result<(Vec<DescriptionBinary>, Vec<TopNBinary>), diesel::result::Error> {
    use diesel::RunQueryDsl;

    let column_descriptions = desc::description_binary
        .inner_join(cd::column_description.on(cd::id.eq(desc::description_id)))
        .select((cd::column_index, cd::count, cd::unique_count, desc::mode))
        .filter(cd::id.eq_any(description_ids))
        .order_by((cd::column_index.asc(), cd::count.desc()))
        .load::<DescriptionBinary>(conn)?;

    let top_n = top_n::top_n_binary
        .inner_join(cd::column_description.on(cd::id.eq(top_n::description_id)))
        .select((cd::column_index, top_n::value, top_n::count))
        .filter(cd::id.eq_any(description_ids))
        .order_by(cd::column_index.asc())
        .load::<TopNBinary>(conn)?;

    Ok((column_descriptions, top_n))
}

pub(super) async fn async_get_binary_statistics(
    mut conn: diesel_async::pg::AsyncPgConnection,
    description_ids: &[i32],
) -> Result<Vec<Statistics>, Error> {
    use diesel_async::RunQueryDsl;

    let column_descriptions = desc::description_binary
        .inner_join(cd::column_description.on(cd::id.eq(desc::description_id)))
        .select((cd::column_index, cd::count, cd::unique_count, desc::mode))
        .filter(cd::id.eq_any(description_ids))
        .order_by((cd::column_index.asc(), cd::count.desc()))
        .load::<DescriptionBinary>(&mut conn)
        .await?;

    let top_n = top_n::top_n_binary
        .inner_join(cd::column_description.on(cd::id.eq(top_n::description_id)))
        .select((cd::column_index, top_n::value, top_n::count))
        .filter(cd::id.eq_any(description_ids))
        .order_by(cd::column_index.asc())
        .load::<TopNBinary>(&mut conn)
        .await?;

    Ok(super::build_column_statistics(column_descriptions, top_n))
}

use super::{
    schema::{
        column_description::dsl as cd, description_enum::dsl as desc, top_n_enum::dsl as top_n,
    },
    BlockingPgConn, ColumnIndex, Error, Statistics, ToDescription, ToElementCount, ToNLargestCount,
};
use diesel::prelude::*;
use structured::{Description, Element, ElementCount, NLargestCount};

#[derive(Debug, Queryable)]
struct DescriptionEnum {
    column_index: i32,
    count: i64,
    unique_count: i64,
    mode: String,
}

impl ColumnIndex for DescriptionEnum {
    fn column_index(&self) -> i32 {
        self.column_index
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
    column_index: i32,
    value: String,
    count: i64,
}

impl ColumnIndex for TopNEnum {
    fn column_index(&self) -> i32 {
        self.column_index
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

pub(super) fn get_enum_statistics(
    conn: &mut BlockingPgConn,
    description_ids: &[i32],
) -> Result<Vec<Statistics>, Error> {
    let (column_descriptions, top_n) = load(conn, description_ids)?;
    Ok(super::build_column_statistics(column_descriptions, top_n))
}

fn load(
    conn: &mut BlockingPgConn,
    description_ids: &[i32],
) -> Result<(Vec<DescriptionEnum>, Vec<TopNEnum>), diesel::result::Error> {
    let column_descriptions = desc::description_enum
        .inner_join(cd::column_description.on(cd::id.eq(desc::description_id)))
        .select((cd::column_index, cd::count, cd::unique_count, desc::mode))
        .filter(cd::id.eq_any(description_ids))
        .order_by((cd::column_index.asc(), cd::count.desc()))
        .load::<DescriptionEnum>(conn)?;

    let top_n = top_n::top_n_enum
        .inner_join(cd::column_description.on(cd::id.eq(top_n::description_id)))
        .select((cd::column_index, top_n::value, top_n::count))
        .filter(cd::id.eq_any(description_ids))
        .order_by(cd::column_index.asc())
        .load::<TopNEnum>(conn)?;

    Ok((column_descriptions, top_n))
}

use super::{
    schema::{
        column_description::dsl as cd, description_float::dsl as desc, top_n_float::dsl as top_n,
    },
    BlockingPgConn, ColumnIndex, Error, Statistics, ToDescription, ToElementCount, ToNLargestCount,
};
use diesel::{ExpressionMethods, JoinOnDsl, QueryDsl};
use structured::{Description, Element, ElementCount, FloatRange, NLargestCount};

#[derive(Debug, Queryable)]
struct DescriptionFloat {
    column_index: i32,
    count: i64,
    unique_count: i64,
    mode_smallest: f64,
    mode_largest: f64,
    min: Option<f64>,
    max: Option<f64>,
    mean: Option<f64>,
    s_deviation: Option<f64>,
}

impl ColumnIndex for DescriptionFloat {
    fn column_index(&self) -> i32 {
        self.column_index
    }
}

impl ToDescription for DescriptionFloat {
    fn to_description(&self) -> Description {
        Description::new(
            usize::try_from(self.count).unwrap_or_default(),
            self.mean,
            self.s_deviation,
            self.min.map(Element::Float),
            self.max.map(Element::Float),
        )
    }
}

impl ToNLargestCount for DescriptionFloat {
    fn to_n_largest_count(self, ec: Vec<ElementCount>) -> NLargestCount {
        NLargestCount::new(
            usize::try_from(self.unique_count).unwrap_or_default(),
            ec,
            Some(Element::FloatRange(FloatRange {
                smallest: self.mode_smallest,
                largest: self.mode_largest,
            })),
        )
    }
}

#[derive(Debug, Queryable)]
struct TopNFloat {
    column_index: i32,
    value_smallest: f64,
    value_largest: f64,
    count: i64,
}

impl ColumnIndex for TopNFloat {
    fn column_index(&self) -> i32 {
        self.column_index
    }
}

impl ToElementCount for TopNFloat {
    fn to_element_count(self) -> ElementCount {
        ElementCount {
            value: Element::FloatRange(FloatRange {
                smallest: self.value_smallest,
                largest: self.value_largest,
            }),
            count: usize::try_from(self.count).unwrap_or_default(),
        }
    }
}

pub(super) fn get_float_statistics(
    conn: &mut BlockingPgConn,
    description_ids: &[i32],
) -> Result<Vec<Statistics>, Error> {
    let (column_descriptions, top_n) = load(conn, description_ids)?;
    Ok(super::build_column_statistics(column_descriptions, top_n))
}

fn load(
    conn: &mut BlockingPgConn,
    description_ids: &[i32],
) -> Result<(Vec<DescriptionFloat>, Vec<TopNFloat>), diesel::result::Error> {
    use diesel::RunQueryDsl;

    let column_descriptions = desc::description_float
        .inner_join(cd::column_description.on(cd::id.eq(desc::description_id)))
        .select((
            cd::column_index,
            cd::count,
            cd::unique_count,
            desc::mode_smallest,
            desc::mode_largest,
            desc::min,
            desc::max,
            desc::mean,
            desc::s_deviation,
        ))
        .filter(cd::id.eq_any(description_ids))
        .order_by((cd::column_index.asc(), cd::count.desc()))
        .load::<DescriptionFloat>(conn)?;

    let top_n = top_n::top_n_float
        .inner_join(cd::column_description.on(cd::id.eq(top_n::description_id)))
        .select((
            cd::column_index,
            top_n::value_smallest,
            top_n::value_largest,
            top_n::count,
        ))
        .filter(cd::id.eq_any(description_ids))
        .order_by(cd::column_index.asc())
        .load::<TopNFloat>(conn)?;

    Ok((column_descriptions, top_n))
}

pub(super) async fn async_get_float_statistics(
    mut conn: diesel_async::pg::AsyncPgConnection,
    description_ids: &[i32],
) -> Result<Vec<Statistics>, Error> {
    use diesel_async::RunQueryDsl;

    let column_descriptions = desc::description_float
        .inner_join(cd::column_description.on(cd::id.eq(desc::description_id)))
        .select((
            cd::column_index,
            cd::count,
            cd::unique_count,
            desc::mode_smallest,
            desc::mode_largest,
            desc::min,
            desc::max,
            desc::mean,
            desc::s_deviation,
        ))
        .filter(cd::id.eq_any(description_ids))
        .order_by((cd::column_index.asc(), cd::count.desc()))
        .load::<DescriptionFloat>(&mut conn)
        .await?;

    let top_n = top_n::top_n_float
        .inner_join(cd::column_description.on(cd::id.eq(top_n::description_id)))
        .select((
            cd::column_index,
            top_n::value_smallest,
            top_n::value_largest,
            top_n::count,
        ))
        .filter(cd::id.eq_any(description_ids))
        .order_by(cd::column_index.asc())
        .load::<TopNFloat>(&mut conn)
        .await?;

    Ok(super::build_column_statistics(column_descriptions, top_n))
}

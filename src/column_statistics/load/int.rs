use super::{
    schema::{
        column_description::dsl as cd, description_int::dsl as desc, top_n_int::dsl as top_n,
    },
    BlockingPgConn, ColumnIndex, Error, Statistics, ToDescription, ToElementCount, ToNLargestCount,
};
use diesel::{ExpressionMethods, JoinOnDsl, QueryDsl};
use structured::{Description, Element, ElementCount, NLargestCount};

#[derive(Debug, Queryable)]
struct DescriptionInt {
    column_index: i32,
    count: i64,
    unique_count: i64,
    mode: i64,
    min: Option<i64>,
    max: Option<i64>,
    mean: Option<f64>,
    s_deviation: Option<f64>,
}

impl ColumnIndex for DescriptionInt {
    fn column_index(&self) -> i32 {
        self.column_index
    }
}

impl ToDescription for DescriptionInt {
    fn to_description(&self) -> Description {
        Description::new(
            usize::try_from(self.count).unwrap_or_default(),
            self.mean,
            self.s_deviation,
            self.min.map(Element::Int),
            self.max.map(Element::Int),
        )
    }
}

impl ToNLargestCount for DescriptionInt {
    fn to_n_largest_count(self, ec: Vec<ElementCount>) -> NLargestCount {
        NLargestCount::new(
            usize::try_from(self.unique_count).unwrap_or_default(),
            ec,
            Some(Element::Int(self.mode)),
        )
    }
}

#[derive(Debug, Queryable)]
struct TopNInt {
    column_index: i32,
    value: i64,
    count: i64,
}

impl ColumnIndex for TopNInt {
    fn column_index(&self) -> i32 {
        self.column_index
    }
}

impl ToElementCount for TopNInt {
    fn to_element_count(self) -> ElementCount {
        ElementCount {
            value: Element::Int(self.value),
            count: usize::try_from(self.count).unwrap_or_default(),
        }
    }
}

pub(super) fn get_int_statistics(
    conn: &mut BlockingPgConn,
    description_ids: &[i32],
) -> Result<Vec<Statistics>, Error> {
    let (column_descriptions, top_n) = load(conn, description_ids)?;
    Ok(super::build_column_statistics(column_descriptions, top_n))
}

fn load(
    conn: &mut BlockingPgConn,
    description_ids: &[i32],
) -> Result<(Vec<DescriptionInt>, Vec<TopNInt>), diesel::result::Error> {
    use diesel::RunQueryDsl;

    let column_descriptions = desc::description_int
        .inner_join(cd::column_description.on(cd::id.eq(desc::description_id)))
        .select((
            cd::column_index,
            cd::count,
            cd::unique_count,
            desc::mode,
            desc::min,
            desc::max,
            desc::mean,
            desc::s_deviation,
        ))
        .filter(cd::id.eq_any(description_ids))
        .order_by((cd::column_index.asc(), cd::count.desc()))
        .load::<DescriptionInt>(conn)?;

    let top_n = top_n::top_n_int
        .inner_join(cd::column_description.on(cd::id.eq(top_n::description_id)))
        .select((cd::column_index, top_n::value, top_n::count))
        .filter(cd::id.eq_any(description_ids))
        .order_by(cd::column_index.asc())
        .load::<TopNInt>(conn)?;

    Ok((column_descriptions, top_n))
}

pub(super) async fn async_get_int_statistics(
    mut conn: diesel_async::pg::AsyncPgConnection,
    description_ids: &[i32],
) -> Result<Vec<Statistics>, Error> {
    use diesel_async::RunQueryDsl;

    let column_descriptions = desc::description_int
        .inner_join(cd::column_description.on(cd::id.eq(desc::description_id)))
        .select((
            cd::column_index,
            cd::count,
            cd::unique_count,
            desc::mode,
            desc::min,
            desc::max,
            desc::mean,
            desc::s_deviation,
        ))
        .filter(cd::id.eq_any(description_ids))
        .order_by((cd::column_index.asc(), cd::count.desc()))
        .load::<DescriptionInt>(&mut conn)
        .await?;

    let top_n = top_n::top_n_int
        .inner_join(cd::column_description.on(cd::id.eq(top_n::description_id)))
        .select((cd::column_index, top_n::value, top_n::count))
        .filter(cd::id.eq_any(description_ids))
        .order_by(cd::column_index.asc())
        .load::<TopNInt>(&mut conn)
        .await?;

    Ok(super::build_column_statistics(column_descriptions, top_n))
}

#[cfg(test)]
mod tests {
    use super::super::top_n_to_element_counts;
    use super::*;

    impl TopNInt {
        fn new(column_index: i32, value: i64, count: i64) -> Self {
            Self {
                column_index,
                value,
                count,
            }
        }
    }

    #[tokio::test]
    async fn convert_top_n_int_to_element_count() {
        let top_n = vec![
            TopNInt::new(5, 15, 5), // ec1
            TopNInt::new(1, 1, 10), // ec2
            TopNInt::new(1, 5, 30), // ec3
            TopNInt::new(1, 2, 15), // ec4
            TopNInt::new(3, 3, 3),  // ec5
        ];

        let ec1 = ElementCount {
            value: Element::Int(15),
            count: 5,
        };
        let ec2 = ElementCount {
            value: Element::Int(1),
            count: 10,
        };
        let ec3 = ElementCount {
            value: Element::Int(5),
            count: 30,
        };
        let ec4 = ElementCount {
            value: Element::Int(2),
            count: 15,
        };
        let ec5 = ElementCount {
            value: Element::Int(3),
            count: 3,
        };

        let element_counts = vec![vec![ec3, ec4, ec2], vec![ec5], vec![ec1]];
        assert_eq!(top_n_to_element_counts(top_n), element_counts);
    }
}

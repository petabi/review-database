use std::collections::HashMap;

use chrono::NaiveDateTime;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{RunQueryDsl, pg::AsyncPgConnection};
use structured::{Description, Element, ElementCount, NLargestCount};

use super::{
    BatchTimestamp, ColumnIndex, DescriptionIndex, Error, Statistics, ToDescription,
    ToElementCount, ToNLargestCount,
    schema::{
        column_description::dsl as cd, description_int::dsl as desc, top_n_int::dsl as top_n,
    },
};

#[derive(Debug, Queryable)]
struct DescriptionInt {
    id: i32,
    column_index: i32,
    batch_ts: NaiveDateTime,
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
impl BatchTimestamp for DescriptionInt {
    fn batch_ts(&self) -> NaiveDateTime {
        self.batch_ts
    }
}

impl DescriptionIndex for DescriptionInt {
    fn description_index(&self) -> i32 {
        self.id
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
    description_id: i32,
    value: i64,
    count: i64,
}

impl DescriptionIndex for TopNInt {
    fn description_index(&self) -> i32 {
        self.description_id
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

pub(super) async fn get_int_statistics(
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

    let modes: HashMap<_, _> = desc::description_int
        .select((
            desc::description_id,
            desc::mode,
            desc::min,
            desc::max,
            desc::mean,
            desc::s_deviation,
        ))
        .filter(desc::description_id.eq_any(description_ids))
        .load::<(i32, i64, Option<i64>, Option<i64>, Option<f64>, Option<f64>)>(&mut conn)
        .await?
        .into_iter()
        .map(|(id, mode, min, max, mean, s_deviation)| (id, (mode, min, max, mean, s_deviation)))
        .collect();

    let column_descriptions: Vec<DescriptionInt> = column_descriptions
        .into_iter()
        .filter_map(|(id, column_index, batch_ts, count, unique_count)| {
            modes
                .get(&id)
                .map(|(mode, min, max, mean, s_deviation)| DescriptionInt {
                    id,
                    column_index,
                    batch_ts,
                    count,
                    unique_count,
                    mode: *mode,
                    min: *min,
                    max: *max,
                    mean: *mean,
                    s_deviation: *s_deviation,
                })
        })
        .collect();

    let top_n = top_n::top_n_int
        .select((top_n::description_id, top_n::value, top_n::count))
        .filter(top_n::description_id.eq_any(description_ids))
        .order_by(top_n::description_id.asc())
        .load::<TopNInt>(&mut conn)
        .await?;

    Ok(super::build_column_statistics(column_descriptions, top_n))
}

#[cfg(test)]
mod tests {
    use super::super::top_n_to_element_counts;
    use super::*;

    impl TopNInt {
        fn new(description_id: i32, value: i64, count: i64) -> Self {
            Self {
                description_id,
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
        let element_counts = vec![1, 3, 5]
            .into_iter()
            .zip(element_counts.into_iter())
            .collect();
        assert_eq!(top_n_to_element_counts(top_n), element_counts);
    }
}

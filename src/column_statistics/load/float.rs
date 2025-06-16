use std::collections::HashMap;

use chrono::NaiveDateTime;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{RunQueryDsl, pg::AsyncPgConnection};
use structured::{Description, Element, ElementCount, FloatRange, NLargestCount};

use super::{
    BatchTimestamp, ColumnIndex, DescriptionIndex, Error, Statistics, ToDescription,
    ToElementCount, ToNLargestCount,
    schema::{
        column_description::dsl as cd, description_float::dsl as desc, top_n_float::dsl as top_n,
    },
};

#[derive(Debug, Queryable)]
struct DescriptionFloat {
    id: i32,
    column_index: i32,
    batch_ts: NaiveDateTime,
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

impl BatchTimestamp for DescriptionFloat {
    fn batch_ts(&self) -> NaiveDateTime {
        self.batch_ts
    }
}

impl DescriptionIndex for DescriptionFloat {
    fn description_index(&self) -> i32 {
        self.id
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
    description_id: i32,
    value_smallest: f64,
    value_largest: f64,
    count: i64,
}

impl DescriptionIndex for TopNFloat {
    fn description_index(&self) -> i32 {
        self.description_id
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

pub(super) async fn get_float_statistics(
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

    let modes: HashMap<_, _> = desc::description_float
        .select((
            desc::description_id,
            desc::mode_smallest,
            desc::mode_largest,
            desc::min,
            desc::max,
            desc::mean,
            desc::s_deviation,
        ))
        .filter(desc::description_id.eq_any(description_ids))
        .load::<(
            i32,
            f64,
            f64,
            Option<f64>,
            Option<f64>,
            Option<f64>,
            Option<f64>,
        )>(&mut conn)
        .await?
        .into_iter()
        .map(
            |(id, mode_smallest, mode_largest, min, max, mean, s_deviation)| {
                (
                    id,
                    (mode_smallest, mode_largest, min, max, mean, s_deviation),
                )
            },
        )
        .collect();

    let column_descriptions: Vec<DescriptionFloat> = column_descriptions
        .into_iter()
        .filter_map(|(id, column_index, batch_ts, count, unique_count)| {
            modes.get(&id).map(
                |(mode_smallest, mode_largest, min, max, mean, s_deviation)| DescriptionFloat {
                    id,
                    column_index,
                    batch_ts,
                    count,
                    unique_count,
                    mode_smallest: *mode_smallest,
                    mode_largest: *mode_largest,
                    min: *min,
                    max: *max,
                    mean: *mean,
                    s_deviation: *s_deviation,
                },
            )
        })
        .collect();

    let top_n = top_n::top_n_float
        .select((
            top_n::description_id,
            top_n::value_smallest,
            top_n::value_largest,
            top_n::count,
        ))
        .filter(top_n::description_id.eq_any(description_ids))
        .order_by(top_n::description_id.asc())
        .load::<TopNFloat>(&mut conn)
        .await?;

    Ok(super::build_column_statistics(column_descriptions, top_n))
}

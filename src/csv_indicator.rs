use crate::{
    schema::{csv_column_list, csv_indicator, csv_whitelist},
    Error,
};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl};
use diesel_async::{pg::AsyncPgConnection, RunQueryDsl};
use std::collections::HashMap;

pub(crate) async fn get_whitelists(
    conn: &mut AsyncPgConnection,
    model_id: i32,
    column_indices: &[usize],
) -> Result<HashMap<usize, String>, Error> {
    use csv_column_list::dsl as list_d;
    use csv_whitelist::dsl as w_d;

    let Some(whitelist_names) = list_d::csv_column_list
        .select(list_d::column_whitelist)
        .filter(list_d::model_id.eq(model_id))
        .get_result::<Option<Vec<Option<String>>>>(conn)
        .await
        .optional()?.flatten() else {
            return Ok(HashMap::new());
    };

    let whitelist_names_indices: HashMap<String, usize> = column_indices
        .iter()
        .filter_map(|i| {
            whitelist_names.get(*i).and_then(|n| {
                if let Some(n) = n {
                    if n.is_empty() {
                        None
                    } else {
                        Some((n.clone(), *i))
                    }
                } else {
                    None
                }
            })
        })
        .collect();
    let whitelist_names: Vec<String> = whitelist_names_indices
        .keys()
        .map(std::clone::Clone::clone)
        .collect();
    let whitelists = w_d::csv_whitelist
        .select((w_d::name, w_d::list))
        .filter(w_d::name.eq_any(&whitelist_names))
        .get_results::<(String, String)>(conn)
        .await
        .optional()?
        .unwrap_or_default();
    Ok(whitelists
        .into_iter()
        .map(|(name, value)| (*whitelist_names_indices.get(&name).expect(""), value))
        .collect())
}

pub(crate) async fn get_csv_indicators(
    conn: &mut AsyncPgConnection,
    model_id: i32,
    column_indices: &[usize],
) -> Result<HashMap<usize, String>, Error> {
    use csv_column_list::dsl as list_d;
    use csv_indicator::dsl as i_d;

    let Some(Some(indicator_names)) = list_d::csv_column_list
        .select(list_d::column_indicator)
        .filter(list_d::model_id.eq(model_id))
        .get_result::<Option<Vec<Option<String>>>>(conn)
        .await
        .optional()? else {
            return Ok(HashMap::new());
    };
    let indicator_names_indices: HashMap<String, usize> = column_indices
        .iter()
        .filter_map(|i| {
            indicator_names.get(*i).and_then(|n| {
                if let Some(n) = n {
                    if n.is_empty() {
                        None
                    } else {
                        Some((n.clone(), *i))
                    }
                } else {
                    None
                }
            })
        })
        .collect();
    let indicator_names: Vec<String> = indicator_names_indices
        .keys()
        .map(std::clone::Clone::clone)
        .collect();
    let indicators = i_d::csv_indicator
        .select((i_d::name, i_d::list))
        .filter(i_d::name.eq_any(&indicator_names))
        .get_results::<(String, String)>(conn)
        .await
        .optional()?
        .unwrap_or_default();

    Ok(indicators
        .into_iter()
        .map(|(name, value)| {
            (
                *indicator_names_indices.get(&name).expect("already checked"),
                value,
            )
        })
        .collect())
}

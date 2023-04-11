use crate::{
    schema::{csv_column_list, csv_indicator, csv_whitelist},
    BlockingPgConn, Error,
};
use diesel::{ExpressionMethods, QueryDsl};
use std::collections::HashMap;

pub(crate) fn get_whitelists(
    conn: &mut BlockingPgConn,
    model_id: i32,
    column_indices: &[usize],
) -> HashMap<usize, String> {
    use csv_column_list::dsl as list_d;
    use csv_whitelist::dsl as w_d;
    use diesel::RunQueryDsl;

    let whitelist_names = match list_d::csv_column_list
        .select(list_d::column_whitelist)
        .filter(list_d::model_id.eq(model_id))
        .get_result::<Option<Vec<String>>>(conn)
    {
        Ok(names) => names,
        Err(_) => None,
    };
    let whitelists: HashMap<usize, String> = whitelist_names.map_or_else(HashMap::new, |names| {
        let whitelist_names_indices: HashMap<String, usize> = column_indices
            .iter()
            .filter_map(|i| {
                names.get(*i).and_then(|n| {
                    if n.is_empty() {
                        None
                    } else {
                        Some((n.clone(), *i))
                    }
                })
            })
            .collect();
        let whitelist_names: Vec<String> = whitelist_names_indices
            .keys()
            .map(std::clone::Clone::clone)
            .collect();
        let whitelists: Vec<(String, String)> = match w_d::csv_whitelist
            .select((w_d::name, w_d::list))
            .filter(w_d::name.eq_any(&whitelist_names))
            .get_results::<(String, String)>(conn)
        {
            Ok(lists) => lists,
            Err(_) => Vec::new(),
        };
        whitelists
            .into_iter()
            .map(|(name, value)| (*whitelist_names_indices.get(&name).expect(""), value))
            .collect()
    });

    whitelists
}

pub(crate) fn get_csv_indicators(
    conn: &mut BlockingPgConn,
    model_id: i32,
    column_indices: &[usize],
) -> HashMap<usize, String> {
    use csv_column_list::dsl as list_d;
    use csv_indicator::dsl as i_d;
    use diesel::RunQueryDsl;

    let indicator_names = match list_d::csv_column_list
        .select(list_d::column_indicator)
        .filter(list_d::model_id.eq(model_id))
        .get_result::<Option<Vec<String>>>(conn)
    {
        Ok(names) => names,
        Err(_) => None,
    };
    let indicators: HashMap<usize, String> = indicator_names.map_or_else(HashMap::new, |names| {
        let indicator_names_indices: HashMap<String, usize> = column_indices
            .iter()
            .filter_map(|i| {
                names.get(*i).and_then(|n| {
                    if n.is_empty() {
                        None
                    } else {
                        Some((n.clone(), *i))
                    }
                })
            })
            .collect();
        let indicator_names: Vec<String> = indicator_names_indices
            .keys()
            .map(std::clone::Clone::clone)
            .collect();
        let indicators: Vec<(String, String)> = match i_d::csv_indicator
            .select((i_d::name, i_d::list))
            .filter(i_d::name.eq_any(&indicator_names))
            .get_results::<(String, String)>(conn)
        {
            Ok(lists) => lists,
            Err(_) => Vec::new(),
        };
        indicators
            .into_iter()
            .map(|(name, value)| {
                (
                    *indicator_names_indices.get(&name).expect("already checked"),
                    value,
                )
            })
            .collect()
    });

    indicators
}

pub(crate) async fn async_get_csv_indicators(
    conn: &mut diesel_async::pg::AsyncPgConnection,
    model_id: i32,
    column_indices: &[usize],
) -> Result<HashMap<usize, String>, Error> {
    use csv_column_list::dsl as list_d;
    use csv_indicator::dsl as i_d;
    use diesel_async::RunQueryDsl;

    let indicator_names = list_d::csv_column_list
        .select(list_d::column_indicator)
        .filter(list_d::model_id.eq(model_id))
        .get_result::<Option<Vec<String>>>(conn)
        .await?;

    let Some(names) = indicator_names else {
        return Ok(HashMap::new());
    };
    let indicator_names_indices: HashMap<String, usize> = column_indices
        .iter()
        .filter_map(|i| {
            names.get(*i).and_then(|n| {
                if n.is_empty() {
                    None
                } else {
                    Some((n.clone(), *i))
                }
            })
        })
        .collect();
    let indicator_names: Vec<String> = indicator_names_indices
        .keys()
        .map(std::clone::Clone::clone)
        .collect();
    let indicators: Vec<(String, String)> = i_d::csv_indicator
        .select((i_d::name, i_d::list))
        .filter(i_d::name.eq_any(&indicator_names))
        .get_results::<(String, String)>(conn)
        .await?;

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

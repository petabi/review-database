use super::{
    schema::{
        column_description::dsl as cd, description_ipaddr::dsl as desc, top_n_ipaddr::dsl as top_n,
    },
    BlockingPgConn, ColumnIndex, Error, Statistics, ToDescription, ToElementCount, ToNLargestCount,
};
use diesel::prelude::*;
use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};
use structured::{Description, Element, ElementCount, NLargestCount};

#[derive(Debug, Queryable)]
struct DescriptionIpAddr {
    column_index: i32,
    count: i64,
    unique_count: i64,
    mode: String,
}

impl ColumnIndex for DescriptionIpAddr {
    fn column_index(&self) -> i32 {
        self.column_index
    }
}

impl ToDescription for DescriptionIpAddr {
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

impl ToNLargestCount for DescriptionIpAddr {
    fn to_n_largest_count(self, ec: Vec<ElementCount>) -> NLargestCount {
        let ipaddr = IpAddr::V4(
            Ipv4Addr::from_str(&self.mode).unwrap_or_else(|_| Ipv4Addr::new(0, 0, 0, 0)),
        );
        NLargestCount::new(
            usize::try_from(self.unique_count).unwrap_or_default(),
            ec,
            Some(Element::IpAddr(ipaddr)),
        )
    }
}

#[derive(Debug, Queryable)]
struct TopNIpAddr {
    column_index: i32,
    value: String,
    count: i64,
}

impl ColumnIndex for TopNIpAddr {
    fn column_index(&self) -> i32 {
        self.column_index
    }
}

impl ToElementCount for TopNIpAddr {
    fn to_element_count(self) -> ElementCount {
        let ipaddr = IpAddr::V4(
            Ipv4Addr::from_str(&self.value).unwrap_or_else(|_| Ipv4Addr::new(0, 0, 0, 0)),
        );
        ElementCount {
            value: Element::IpAddr(ipaddr),
            count: usize::try_from(self.count).unwrap_or_default(),
        }
    }
}

pub(super) fn get_ipaddr_statistics(
    conn: &mut BlockingPgConn,
    description_ids: &[i32],
) -> Result<Vec<Statistics>, Error> {
    let (column_descriptions, top_n) = load(conn, description_ids)?;
    Ok(super::build_column_statistics(column_descriptions, top_n))
}

fn load(
    conn: &mut BlockingPgConn,
    description_ids: &[i32],
) -> Result<(Vec<DescriptionIpAddr>, Vec<TopNIpAddr>), diesel::result::Error> {
    let column_descriptions = desc::description_ipaddr
        .inner_join(cd::column_description.on(cd::id.eq(desc::description_id)))
        .select((cd::column_index, cd::count, cd::unique_count, desc::mode))
        .filter(cd::id.eq_any(description_ids))
        .order_by((cd::column_index.asc(), cd::count.desc()))
        .load::<DescriptionIpAddr>(conn)?;

    let top_n = top_n::top_n_ipaddr
        .inner_join(cd::column_description.on(cd::id.eq(top_n::description_id)))
        .select((cd::column_index, top_n::value, top_n::count))
        .filter(cd::id.eq_any(description_ids))
        .order_by(cd::column_index.asc())
        .load::<TopNIpAddr>(conn)?;

    Ok((column_descriptions, top_n))
}

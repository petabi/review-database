use crate::{self as database, Error, OrderDirection};
use bb8_postgres::tokio_postgres::{self, types::ToSql, Row, ToStatement};
use bytes::BytesMut;
use std::{
    any::Any, cell::RefCell, collections::HashMap, convert::TryFrom, path::Path, sync::Arc,
    sync::Mutex,
};

pub type Value = dyn ToSql + Sync;

pub struct BlockingConnection();

impl database::BlockingConnection for BlockingConnection {}

pub struct BlockingConnectionPool();

impl database::BlockingConnectionPool for BlockingConnectionPool {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn get(&self) -> Result<Box<dyn database::BlockingConnection>, Error> {
        Ok(Box::new(BlockingConnection {}))
    }
}

#[derive(Clone)]
pub struct Connection {
    tables: Arc<Mutex<RefCell<HashMap<String, HashMap<String, Vec<Option<BytesMut>>>>>>>,
}

impl Connection {
    pub async fn build_transaction(&mut self) -> Result<Transaction, Error> {
        unimplemented!()
    }

    pub async fn count(
        &self,
        table: &str,
        _variables: &[(&str, database::Type)],
        _any_variables: &[(&str, database::Type)],
        _values: &[&(dyn ToSql + Sync)],
    ) -> Result<i64, Error> {
        let guard = self.tables.lock().unwrap();
        if !guard.borrow().contains_key(table) {
            guard.borrow_mut().insert(table.to_string(), HashMap::new());
        }
        let mut tables = guard.borrow_mut();
        let table = tables.get_mut(table).expect("contains key");
        let len = table
            .values()
            .next()
            .map(|v| v.iter().filter(|&v| v.is_some()).count())
            .unwrap_or_default();
        Ok(i64::try_from(len).unwrap_or(i64::MAX))
    }

    pub async fn delete_from(
        &self,
        _table: &str,
        _variables: &[(&str, database::Type)],
        _values: &[&(dyn ToSql + Sync)],
    ) -> Result<i64, Error> {
        unimplemented!()
    }

    pub async fn delete_in(
        &self,
        _table: &str,
        _variables: &[(&str, database::Type)],
        _any_variables: &[(&str, database::Type)],
        _values: &[&(dyn ToSql + Sync)],
    ) -> Result<i64, Error> {
        unimplemented!()
    }

    pub async fn insert_into(
        &self,
        table: &str,
        columns: &[(&str, database::Type)],
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<i32, Error> {
        let guard = self.tables.lock().unwrap();
        if !guard.borrow().contains_key(table) {
            guard.borrow_mut().insert(table.to_string(), HashMap::new());
        }
        let mut tables = guard.borrow_mut();
        let table = tables.get_mut(table).expect("contains key");
        for ((f, ty), &v) in columns.iter().zip(values.iter()) {
            if !table.contains_key(*f) {
                table.insert((*f).to_string(), Vec::new());
            }
            let col = table.get_mut(*f).expect("contains key");
            let mut buf = BytesMut::new();
            if let Err(e) = v.to_sql_checked(ty, &mut buf) {
                return Err(Error::InvalidInput(format!("insertion failed: {e}")));
            }
            col.push(Some(buf));
        }
        Ok(columns
            .first()
            .and_then(|col| table.get(col.0))
            .map(|col| i32::try_from(col.len()).unwrap_or(i32::MAX))
            .unwrap_or_default())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn select_slice<D>(
        &self,
        _table: &str,
        _columns: &[&str],
        _variables: &[(&str, database::Type)],
        _any_variables: &[(&str, database::Type)],
        _values: &[&(dyn ToSql + Sync)],
        _key: &(&str, database::Type),
        _order: OrderDirection,
        _cursors: (bool, bool),
        _is_first: bool,
        _limit: usize,
    ) -> Result<D, Error> {
        unimplemented!()
    }

    #[allow(dead_code)]
    pub async fn select_in<D>(
        &self,
        _table: &str,
        _columns: &[&str],
        _variables: &[(&str, database::Type)],
        _any_variables: &[(&str, database::Type)],
        _array_variables: &[(&str, database::Type)],
        _values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<D>, Error> {
        unimplemented!()
    }

    /// Selects a single row from a table.
    pub async fn select_one_from<D>(
        &self,
        _table: &str,
        _columns: &[&str],
        _variables: &[(&str, database::Type)],
        _values: &[&(dyn ToSql + Sync)],
    ) -> Result<D, Error> {
        unimplemented!()
    }

    pub async fn select_one_opt_from<D>(
        &self,
        _table: &str,
        _columns: &[&str],
        _variables: &[(&str, database::Type)],
        _values: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<D>, Error> {
        unimplemented!()
    }

    pub async fn update(
        &self,
        _table: &str,
        _id: i32,
        _columns: &[(&str, database::Type)],
        _values: &[&(dyn ToSql + Sync)],
    ) -> Result<(), Error> {
        unimplemented!()
    }

    /// Executes a function.
    pub async fn execute_function(
        &self,
        _function: &str,
        _arguments: &[database::Type],
        _values: &[&(dyn ToSql + Sync)],
    ) -> Result<(), Error> {
        unimplemented!()
    }
}

#[derive(Clone)]
pub struct ConnectionPool {
    inner: Connection,
}

impl ConnectionPool {
    pub async fn new<P: AsRef<Path>>(url: &str, _db_root_ca: &[P]) -> Result<Self, Error> {
        if url != ":memory:" {
            return Err(Error::InvalidInput(format!("invalid URL: {url}")));
        }
        let inner = Connection {
            tables: Arc::new(Mutex::new(RefCell::new(HashMap::new()))),
        };
        Ok(Self { inner })
    }

    pub async fn get(&self) -> Result<Connection, Error> {
        Ok(self.inner.clone())
    }
}

pub struct Transaction<'a>(tokio_postgres::Transaction<'a>);

impl<'a> Transaction<'a> {
    pub async fn commit(self) -> Result<(), Error> {
        unimplemented!()
    }

    pub async fn execute<T>(&self, _stmt: &T, _params: &[&(dyn ToSql + Sync)]) -> Result<u64, Error>
    where
        T: ?Sized + ToStatement,
    {
        unimplemented!()
    }

    pub async fn insert_into(
        &self,
        _table: &str,
        _columns: &[(&str, database::Type)],
        _params: &[&(dyn ToSql + Sync)],
    ) -> Result<i32, Error> {
        unimplemented!()
    }

    pub async fn select_in(
        &self,
        _table: &str,
        _columns: &[&str],
        _variables: &[(&str, database::Type)],
        _in_variables: &[(&str, database::Type)],
        _array_variables: &[(&str, database::Type)],
        _params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, Error> {
        unimplemented!()
    }

    pub async fn select_one_from(
        &self,
        _table: &str,
        _columns: &[&str],
        _variables: &[(&str, database::Type)],
        _params: &[&(dyn ToSql + Sync)],
    ) -> Result<Row, Error> {
        unimplemented!()
    }
}

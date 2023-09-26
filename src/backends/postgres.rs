mod de;
mod error;
mod transaction;

use crate::{self as database, Error};
use bb8_postgres::{
    bb8,
    tokio_postgres::{
        self,
        tls::{MakeTlsConnect, TlsConnect},
        types::ToSql,
        NoTls, Socket,
    },
    PostgresConnectionManager,
};
use diesel_async::AsyncPgConnection;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use rustls::{Certificate, CertificateError, ClientConfig, RootCertStore};
use serde::de::DeserializeOwned;
use std::{
    cmp::min,
    fmt::Write,
    fs, io,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_postgres_rustls::MakeRustlsConnect;
pub use transaction::Transaction;

pub type Value = dyn ToSql + Sync;
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./src/backends/postgres/migrations/");

pub(super) enum ConnectionType<'a> {
    Tls(bb8::PooledConnection<'a, PostgresConnectionManager<MakeRustlsConnect>>),
    NoTls(bb8::PooledConnection<'a, PostgresConnectionManager<NoTls>>),
}

pub struct Connection<'a> {
    inner: ConnectionType<'a>,
}

impl<'a> Connection<'a> {
    /// Build a database transaction
    pub async fn build_transaction(&mut self) -> Result<Transaction<'_>, Error> {
        match &mut self.inner {
            ConnectionType::NoTls(conn) => Transaction::build(conn).await,
            ConnectionType::Tls(conn) => Transaction::build(conn).await,
        }
    }

    /// Returns the number of rows in a table.
    pub async fn count(
        &self,
        table: &str,
        variables: &[(&str, database::Type)],
        any_variables: &[(&str, database::Type)],
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<i64, Error> {
        let mut query = "SELECT COUNT(*) FROM ".to_string();
        query.push_str(table);
        if !values.is_empty() {
            query.push_str(" WHERE ");
            query_equality(&mut query, variables);
            if !variables.is_empty() && !any_variables.is_empty() {
                query.push_str(" AND ");
            }
            query_any(&mut query, variables.len() + 1, any_variables);
        }

        let row = match &self.inner {
            ConnectionType::NoTls(conn) => conn.query_one(query.as_str(), values).await?,
            ConnectionType::Tls(conn) => conn.query_one(query.as_str(), values).await?,
        };
        Ok(row.get(0))
    }

    /// Deletes rows from a table.
    ///
    /// # Examples
    ///
    /// The following code deletes from the table "user" all the rows with name
    /// "john" and age 32.
    ///
    /// ```ignore
    /// conn.delete_from("user", &[("name", Type::TEXT), ("age", Type::INT4)], &[&"john", &32_i32]);
    /// ```
    pub async fn delete_from(
        &self,
        table: &str,
        variables: &[(&str, database::Type)],
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, Error> {
        let query = query_delete_from(table, variables);
        let n = match &self.inner {
            ConnectionType::NoTls(conn) => conn.execute(query.as_str(), values).await?,
            ConnectionType::Tls(conn) => conn.execute(query.as_str(), values).await?,
        };
        Ok(n)
    }

    /// Deletes rows from a table.
    ///
    /// # Examples
    ///
    /// The following code deletes from the table "user" all the rows with name
    /// "john" and age 32 and id listed in [2, 4].
    ///
    /// ```ignore
    /// conn.delete_in("user", &[("name", Type::TEXT), ("age", Type::INT4)], &[("id", Type::INT4_ARRAY)], &[&"john", &32_i32, &[2_i32, 4_i32]]);
    /// ```
    pub async fn delete_in(
        &self,
        table: &str,
        variables: &[(&str, database::Type)],
        any_variables: &[(&str, database::Type)],
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, Error> {
        if variables.is_empty() && any_variables.is_empty() {
            return Ok(0);
        }

        let query = query_delete_in(table, variables, any_variables);
        let n = match &self.inner {
            ConnectionType::NoTls(conn) => conn.execute(query.as_str(), values).await?,
            ConnectionType::Tls(conn) => conn.execute(query.as_str(), values).await?,
        };
        Ok(n)
    }

    /// Inserts a row into a table.
    ///
    /// # Panics
    ///
    /// Panics if `columns` is empty.
    pub async fn insert_into(
        &self,
        table: &str,
        columns: &[(&str, database::Type)],
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<i32, Error> {
        let query = query_insert_into(table, columns);
        let row = match &self.inner {
            ConnectionType::NoTls(conn) => conn.query_one(query.as_str(), values).await?,
            ConnectionType::Tls(conn) => conn.query_one(query.as_str(), values).await?,
        };
        Ok(row.get(0))
    }

    /// Selects columns according to the `IN` condition.
    pub async fn select_in<D: DeserializeOwned>(
        &self,
        table: &str,
        columns: &[&str],
        variables: &[(&str, database::Type)],
        in_variables: &[(&str, database::Type)],
        array_variables: &[(&str, database::Type, Option<&str>)],
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<D>, Error> {
        let query = query_select(table, columns, variables, in_variables, array_variables);
        let rows = match &self.inner {
            ConnectionType::NoTls(conn) => conn.query(query.as_str(), values).await?,
            ConnectionType::Tls(conn) => conn.query(query.as_str(), values).await?,
        };
        let mut result = Vec::with_capacity(rows.len());
        for row in &rows {
            let data = de::from_row(row).map_err(|e| Error::InvalidInput(e.to_string()))?;
            result.push(data);
        }
        Ok(result)
    }

    /// Selects a single row from a table.
    pub async fn select_one_from<D: DeserializeOwned>(
        &self,
        table: &str,
        columns: &[&str],
        variables: &[(&str, database::Type)],
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<D, Error> {
        let query = query_select_one(table, columns, variables, &[], &[]);
        let row = match &self.inner {
            ConnectionType::NoTls(conn) => conn.query_one(query.as_str(), values).await?,
            ConnectionType::Tls(conn) => conn.query_one(query.as_str(), values).await?,
        };
        de::from_row(&row).map_err(|e| Error::InvalidInput(e.to_string()))
    }

    /// Selects a single or zero row from a table.
    pub async fn select_one_opt_from<D: DeserializeOwned>(
        &self,
        table: &str,
        columns: &[&str],
        variables: &[(&str, database::Type)],
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<D>, Error> {
        let query = query_select_one(table, columns, variables, &[], &[]);
        let query_result = match &self.inner {
            ConnectionType::NoTls(conn) => conn.query_opt(query.as_str(), values).await,
            ConnectionType::Tls(conn) => conn.query_opt(query.as_str(), values).await,
        }
        .map_err(|e| Error::InvalidInput(e.to_string()))?;

        if let Some(row) = query_result {
            de::from_row(&row).map_err(|e| Error::InvalidInput(e.to_string()))
        } else {
            Ok(None)
        }
    }

    /// Updates the given fields of a row in a table.
    ///
    /// # Panics
    ///
    /// Panics if `columns` is empty.
    pub async fn update(
        &self,
        table: &str,
        id: i32,
        columns: &[(&str, database::Type)],
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<(), Error> {
        let query = query_update(table, id, columns);
        let n = match &self.inner {
            ConnectionType::NoTls(conn) => conn.execute(query.as_str(), values).await?,
            ConnectionType::Tls(conn) => conn.execute(query.as_str(), values).await?,
        };
        if n == 1 {
            Ok(())
        } else {
            Err(Error::InvalidInput(format!("no row with id = {id}")))
        }
    }

    /// Executes a function.
    pub async fn execute_function(
        &self,
        function: &str,
        arguments: &[database::Type],
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<(), Error> {
        let query = query_select_function(function, arguments);
        let result = match &self.inner {
            ConnectionType::NoTls(conn) => conn.execute(query.as_str(), values).await?,
            ConnectionType::Tls(conn) => conn.execute(query.as_str(), values).await?,
        };
        if result == 1 {
            Ok(())
        } else {
            Err(Error::InvalidInput(format!(
                "failed to execute PostgreSQL function: {function}"
            )))
        }
    }
}

#[derive(Clone)]
enum ConnectionPoolType {
    Tls(bb8::Pool<PostgresConnectionManager<MakeRustlsConnect>>),
    NoTls(bb8::Pool<PostgresConnectionManager<NoTls>>),
}

impl ConnectionPoolType {
    async fn builder<M: bb8::ManageConnection>(manager: M) -> Result<bb8::Pool<M>, M::Error> {
        bb8::Pool::builder()
            .connection_timeout(Duration::from_secs(10))
            .build(manager)
            .await
    }

    async fn build_notls_pool(config: tokio_postgres::Config) -> Result<Self, Error> {
        let manager = PostgresConnectionManager::new(config, tokio_postgres::NoTls);
        let inner = Self::builder(manager).await?;

        Ok(ConnectionPoolType::NoTls(inner))
    }

    async fn build_tls_pool<P: AsRef<Path>>(
        url: &str,
        config: tokio_postgres::Config,
        db_root_ca: &[P],
    ) -> Result<Self, Error> {
        let with_platform_root = true;
        let tls_config = Self::build_client_config(db_root_ca, with_platform_root)
            .map_err(|e| Error::InvalidInput(e.to_string()))?;
        let tls_connect = MakeRustlsConnect::new(tls_config);
        is_pg_ready(url, tls_connect.clone()).await?;

        let manager = PostgresConnectionManager::new(config, tls_connect);
        let inner = Self::builder(manager).await?;

        Ok(ConnectionPoolType::Tls(inner))
    }

    /// Builds a `ClientConfig` with safe defaults.
    ///
    /// # Errors
    ///
    /// This function may return a `rustls::Error` if any of the following occurs:
    ///
    /// * The provided root CA certificate paths are invalid or cannot be read.
    /// * The provided root CA certificates are invalid or cannot be parsed.
    /// * The function is unable to load root certificates from the platform's trusted certificate
    ///   store.
    fn build_client_config<P: AsRef<Path>>(
        root_ca: &[P],
        with_platform_root: bool,
    ) -> Result<ClientConfig, rustls::Error> {
        let mut root_store = RootCertStore::empty();
        if with_platform_root {
            match rustls_native_certs::load_native_certs() {
                Ok(certs) => {
                    for cert in certs {
                        root_store.add(&Certificate(cert.0))?;
                    }
                }
                Err(e) => tracing::error!("Could not load platform certificates: {:#}", e),
            }
        }
        for root in root_ca {
            let certs = Self::read_certificates_from_path(root).map_err(|e| {
                rustls::Error::InvalidCertificate(CertificateError::Other(Arc::new(e)))
            })?;
            for cert in certs {
                root_store.add(&cert)?;
            }
        }

        let mut builder = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        builder.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
        Ok(builder)
    }

    /// Reads certificates from a given file path.
    ///
    /// # Errors
    ///
    /// This function can return an [`std::io::Error`] in the following cases:
    ///
    /// * If the file cannot be read or does not exist.
    /// * If the certificates cannot be parsed from the file.
    fn read_certificates_from_path<P: AsRef<Path>>(path: P) -> Result<Vec<Certificate>, io::Error> {
        let cert = fs::read(&path)?;
        Ok(rustls_pemfile::certs(&mut &*cert)?
            .into_iter()
            .map(Certificate)
            .collect())
    }
}

// diesel_migrations doesn't support async connections
// diesel_async#17
fn run_migrations(url: &str) -> Result<(), Error> {
    use diesel::{pg::PgConnection, Connection};

    let mut conn = PgConnection::establish(url)?;
    conn.run_pending_migrations(MIGRATIONS)
        .map_err(Error::Migration)?;

    Ok(())
}

#[derive(Clone)]
pub struct ConnectionPool {
    inner: ConnectionPoolType,
}

impl ConnectionPool {
    pub async fn new<P: AsRef<Path>>(url: &str, db_root_ca: &[P]) -> Result<Self, Error> {
        use bb8_postgres::tokio_postgres::config::SslMode;

        let config = url
            .parse::<tokio_postgres::Config>()
            .map_err(|e| Error::InvalidInput(e.to_string()))?;

        match config.get_ssl_mode() {
            SslMode::Require | SslMode::Prefer => {
                let inner = ConnectionPoolType::build_tls_pool(url, config, db_root_ca).await?;
                run_migrations(url)?;
                Ok(Self { inner })
            }
            _ => {
                is_pg_ready(url, NoTls).await?;
                let inner = ConnectionPoolType::build_notls_pool(config).await?;
                run_migrations(url)?;
                Ok(Self { inner })
            }
        }
    }

    pub async fn get(&self) -> Result<Connection<'_>, Error> {
        match &self.inner {
            ConnectionPoolType::Tls(pool) => {
                let inner = get_connection(pool).await?;
                let inner = ConnectionType::Tls(inner);
                Ok(Connection { inner })
            }
            ConnectionPoolType::NoTls(pool) => {
                let inner = get_connection(pool).await?;
                let inner = ConnectionType::NoTls(inner);
                Ok(Connection { inner })
            }
        }
    }

    pub async fn get_diesel_conn(&self) -> Result<AsyncPgConnection, Error> {
        let conn = match &self.inner {
            ConnectionPoolType::Tls(pool) => pool.dedicated_connection().await?,
            ConnectionPoolType::NoTls(pool) => pool.dedicated_connection().await?,
        };
        let conn = AsyncPgConnection::try_from(conn).await?;
        Ok(conn)
    }
}

async fn get_connection<Tls>(
    pool: &bb8::Pool<PostgresConnectionManager<Tls>>,
) -> Result<bb8::PooledConnection<'_, bb8_postgres::PostgresConnectionManager<Tls>>, Error>
where
    Tls: MakeTlsConnect<Socket> + Clone + Send + Sync + 'static,
    <Tls as MakeTlsConnect<Socket>>::Stream: Send + Sync,
    <Tls as MakeTlsConnect<Socket>>::TlsConnect: Send,
    <<Tls as MakeTlsConnect<Socket>>::TlsConnect as TlsConnect<Socket>>::Future: Send,
{
    let timeout = Duration::from_secs(30);
    let mut delay = Duration::from_millis(100);
    let start = Instant::now();

    loop {
        match pool.get().await {
            Ok(conn) => return Ok(conn),
            Err(e) => {
                tracing::debug!("Failed to get a database connection: {:#}", e);
                if start.elapsed() > timeout {
                    return Err(Error::PgConnection(e));
                }
                delay = min(timeout / 2, delay * 2);
                tokio::time::sleep(delay).await;
            }
        }
    }
}

// Checks if the postgres server accepts connections.
// Waits at least 30 seconds for the postgres server to boot and run.
#[allow(clippy::trait_duplication_in_bounds)] // rust-lang/rust-clippy#8771
async fn is_pg_ready<Tls>(url: &str, tls: Tls) -> Result<(), Error>
where
    Tls: MakeTlsConnect<Socket> + Clone + Send + Sync + 'static,
    <Tls as MakeTlsConnect<Socket>>::Stream: Send + Sync,
    <Tls as MakeTlsConnect<Socket>>::TlsConnect: Send,
    <<Tls as MakeTlsConnect<Socket>>::TlsConnect as TlsConnect<Socket>>::Future: Send,
{
    let timeout = Duration::from_secs(30);
    let mut delay = Duration::from_millis(100);
    let start = Instant::now();
    loop {
        match tokio_postgres::connect(url, tls.clone()).await {
            Ok(_) => {
                return Ok(());
            }
            Err(e) => {
                if start.elapsed() > timeout {
                    return Err(Error::Postgres(e));
                }
                delay = min(timeout / 2, delay * 2);
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// Builds a DELETE statement.
fn query_delete_from(table: &str, variables: &[(&str, database::Type)]) -> String {
    let mut query = "DELETE FROM ".to_string();
    query.push_str(table);
    query.push_str(" WHERE ");
    query_equality(&mut query, variables);
    query
}

fn query_delete_in(
    table: &str,
    variables: &[(&str, database::Type)],
    any_variables: &[(&str, database::Type)],
) -> String {
    if variables.is_empty() && any_variables.is_empty() {
        return String::new();
    }

    let mut query = "DELETE FROM ".to_string();
    query.push_str(table);
    query.push_str(" WHERE ");

    query_equality(&mut query, variables);
    if !variables.is_empty() && !any_variables.is_empty() {
        query.push_str(" AND ");
    }
    query_any(&mut query, variables.len() + 1, any_variables);
    query
}

/// Builds an INSERT statement.
///
/// # Panics
///
/// Panics if `columns` is empty.
fn query_insert_into(table: &str, columns: &[(&str, database::Type)]) -> String {
    let mut query = "INSERT INTO ".to_string();
    query.push_str(table);
    query.push_str(" (");
    query.push_str(columns[0].0);
    let col_query = format!("$1::{}", &columns[0].1);
    let (mut query, col_query) =
        columns
            .iter()
            .enumerate()
            .skip(1)
            .fold((query, col_query), |mut q, (i, c)| {
                q.0.push_str(", ");
                q.0.push_str(c.0);
                write!(q.1, ", ${}::{}", i + 1, c.1).expect("in-memory operation");
                q
            });
    write!(query, ") VALUES ({col_query}) RETURNING id").expect("in-memory operation");
    query
}

/// Builds a SELECT statement.
///
/// # Panics
///
/// Panics if `columns` is empty.
fn query_select(
    table: &str,
    columns: &[&str],
    variables: &[(&str, database::Type)],
    any_variables: &[(&str, database::Type)],
    array_variables: &[(&str, database::Type, Option<&str>)],
) -> String {
    let mut query = "SELECT ".to_string();
    query.push_str(columns[0]);
    for &col in columns.iter().skip(1) {
        query.push_str(", ");
        query.push_str(col);
    }
    query.push_str(" FROM ");
    query.push_str(table);
    if variables.is_empty() && any_variables.is_empty() && array_variables.is_empty() {
        return query;
    }

    query.push_str(" WHERE ");
    query_equality(&mut query, variables);
    if !variables.is_empty() && !any_variables.is_empty() {
        query.push_str(" AND ");
    }
    query_any(&mut query, variables.len() + 1, any_variables);

    if (!variables.is_empty() || !any_variables.is_empty()) && !array_variables.is_empty() {
        query.push_str(" AND ");
    }
    query_array(
        &mut query,
        variables.len() + any_variables.len() + 1,
        array_variables,
    );
    query
}

/// Builds a SELECT statement which returns a single row.
///
/// # Panics
///
/// Panics if `columns` is empty.
fn query_select_one(
    table: &str,
    columns: &[&str],
    variables: &[(&str, database::Type)],
    any_variables: &[(&str, database::Type)],
    array_variables: &[(&str, database::Type, Option<&str>)],
) -> String {
    let mut query = "SELECT ".to_string();
    query.push_str(columns[0]);
    for &col in columns.iter().skip(1) {
        query.push_str(", ");
        query.push_str(col);
    }
    query.push_str(" FROM ");
    query.push_str(table);
    if variables.is_empty() && any_variables.is_empty() && array_variables.is_empty() {
        return query;
    }

    query.push_str(" WHERE ");
    query_equality(&mut query, variables);
    if !variables.is_empty() && !any_variables.is_empty() {
        query.push_str(" AND ");
    }
    query_any(&mut query, variables.len() + 1, any_variables);

    if (!variables.is_empty() || !any_variables.is_empty()) && !array_variables.is_empty() {
        query.push_str(" AND ");
    }
    query_array(
        &mut query,
        variables.len() + any_variables.len() + 1,
        array_variables,
    );

    query.push_str(" LIMIT 1");

    query
}

// Builds a SELECT statement to execute a function.
fn query_select_function(function: &str, arguments: &[database::Type]) -> String {
    let mut query = "SELECT ".to_string();
    query.push_str(function);
    query.push('(');
    if !arguments.is_empty() {
        query.push_str("$1::");
        query.push_str(&arguments[0].to_string());
        for (i, arg) in arguments.iter().enumerate().skip(1) {
            query.push_str(", $");
            query.push_str(&(i + 1).to_string());
            query.push_str("::");
            query.push_str(&arg.to_string());
        }
    }
    query.push(')');
    query
}

/// Builds an UPDATE statement.
///
/// # Panics
///
/// Panics if `columns` is empty.
fn query_update(table: &str, id: i32, columns: &[(&str, database::Type)]) -> String {
    let mut query = "UPDATE ".to_string();
    query.push_str(table);
    query.push_str(" SET ");
    query.push_str(columns[0].0);
    query.push_str(" = $1::");
    query.push_str(&columns[0].1.to_string());
    for (i, col) in columns.iter().enumerate().skip(1) {
        query.push_str(", ");
        query.push_str(col.0);
        query.push_str(" = $");
        query.push_str(&(i + 1).to_string());
        query.push_str("::");
        query.push_str(&col.1.to_string());
    }
    query.push_str(" WHERE id = ");
    query.push_str(&id.to_string());
    query
}

/// Builds a query fragment for equality conditions.
fn query_equality(query: &mut String, variables: &[(&str, database::Type)]) {
    if variables.is_empty() {
        return;
    }

    query.push_str(variables[0].0);
    query.push_str(" = $1::");
    query.push_str(&variables[0].1.to_string());
    for (i, var) in variables.iter().enumerate().skip(1) {
        query.push_str(" AND ");
        query.push_str(var.0);
        query.push_str(" = $");
        query.push_str(&(i + 1).to_string());
        query.push_str("::");
        query.push_str(&var.1.to_string());
    }
}

/// Builds a query fragment for `IN` conditions.
fn query_any(query: &mut String, index: usize, variables: &[(&str, database::Type)]) {
    if variables.is_empty() {
        return;
    }

    if !variables.is_empty() {
        query.push_str(variables[0].0);
        query.push_str(" = ANY($");
        query.push_str(&index.to_string());
        query.push_str("::");
        query.push_str(&variables[0].1.to_string());
        query.push(')');
        for (i, var) in variables.iter().enumerate().skip(1) {
            query.push_str(" AND ");
            query.push_str(var.0);
            query.push_str(" = ANY($");
            query.push_str(&(index + i).to_string());
            query.push_str("::");
            query.push_str(&var.1.to_string());
            query.push(')');
        }
    }
}

/// Builds a query fragment for provided conditions,
/// `@>` if None is provided.
fn query_array(
    query: &mut String,
    index: usize,
    variables: &[(&str, database::Type, Option<&str>)],
) {
    if variables.is_empty() {
        return;
    }

    if !variables.is_empty() {
        query.push_str(variables[0].0);
        if let Some(comparator) = variables[0].2 {
            query.push_str(&format!(" {comparator} $"));
        } else {
            query.push_str(" @> $");
        }

        query.push_str(&index.to_string());
        query.push_str("::");
        query.push_str(&variables[0].1.to_string());
        for (i, var) in variables.iter().enumerate().skip(1) {
            query.push_str(" AND ");
            query.push_str(var.0);
            if let Some(comparator) = var.2 {
                query.push_str(&format!(" {comparator} $"));
            } else {
                query.push_str(" @> $");
            }
            query.push_str(&(index + i).to_string());
            query.push_str("::");
            query.push_str(&var.1.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use bb8_postgres::tokio_postgres::types::Type;

    #[test]
    fn query_delete_from() {
        let query = super::query_delete_from("t1", &[("f2", Type::INT4), ("f5", Type::TEXT)]);
        assert_eq!(
            query,
            "DELETE FROM t1 WHERE f2 = $1::int4 AND f5 = $2::text"
        );
    }

    #[test]
    fn query_delete_in_empty() {
        let query = super::query_delete_in("t1", &[], &[]);
        assert_eq!(query, "");
    }

    #[test]
    fn query_delete_in() {
        let query = super::query_delete_in(
            "t1",
            &[("f2", Type::INT4), ("f5", Type::TEXT)],
            &[("f8", Type::INT4_ARRAY)],
        );
        assert_eq!(
            query,
            "DELETE FROM t1 WHERE f2 = $1::int4 AND f5 = $2::text AND f8 = ANY($3::_int4)"
        );
    }

    #[test]
    fn query_insert_into() {
        let query = super::query_insert_into("t1", &[("f1", Type::INT4), ("f2", Type::TEXT)]);
        assert_eq!(
            query,
            "INSERT INTO t1 (f1, f2) VALUES ($1::int4, $2::text) RETURNING id"
        );
    }

    #[test]
    fn query_select_one() {
        let query = super::query_select_one(
            "t1",
            &["f1", "f2"],
            &[("f1", Type::INT4), ("f2", Type::TEXT)],
            &[],
            &[],
        );
        assert_eq!(
            query,
            "SELECT f1, f2 FROM t1 WHERE f1 = $1::int4 AND f2 = $2::text LIMIT 1"
        );
    }

    #[test]
    fn query_select_function() {
        let query = super::query_select_function("f1", &[Type::INT8_ARRAY, Type::TEXT]);
        assert_eq!(query, "SELECT f1($1::_int8, $2::text)")
    }

    #[test]
    fn query_select_in() {
        let query = super::query_select(
            "t1",
            &["f3"],
            &[("f2", Type::TEXT), ("f5", Type::TEXT)],
            &[("f1", Type::INT4_ARRAY), ("f4", Type::INT8_ARRAY)],
            &[
                ("f6", Type::INT4_ARRAY, None),
                ("f7", Type::INT8_ARRAY, None),
            ],
        );
        assert_eq!(
            query,
            "SELECT f3 FROM t1 WHERE f2 = $1::text AND f5 = $2::text AND \
             f1 = ANY($3::_int4) AND f4 = ANY($4::_int8) AND \
             f6 @> $5::_int4 AND f7 @> $6::_int8"
        );
    }

    #[test]
    fn query_select_in_array() {
        let query = super::query_select("t1", &["f3"], &[], &[], &[("f6", Type::INT4_ARRAY, None)]);
        assert_eq!(query, "SELECT f3 FROM t1 WHERE f6 @> $1::_int4");
    }

    #[test]
    fn query_update() {
        let query = super::query_update("t1", 10, &[("f1", Type::INT4), ("f2", Type::TEXT)]);
        assert_eq!(
            query,
            "UPDATE t1 SET f1 = $1::int4, f2 = $2::text WHERE id = 10"
        );
    }
}

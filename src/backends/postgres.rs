use std::{
    cmp::min,
    fs, io,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use bb8_postgres::{
    PostgresConnectionManager, bb8,
    tokio_postgres::{
        self, NoTls, Socket,
        tls::{MakeTlsConnect, TlsConnect},
    },
};
use diesel_async::AsyncPgConnection;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use rustls::{CertificateError, ClientConfig, RootCertStore};
use rustls_pki_types::CertificateDer;
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::Error;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./src/backends/migrations/");

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
            let certs = rustls_native_certs::load_native_certs();
            for c in certs.certs {
                root_store.add(c)?;
            }
            for e in certs.errors {
                tracing::warn!("Could not load platform certificate: {:#}", e);
            }
        }
        for root in root_ca {
            let certs = Self::read_certificates_from_path(root).map_err(|e| {
                rustls::Error::InvalidCertificate(CertificateError::Other(rustls::OtherError(
                    Arc::new(e),
                )))
            })?;
            for cert in certs {
                root_store.add(cert)?;
            }
        }

        let mut builder =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
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
    fn read_certificates_from_path<P: AsRef<Path>>(
        path: P,
    ) -> Result<Vec<CertificateDer<'static>>, io::Error> {
        let cert = fs::read(&path)?;
        Ok(rustls_pemfile::certs(&mut &*cert)
            .filter_map(Result::ok)
            .collect())
    }
}

// diesel_migrations doesn't support async connections
// diesel_async#17
fn run_migrations(url: &str) -> Result<(), Error> {
    use diesel::{Connection, pg::PgConnection};

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

        let pool_type = match config.get_ssl_mode() {
            SslMode::Require | SslMode::Prefer => {
                ConnectionPoolType::build_tls_pool(url, config, db_root_ca).await
            }
            _ => {
                is_pg_ready(url, NoTls).await?;
                ConnectionPoolType::build_notls_pool(config).await
            }
        }?;
        run_migrations(url)?;
        Ok(Self { inner: pool_type })
    }

    pub async fn get(&self) -> Result<AsyncPgConnection, Error> {
        let conn = match &self.inner {
            ConnectionPoolType::Tls(pool) => pool.dedicated_connection().await?,
            ConnectionPoolType::NoTls(pool) => pool.dedicated_connection().await?,
        };
        let conn = AsyncPgConnection::try_from(conn).await?;
        Ok(conn)
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

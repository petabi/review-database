use bb8_postgres::{
    bb8::PooledConnection,
    tokio_postgres::{
        self,
        tls::{MakeTlsConnect, TlsConnect},
        types::ToSql,
        Socket, ToStatement,
    },
    PostgresConnectionManager,
};

use crate::Error;

pub struct Transaction<'a>(tokio_postgres::Transaction<'a>);

impl<'a> Transaction<'a> {
    /// Build a database transaction
    #[allow(clippy::trait_duplication_in_bounds)] // rust-lang/rust-clippy#8771
    pub async fn build<Tls>(
        conn: &'a mut PooledConnection<'_, PostgresConnectionManager<Tls>>,
    ) -> Result<Transaction<'a>, Error>
    where
        Tls: MakeTlsConnect<Socket> + Clone + Send + Sync + 'static,
        <Tls as MakeTlsConnect<Socket>>::Stream: Send + Sync,
        <Tls as MakeTlsConnect<Socket>>::TlsConnect: Send,
        <<Tls as MakeTlsConnect<Socket>>::TlsConnect as TlsConnect<Socket>>::Future: Send,
    {
        let transaction = conn
            .build_transaction()
            .read_only(false)
            .deferrable(false)
            .start()
            .await
            .map_err(Error::Postgres)?;

        Ok(Transaction(transaction))
    }

    /// Consumes the transaction, committing all changes made within it.
    pub async fn commit(self) -> Result<(), Error> {
        Ok(self.0.commit().await?)
    }

    /// Execute a statement within the transaction
    pub async fn execute<T>(&self, stmt: &T, params: &[&(dyn ToSql + Sync)]) -> Result<u64, Error>
    where
        T: ?Sized + ToStatement,
    {
        Ok(self.0.execute(stmt, params).await?)
    }
}

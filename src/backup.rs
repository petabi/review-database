//! Database backup utilities.

use std::{sync::Arc, time::Duration};

use anyhow::Result;
use tokio::sync::Notify;
use tracing::{info, warn};

use crate::Store;

/// Schedules periodic database backups.
#[allow(clippy::module_name_repetitions)]
pub async fn schedule_periodic(
    store: Arc<Store>,
    schedule: (Duration, Duration),
    backups_to_keep: u32,
    stop: Arc<Notify>,
) {
    use tokio::time::{sleep, Instant};

    let (init, duration) = schedule;
    let sleep = sleep(init);
    tokio::pin!(sleep);

    loop {
        tokio::select! {
            () = &mut sleep => {
                sleep.as_mut().reset(Instant::now() + duration);
                let _res = create(&store, backups_to_keep);
            }
            _ = stop.notified() => {
                info!("creating a database backup before shutdown");
                let _res = create(&store, backups_to_keep);
                stop.notify_one();
                return;
            }

        }
    }
}

/// Creates a new database backup, keeping the specified number of backups.
///
/// # Errors
///
/// Returns an error if backup fails.
pub fn create(store: &Store, backups_to_keep: u32) -> Result<()> {
    // TODO: This function should be expanded to support PostgreSQL backups as well.
    if let Err(e) = store.backup(backups_to_keep) {
        warn!("database backup failed: {:?}", e);
        return Err(e);
    }
    info!("database backup created");
    Ok(())
}

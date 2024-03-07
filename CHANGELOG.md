# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `Indexable::id` and `Indexable::make_indexed_key` for `Indexable` trait.
  This enhancement provides users with greater flexibility in customizing the
  `indexed_key` associated with `Indexable` trait.
- Introduced `Network` and `NetworkUpdate` to describe data stored in `Table<Network>`.
- Added new functions to facilitate insert, remove, and update operations,
  ensuring a more controlled and secure network management.

### Changed

- Introduced `IndexedMap` as the replacement for `IndexedMultiMap` for database
  table types. This change allows for a more streamlined and efficient approach
  to managing entries in the table.
- The customized indexed key implementation allows for more tailored and efficient
  indexing strategies.
- Changed the return type of `Store::network_map` to `IndexedTable<Network>`
  to enhance security by preventing direct exposure of internal structure.
- Replaced `IndexedMap::get_by_id` function with `Indexed::get_by_id`, providing
   a more structured and type-safe result.
  - Previously, the function returned a binary representation of the key-value
    pair: `Result<(Option<impl AsRef<[u8]>>, Option<impl AsRef<[u8]>>)>`.
  - Now, it returns `Result<Option<T>>`, where T is the entry type.
  - The type T must implement the `Indexable` and `FromKeyValue` traits.
  - This change enhances security by avoiding direct exposure of binary data.
- Modified `Node` to have `name` and `name_draft` field, replacing its previous
  location within `NodeSetting`. Also, renamed `as_is` and `to_be` to `setting`
  and `setting_draft`.
- `Store::network_tag_set` now returns `TagSet` instead of `IndexSet`. This
  change is made to leverage the new `TagSet` structure for a more user-friendly
  approach in accessing tags. The `TagSet` allows users to interact with tags
  through the `Tag` struct, which includes `name` and `id` fields, offering a
  more straightforward and human-readable format compared to the raw binary
  format exposed by `IndexSet`.

### Removed

- `IndexedMultiMap` has been removed from the codebase, for table that currently
  use `IndexedMultiMap` use `IndexedMap` with a customized `Indexable::make_indexed_key`
  for entries stored instead.

## [0.25.0] - 2024-03-05

### Added

- Introduced the `UniqueKey` trait to provide a standardized way to retrieve a
  unique, opaque key (`Cow<[u8]>`) for instances of structs used as records in
  the database.
- Implemented `iter` method not only for `Table<Account>` but for all `Table<R>`
  and `IndexedTable<R>` where `R` implements `DeserializedOwned`, through the
  newly-introduced `Iterable` trait. This enhancement enables the `iter` method
  to be used universally on any table that contains a record that can be
  deserialized from a key-value entry, extending its functionality beyond just
  the `Table<Account>`.
- Added new functions to facilitate insert, revoke, and containment operations,
  ensuring a more controlled and secure access_token management.
- Added new functions to facilitate insert, remove, get and list operations,
  ensuring a more controlled and secure filter management.
- Introduced a new data structure `TagSet` to facilitate easier access and
  manipulation of tags stored in the database.
- Added new functions to facilitate insert, remove, and update operations,
  ensuring a more controlled and secure template management.
- Introduced `Structured`, `Unstructured`, `StructuredClusteringAlgorithm` and
 `UnstructuredClusteringAlgorithm` to describe data stored in `Table<Template>`.
- Introduced `TriageResponse` to describe data stored in `IndexedTable<TriageResponse>`.
- Introduced `TriageResponseUpdate` to support `TriageResponse` record update.
- Added new functions to facilitate insert, remove, and update operations,
  ensuring a more controlled and secure triage response management.
- Introduced `TorExitNode` to describe data stored in `Table<TorExitNode>`.
- Added new functions to facilitate replace and list operations, ensuring a
  more controlled and secure tor exit node management.

### Changed

- Moved the csv_column_extra table from the PostgreSQL database to RocksDB.
  - The csv_column_extra table data is now stored in RocksDB for improved performance
    and scalability.
  - A migration function has been provided to seamlessly transition data from
    the old PostgreSQL table to RocksDB.
- The `Indexable::key()`, `Indexable::indexed_key()`, `IndexedMapUpdate::key()`,
  method now returns a `Cow<[u8]>` instead of `&[u8]`. This change was
  introduced to provide greater flexibility and avoid potential ownership and
  borrowing issues. `Cow<[u8]>` allows users to efficiently handle both owned
  and borrowed data, depending on their specific use case.
- `backup::restore` and `Database::add_time_series` no longer leave log messages
  regarding the result of their database operations, since the messages don't
  provide any information that the caller doesn't already have. This change aims
  to reduce unnecessary verbosity and improve the overall clarity and
  readability of the log output. The same information, if needed, can be
  obtained by checking the return value of each function, and the caller can
  decide whether to log it or not.
- Changed the return type of `Store::access_token_map` to `Table<AccessToken>` to
  enhance security by preventing direct exposure of `Map`.
- The `get_by_id` method in the `IndexedMap` struct has been updated to return a
  key-value pair (`(Vec<u8>, Vec<u8>)`) instead of just the value (`impl
  AsRef<[u8]>`). This change accommodates scenarios where the information stored
  in a key may not be present in the value for some Column Families. Previously,
  if you called `get_by_id` with a specific ID, you would receive the
  corresponding value as `Option<impl AsRef<[u8]>>`. Now, calling `get_by_id`
  with an ID will return an `Option` containing a tuple of `Vec<u8>` for both
  the key and the value, effectively giving you direct access to the stored key
  along with its corresponding value.
- Changed the return type of `Store::filter_map` to `Table<Filter>` to
  enhance security by preventing direct exposure of `Map`.
- Modified `Filter` struct to include the `username` property, representing the
  associated username for the specific `Filter`.
- Changed the return type of `Store::model_indicator_map` to `Table<ModelIndicator>`
  to enhance security by preventing direct exposure of `Map`.
- Moved member functions of `ModelIndicator` that are related to database operations
  under `Table<ModelIndicator>` to facilitate insert, remove, update, get and
  list operations, ensuring a more controlled and secure model indicator management
  and improved code organization.
- Modified `ModelIndicator` struct to include the `name` property, representing the
  associated name for the specific `ModelIndicator`.
- `Store::event_tag_set` and `Store::workflow_tag_set` now returns `TagSet`
  instead of `IndexSet`. This change is made to leverage the new `TagSet`
  structure for a more user-friendly approach in accessing tags. The `TagSet`
  allows users to interact with tags through the `Tag` struct, which includes
  `name` and `id` fields, offering a more straightforward and human-readable
  format compared to the raw binary format exposed by `IndexSet`.
- Changed the return type of `Store::template_map` to `Table<Template>` to enhance
  security by preventing direct exposure of `Map`.
- The Template type has been replaced with the enum type. This modification
  reflects the diverse templates supported by the database.
- Changed the return type of `Store::triage_response_map` to `IndexedTable<TriageResponse>`
  to enhance security by preventing direct exposure of `IndexedMap`.
- Changed the return type of `Store::tor_exit_node_map` to `Table<TorExitNode>`
  to enhance security by preventing direct exposure of `Map`.
- Modify the kind value of the Blocklist/CryptocurrencyMiningPool/TorConnection
  event that implements the Match trait. This fix allows the kind filter in
  GraphQL queries that retrieve the event to work correctly.
- Modified `Node` struct to include the `as_is` and `to_be` fields,
  with existing field values migrated to the `to_be` field.

### Deprecated

- `csv_column_extra` table from PostgreSQL database is now deprecated.

### Removed

- The `Table::get_range` method has been removed in favor of a more consistent
  and versatile iteration method. Users will now utilize the `Table::iter`
  method for traversing records within a table. This change aims to streamline
  the interface and improve the overall usability of the database access
  patterns.
- The status and qualifier tables have been permanently removed from the
  PostgreSQL database in this release.
  - To ensure data integrity and avoid potential data loss, users currently
    utilizing review-database versions below 0.24.0 must migrate to version
    0.24.0 before proceeding with any further migrations.
- The `backup::schedule_periodic` function has been permanently removed. Users
  are advised to update their codebase accordingly and leverage alternative
  methods for scheduling periodic backups.
- The `backup::recover` and `Store::recover` functions have been removed. These
  functions were designed to attempt recovery from the most recent backup until
  success. We recommend implementing backup recovery strategies at the
  application level to better suit specific needs.
- The `FromKeyValue` implementation for `DeserializeOwned` has been removed. This
  change was made to ensure that the `FromKeyValue` trait is only implemented for
  types that are explicitly intended to be deserialized from key-value entries.

### Fixed

- Corrected key order in the `batch_info` Column Family.
  - The order was adjusted due to Little-Endian Serialization.
  - After the correction, it now uses the Big-Endian format.

## [0.24.0] - 2024-01-29

### Changed

- Updated the `insert` and `update` methods in the `Tidb` class to simplify
  return types and remove unnecessary cloning. These methods no longer return
  redundant tuple values `(String, String)` representing the name and version of
  the TI database, instead returning a `Result<()>`. Additionally, the update
  eliminates the need for cloning `name` and `version`, as these values are now
  directly accessible through the public member variables of the `Tidb`
  instance.
- Moved the qualifier table from the PostgreSQL database to RocksDB.
  - The qualifier table data is now stored in RocksDB for improved performance
    and scalability.
  - A migration function has been provided to seamlessly transition data from
    the old PostgreSQL table to RocksDB.
- Moved the status table from the PostgreSQL database to RocksDB.
  - The status table data is now stored in RocksDB for improved performance
    and scalability.
  - A migration function has been provided to seamlessly transition data from
    the old PostgreSQL table to RocksDB.
- Modified `Node` fields.

### Deprecated

- `qualifier` table from PostgreSQL database is now deprecated.
- `status` table from PostgreSQL database is now deprecated.

### Removed

- `Table<Account>` no longer implements `IterableMap`. Instead, the user should
  use `Table<Account>::iter` to iterate over the accounts in the database. This
  change eliminates the need for callers to deserialize records manually,
  simplifying the interaction with the accounts table.

## [0.23.0] - 2024-01-18

### Added

- Added three detection events:
  - `WindowsThreat`: This is a detection event for windows sysmon events.
  - `NetworkThreat`: This is a detection event for network events.
  - `ExtraThreat`: This is a detection event for misc log events. This event
    replaces the place of `EventKind::Log` because it stores detections from
    unstructured Log data and composite data (network event/sysmon events).
    Also, because `EventKind::Log` is still not in actual use today, there is
    no migration processing for that change.

### Changed

- `IndexedTable<Category>::add` has been replaced with
  `IndexedTable<Category>::insert`, to be consistent with the `HashMap` API.
- `TimeSeriesUpdate::time` has been removed for simplification.
- `batch_ts` argument has been added to `add_time_series`.

### Removed

- The category table has been permanently removed from the PostgreSQL database
  in this release.
  - To ensure data integrity and avoid potential data loss, users currently
    utilizing review-database versions below 0.22.0 must migrate to version
    0.22.1 before proceeding with any further migrations.
- A generic definition of `IndexedTable::insert` has been removed; each table
  implements its own `insert` function.

## [0.22.1] - 2024-01-10

### Fixed

- The default implementation of `Indexed::update` has a code that it assumes the
  implementor is using key + id as the primary key in RocksDB. This is not true
  for `IndexedMap`, which uses only the key as the primary key. This version
  fixes the issue by using `indexed_key`, which behaves differently depending
  on the implementor.
- The default implementation of `Indexed::update` doesn't allow duplicated keys
  which might not be true for `IndexedMultimap`. This version fixes the issue by
  guard it with a check.

## [0.22.0] - 2024-01-09

### Added

- `migrate_backend` function is provided for user to transfer data between
  PostgreSQL and RocksDB for a seamless backend transition.

### Changed

- Ensures that when updating elements in `Map` and `IndexedMap`, the system now
  checks whether the new key already exists in the database. This prevents
  unintentional overwrites or conflicts, providing a more robust and reliable
  update mechanism.
- Moved the category table from the PostgreSQL database to RocksDB.
  - The category table data is now stored in RocksDB for improved performance
    and scalability.
  - A migration function has been provided to seamlessly transition data from
    the old PostgreSQL table to RocksDB.
- `nodes` table's fields are modified. Migration of data is supported by function
  `migrate_0_20_to_0_22`.

### Deprecated

- `category` table from PostgreSQL database is now deprecated.

## [0.21.0] - 2023-12-01

### Added

- Introduced the `batch_ts` attribute to the `Statistics` module, providing users
  with the ability to retrieve the timestamp associated with the batch of column
  statistics. This information is valuable for tracking changes over time and
  aligning statistical insights with specific data batches.

### Changed

- Removed `batch_info` and `scores` arguments from `Model::from_storage` function.
  These arguments were previously used for custom initialization of the
  `batch_info` and `scores` fields within the model. This change means that when
  you create a model using `Model::from_storage`, the  `batch_info` and `scores`
  fields will now be initialized with their default values. If you previously
  relied on custom values for these fields, you will need to update your code accordingly.

### Removed

- `event_range` Table Removal:
  - The `event_range` table has been removed from the database schema.
  - Information previously stored in `event_range` is now managed using the
    `column_description` and `batch_info` tables.

## [0.20.0] - 2023-10-06

### Added

- Added public accessors for the `model` field in the `BatchInfo` and `Scores` structs.

### Changed

- Modified `Kerberos` event fields.

### Fixed

- Use a Rust struct that matches the Postgres table schema when loading a model
  from the Postgres database.

## [0.19.0] - 2023-09-25

### Added

- Added a 'BlockList' event with `dcerpc`, `dns`, `http`, `kerberos`, `ldap`,
  `mqtt`, `nfs`, `ntlm`, `rdp`, `smb`, `smtp`, `ssh`, `tls` protocol.

### Fixed

- Fixed PostgreSQL Error when query column statistics on Web UI.

## [0.18.0] - 2023-09-07

### Added

- Introduced a new column `version` within the model table of the database. It
  indicates the specific version associated with each model. Existing model entry
  will have default version 0.
- Introduced new database tables `BATCH_INFO` and `SCORES` to facilitate the
  recording of batch information and scores.
- Introduced the `ModelSql` struct, aimed at encapsulating all information related
  to models stored in the PostgreSQL database.
- Introduced the `ModelDigest` struct, designed to encapsulate all the information
  necessary for the web user interface.
- Requires a 16 bytes long header for serializing or deserializing `Model`, encoded
  with version, kind, format version information for `Model`.

### Changed

- Updated the `Model` struct, encompassing all the information pertinent to a model.
- Return deleted model id for `delete_model`.
- Enhanced and Modified `add_model`, `update_model` for improved usability and
  clarity. The functions now accept a single parameter of type `SqlModel`
  encapsulating various attributes that are required for adding or updating a model.
- Updated `load_model_by_name` to return a `SqlModel` struct, encapsulating
  various attributes that are required by user.

### Removed

- Removed obsoleted PostgresQL function `attempt_outlier_upsert`

## [0.17.1] - 2023-08-22

### Fixed

- Fix wrong initial counting of events.

## [0.17.0] - 2023-08-07

### Added

- Added a 'blockList' event with `conn`, `ftp` protocol.

### Removed

- Removed database migration support for versions prior to 0.12.0. This change
  will allow us to focus on supporting the latest and most stable versions,
  ensuring a more efficient development and maintenance process.

  Please note that if you are currently using a version of the application
  earlier than 0.12.0, database migration support has been deprecated and will
  no longer be available.
  - Users on versions prior to 0.12.0 will need to manually manage their database
    schema updates if they choose to continue using these older versions.
  - We highly recommend upgrading to the latest version (0.12.0 or later) to
    benefit from the most recent features, bug fixes, and ongoing support.

## [0.16.0] - 2023-07-25

### Changed

- Modified `FtpBruteForce`, `LdapBruteForce`, `RdpBruteForce` fields to align
  with the event fields provided.

### Fixed

- Fixed a critical issue that caused a PostgreSQL database error when attempting
  to delete a model from the system. The error occurred due to improper handling
  of foreign key constraints during the deletion process.

## [0.15.2] - 2023-07-06

### Added

- Added a `CryptocurrencyMiningPool` event with `dns` protocol.

### Changed

- Renamed `ExternalDDos` to `ExternalDdos` and `ExternalDDosFields` to
  `ExternalDdosFields` in line with the Rust API Guidelines. This change
  improves consistency with the way acronyms are capitalized in UpperCamelCase.
  According to the guidelines, acronyms and contractions of compound words are
  to be treated as one word. For example, use `Uuid` instead of `UUID`, `Usize`
  instead of `USize`, or `Stdin` instead of `StdIn`.

  Please note that this is a breaking change and you will need to update your
  code if you have been using the old naming convention. We apologise for any
  inconvenience this may cause, but we believe this change will bring greater
  consistency and readability to the codebase.
- Removed `src_port` field from `FtpBruteForce` and `LdapBruteForce` events.
  to align with the event fields provided by hog.
- Modified `LdapPlainText` fields to appropriate LDAP event fields from wrong
  fields. This changes require updates in dependent projects due to complete
  change of the fields.
- Modified `FtpBruteForce` by adding an `is_internal` field which is a boolean
  indicating whether it is internal or not.

## [0.15.1] - 2023-06-26

### Added

- Added more event objects with `conn`, `ftp`, `http`, `ldap`.

### Fixed

- Fixed `Event::TorConnection` and `Event::DomainGenerationAlgorithm` in
  `Event::count_network`.
  - Adjusted the counting routine for `TorConnection` and
    `DomainGenerationAlgorithm` events to address an issue of overcounting
    destination IP addresses. Previously, the counter was incremented for each
    destination address regardless of whether the event matched the specified
    `locator` and `filter`. The logic has been updated so that now both source
    and destination addresses are only considered if the event matches the
    `locator` and `filter`. This change corrects the count by ensuring only
    relevant events are considered in the total tally.

## [0.15.0] - 2023-06-14

### Added

- Introduced a new database table 'TRUSTED_USER_AGENTS' for handling
  non-browser detections.
- Added the ability to recover from the latest valid backup file.
  - In case of data loss or system failure, the new recovery feature allows
    users to automatically restore the system using the latest valid backup
    file available.
  - The recovery process identifies the most recent backup file that is valid
    and consistent, ensuring the integrity of the recovered data.

### Changed

- Added a new flag, `flush`, to the backup functionality, allowing users to
  control whether the database should be flushed before initiating the backup
  process.
  - When the flush flag is set to true, the database will be flushed before
    initiating the backup. This ensures that all pending data is written to
    disk, minimizing the risk of data loss during the backup process.
  - When the flush flag is set to false (default), the database will not be
    flushed before the backup, allowing for faster backup operations. However,
    please note that there is a slight risk of potential data loss if there are
    pending writes that have not been committed at the time of backup.

- Modified the backup, `restore_from_latest_backup`, `restore_from_backup`, and
  `purge_old_backups` functions to require a mutable reference of the database.
  Exclusive access to the database directory and backup directory is necessary
  for consistency and integrity. This prevents potential conflicts or data
  corruption during these critical processes.
  - It is recommended to schedule these operations during maintenance windows
    or low-activity periods to minimize disruption to users and services.
  - Ensure that appropriate permissions are granted to the executing user or
    process to access and modify the database and backup directories.

- Changed the argument `store` from `&Arc<Store>` to `&Arc<RwLock<Store>>` for
  `create`, `schedule_periodic`, `restore`, and `list` functions to allow for
  concurrent read and exclusive write access to the store, enabling better
  thread safety and data consistency during these operations.

- Modified the `restore` function argument `backup_id` from `u32` to `Option<u32>`.
  - When `backup_id` is set to `Some(id)`, the function restores from the backup
    with the provided `id`.
  - When `backup_id` is set to `None`, the function restores from the latest
    available backup. Please note that if the latest backup is invalid,
    restoration will fail.
  - To recover from the latest valid backup, a new `recover` function is introduced.

- Changed the default path for storing state.db backup from "/backup/path/" to
  "/backup/path/state.db/". The new default path provides better clarity and
  specificity, making it easier for users to locate and manage the state.db
  backup file. This change ensures consistency and aligns with best practices
  for backup file naming and organization.

- Modified the backup process during migration to occur once before the
  migration starts and deleted after the entire process succeeds. Previously,
  the backup and deletion of the backup were performed for each migration step.
  With this update, the backup process occurs once before the migration starts,
  ensuring a consistent starting point for the migration process. After the
  migration process successfully completes, the backup is deleted to avoid
  unnecessary duplication of backup files and reduce storage usage. This
  approach ensures that the backup file represents the state of the database
  before the entire migration process, providing a reliable fallback option if
  needed. This optimization improves the efficiency of the migration process,
  especially in scenarios involving a large number of migration steps or
  extensive data transformations.

- The `migrate_0_6_to_0_7` method has been improved for increased performance
  and memory usage. Previously, this method would migrate all the outlier in
  database.

  The updated method now removes outlier that is not marked as saved. This change
  is expected to remove unnecessary outliers in the database.

## [0.14.1] - 2023-06-10

### Changed

- The `migrate_0_6_to_0_7` method has been improved for increased performance
  and memory usage. Previously, this method would first scan all outliers in
  the database, deserializing them into memory, and then traverse them again in
  reverse order to update each entry according to the new format of version
  0.7. This two-pass approach could be memory intensive for large databases.

  The updated method now directly traverses outliers in the database in reverse
  order and updates each entry in a single pass. This reduces the memory
  footprint and increases efficiency by removing the initial full scan of
  outliers. This change is expected to significantly improve the speed and
  memory consumption of migrations from version 0.6 to 0.7, especially for
  larger databases.

## [0.14.0] - 2023-06-08

### Changed

- Altered the model file naming convention: Files are now required to use the
.tmm extension. The format has changed from `{model_name}-{timestamp}` to
`{model_name}-{timestamp}.tmm`. This adjustment ensures consistency in model
file formats and enhances our file identification and management system.
- Updated the logging mechanism to include a message `Migrating database to
{version}` when a database migration starts. This change enhances the
visibility and traceability of our database migrations, aiding in system
maintenance and debugging efforts.

### Removed

- Removed `Database::update_agent_status` from the review-database. In prior
versions, this function was used when REview allowed agents to forward messages
from another agent not directly connected to REview. However, in the recent
architectural changes, all agents now directly connect to REview, rendering
this function obsolete. The removal of `Database::update_agent_status`
simplifies the overall architecture and eliminates unnecessary function calls,
leading to a more streamlined system.

## [0.13.2] - 2023-05-31

### Added

- Added `Store::pretrained_model` function to retrieve pre-trained models based
  on their names. This function allows users to retrieve a pre-trained model
  from the store by specifying its name. When called, the function returns a
  `PretrainedModel` struct, defined as `pub struct PretrainedModel(pub Vec<u8>)`.

## [0.13.1] - 2023-05-26

### Added

- New functions in `backup`:
  - `list`: This function retrieves the details of backups stored on the file
  system and returns a vector of `BackupInfo` instances. Each `BackupInfo`
  instance contains details such as the backup's ID, creation timestamp, and
  size.
  - `restore`: This function enables the restoration of backups using their ID.
  Users can restore their data from a specific backup by providing the `Store`
  instance and the backup ID.

### Fixed

- Corrected an issue in the `migrate_0_9_to_0_11` function in the
  review-database. The function was incorrectly updating `HttpThreatFields` to
  its latest (0.12) version instead of the intended 0.11 version, causing
  inconsistencies when `migrate_0_11_to_0_12` was subsequently applied. This
  has been resolved by introducing a new struct `NewHttpThreatFields` that
  correctly represents the `HttpThreatFields` structure at version 0.11. The
  function now deserializes the old fields into `OldHttpThreatFields`, converts
  it into `NewHttpThreatFields` (i.e., the 0.11 version), and then stores its
  serialized form back into the database. This ensures that each migration
  function behaves as expected and applies the correct changes respective to
  its version.

## [0.13.0] - 2023-05-25

### Added

- `backup::create`: This new function creates a new RocksDB backup. In a future
  release, this function will be enhanced to support creation of PostgreSQL
  backups as well. This provides a centralized and consistent interface for
  creating backups across different types of databases.
- New functions in `Store`:
  - `Store::get_backup_info`: This new function retrieves the details of
    backups stored on filesystem. The returned information is in the form of
    `Vec<BackupEngineInfo>`. Each `BackupEngineInfo` instance contains details
    like backup's timestamp, ID, size, and number of files. This will help
    users to get detailed insights about each backup available on the
    filesystem.
  - `Store::restore_from_backup`: This new function allows users to restore
    from a specific backup, given a backup ID. The feature adds significant
    utility to the users by enabling them to restore data from the selected
    backup easily and quickly.

### Changed

- The `backup` function has been renamed to `backup::schedule_periodic` for
  better clarity and to more accurately represent its functionality of
  initiating periodic backups. Please update any references in your codebase
  accordingly.

### Removed

- `Store::backup` has been removed from our API. It is replaced by the
  `backup::create` function to streamline and centralize backup operations.
  Please update your codebase to call `backup::create` for creating database
  backups.

## [0.12.0] - 2023-05-22

### Changed

- Removed `policy` field from `DataSource`. This change has been made to
  streamline the information flow and reduce redundancy in the data structure.
  If you were previously relying on this field, use `source` field instead.
- Added confidence field to `DgaFields`. This addition aims to provide a
  numeric measure of the reliability of DGA (Domain Generation Algorithm)
  detections, helping to make more informed decisions on potential threats.
- Changed the storage format for the time field in `HttpThreatFields`.
  Previously, the time field was stored as a `DateTime<Utc>`, but it's now
  being stored as nanoseconds in `i64`.

### Fixed

- Fixed a bug where an "invalid event" was incorrectly logged to syslog for DGA
  events.

## [0.11.0] - 2023-05-18

### Changed

- The `HttpThreat` event object has been significantly expanded to incorporate
  all its original fields.
- Added a new field called matched_to to the `HttpThreat` event object. This
  field will contain the patterns that have been matched, enabling users to
  identify the threats they are exposed to more effectively.

## [0.10.1] - 2023-05-16

### Fixed

- Fixed an issue where the `event_source` column becomes `null` when the value
  of `max_event_id_num` gets updated.

## [0.10.0] - 2023-05-16

### Changed

- Improved security by hiding `SaltedPassword`, `Account::password` field and
  related operations from user access.

## [0.9.0] - 2023-05-15

### Added

- Introduced a new iterator method, `Table<Account>::iter`, to enhance the
  encapsulation of the internal database serialization format and improve
  usability. This method returns an iterator that generates `Account` objects
  in each iteration, simplifying the use of iterators and mitigating potential
  issues associated with the direct manipulation of serialized data.
- Expanded the `DnsCovertChannel` and `TorConnection` events by adding all
  fields. These added fields enable packet attribute criteria to be performed
  during the adjudication function.
- Added support for argon2id as a password hashing algorithm.

### Changed

- Revised the
  `Event::DomainGenerationAlgorithm(Box<DomainGenerationAlgorithm>)` variant to
  `Event::DomainGenerationAlgorithm(DomainGenerationAlgorithm)`. This change
  enhances the code structure and reduces unnecessary memory allocations.

### Deprecated

- The methods `Table<Account>::iter_forward`, `Table<Account>::iter_backward`,
  and `Table<Account>::iter_from` have been deprecated. These methods will be
  removed in a future release. We encourage developers to transition to the new
  `Table<Account>::iter` method for iterating over `Account` objects in the
  database. The deprecated methods expose the internal, serialized form in the
  database as `[u8]`, which can create potential challenges in data handling.

## [0.8.0] - 2023-05-08

### Added

- Introduced a new column 'classification_id' in the 'model' table to track the
  timestamp of the latest model classification.

### Changed

- `Table<Account>::put` and `Table<Account>::insert` allow adding an Account
  instance directly to the database, without requiring explicit serialization
  by the caller.
- Renamed `Table<Account>::update_account` to `Table<Account>::update`. This
  change simplifies the method name and provides a more consistent interface
  for updating `Account` records.
- Introduced `event_sources` for `Cluster` to properly identify events included
  in the cluster.

### Removed

- Removed the old `Table<Account>::update` method. This method was exposing the
  internal format of the database to the public API, which could lead to
  potential security and compatibility issues. To maintain a secure and
  reliable interface, we have decided to remove this method. Users should now
  use the newly renamed `Table<Account>::update` method for updating `Account`
  records.

### Fixed

- Resolved issue with 'load_outliers' function to accurately retrieve cluster data.

## [0.7.1] - 2023-05-03

### Fixed

- Fixed query for selecting column description.
- Fixed a case where the migration process was not correctly handling existing
  empty values in the event_ids column.

## [0.7.0] - 2023-05-02

### Changed

- Updated `ip2location` to 0.4.2.
- Updated the database to include event_source(s) and modified the relevant
  queries to accommodate this change.

## [0.6.0] - 2023-04-26

### Changed

- Add `port/protocol` to `TrafficFilterRules` to filter traffic in Piglet

## [0.5.0] - 2023-04-24

### Changed

- The return value of `Store::account_map` method has been modified to provide
  better encapsulation and prevent misuse of account-related functions.
  Previously, this method returned a `Map` object, which allowed direct access
  to the underlying data structure. To ensure that account-related functions
  are only called on relevant objects, we have updated the return value to be
  `Table<Account>` instead. As part of this change, the `Map::update_account`
  function has been moved to `Table<Account>`. This helps prevent other Map
  objects that have nothing to do with Account from mistakenly calling the
  update_account function. This change aims to promote better practices in
  accessing and manipulating the account data, as well as providing a more
  consistent API for developers.
- `sensors`, `confidence`, and `learning_methods` are added in `EventFilter`.

### Removed

- `StatdDb` and `Map::new`. They are only used internally and shouldn't be
  called from another crate.
- `Map::update_account`. Use `Table<Account>::update_account` instead.
- `BlockingPgPool` has been removed as `diesel_async` is used instead.

## [0.4.0] - 2023-04-06

### Added

- Add `PrefixMap` to provide prefix iterating.

### Changed

- Update interface to interact with outlier map.

## [0.3.0] - 2023-03-30

### Added

- Support for Argon2id as a new and more secure alternative to the existing
  PBKDF2 password hashing algorithm.
- Add `distance` field for `UpdateOutlierRequest`.
- Add migration support for database.

### Removed

- `initial_account` has been removed since it should be defined by the
  application.

## [0.2.0] - 2023-03-22

### Changed

- `DataSource` is updated to store additional properties.

## [0.1.0] - 2023-03-20

### Added

- An initial version.

[Unreleased]: https://github.com/petabi/review-database/compare/0.25.0...main
[0.25.0]: https://github.com/petabi/review-database/compare/0.24.0...0.25.0
[0.24.0]: https://github.com/petabi/review-database/compare/0.23.0...0.24.0
[0.23.0]: https://github.com/petabi/review-database/compare/0.22.1...0.23.0
[0.22.1]: https://github.com/petabi/review-database/compare/0.22.0...0.22.1
[0.22.0]: https://github.com/petabi/review-database/compare/0.21.0...0.22.0
[0.21.0]: https://github.com/petabi/review-database/compare/0.20.0...0.21.0
[0.20.0]: https://github.com/petabi/review-database/compare/0.19.0...0.20.0
[0.19.0]: https://github.com/petabi/review-database/compare/0.18.0...0.19.0
[0.18.0]: https://github.com/petabi/review-database/compare/0.17.1...0.18.0
[0.17.1]: https://github.com/petabi/review-database/compare/0.17.0...0.17.1
[0.17.0]: https://github.com/petabi/review-database/compare/0.16.0...0.17.0
[0.16.0]: https://github.com/petabi/review-database/compare/0.15.2...0.16.0
[0.15.2]: https://github.com/petabi/review-database/compare/0.15.1...0.15.2
[0.15.1]: https://github.com/petabi/review-database/compare/0.15.0...0.15.1
[0.15.0]: https://github.com/petabi/review-database/compare/0.14.1...0.15.0
[0.14.1]: https://github.com/petabi/review-database/compare/0.14.0...0.14.1
[0.14.0]: https://github.com/petabi/review-database/compare/0.13.2...0.14.0
[0.13.2]: https://github.com/petabi/review-database/compare/0.13.1...0.13.2
[0.13.1]: https://github.com/petabi/review-database/compare/0.13.0...0.13.1
[0.13.0]: https://github.com/petabi/review-database/compare/0.12.0...0.13.0
[0.12.0]: https://github.com/petabi/review-database/compare/0.11.0...0.12.0
[0.11.0]: https://github.com/petabi/review-database/compare/0.10.1...0.11.0
[0.10.1]: https://github.com/petabi/review-database/compare/0.10.0...0.10.1
[0.10.0]: https://github.com/petabi/review-database/compare/0.9.0...0.10.0
[0.9.0]: https://github.com/petabi/review-database/compare/0.8.0...0.9.0
[0.8.0]: https://github.com/petabi/review-database/compare/0.7.1...0.8.0
[0.7.1]: https://github.com/petabi/review-database/compare/0.7.0...0.7.1
[0.7.0]: https://github.com/petabi/review-database/compare/0.6.0...0.7.0
[0.6.0]: https://github.com/petabi/review-database/compare/0.5.0...0.6.0
[0.5.0]: https://github.com/petabi/review-database/compare/0.4.0...0.5.0
[0.4.0]: https://github.com/petabi/review-database/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/petabi/review-database/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/petabi/review-database/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/petabi/review-database/tree/0.1.0

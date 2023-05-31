# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

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

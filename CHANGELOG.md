# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.0] - 2023-05-16

### Changed

- Improved security by hiding `SaltedPassword`, `Account::password` field and
  related operations from user access.

### Fixed

- Fixed an issue where the `event_source` column becomes `null` when the value
  of `max_event_id_num` gets updated.

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

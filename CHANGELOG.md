# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/petabi/review-database/compare/0.4.0...main
[0.4.0]: https://github.com/petabi/review-database/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/petabi/review-database/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/petabi/review-database/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/petabi/review-database/tree/0.1.0

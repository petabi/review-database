# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `ClassifierFileManager` for file system-based storage of classifier
  binary data, replacing direct PostgreSQL storage.
- Added new `TorConnectionConn` event kind and event structure for monitoring
  network connections to Tor exit nodes.
- Added hostname uniqueness constraint for nodes across all customers. Node
  hostnames in both `profile` and `profile_draft` fields must now be unique
  globally, preventing hostname conflicts between different customers.
- Added `confidence` and `kind` field to `tidb::Rule` struct.

### Changed

- Changed `classifier` column from `Bytea` to `Nullable<Bytea>` in PostgreSQL to
  support migration to file system storage.

### Removed

- Migration from version 0.39.0 and earlier is no longer supported.
- `Database::insert_column_statistics` is removed. User is advised to use
  `Table<'d, ColumnStats>::insert_column_statistics`.
- The `Indexed` trait is no longer necessary in the public API.
- `Database::get_columns_for_top_n` and `Database::get_top_multimaps_of_model`
  are removed. User is advised to use `Table<'d, CsvColumnExtra>::get_by_model`
  to retrieve `CsvColumnExtra` for the model, and then use
  `Table<'d, ColumnStats>::get_columns_for_top_n` and
  `Table<'d, ColumnStats>::get_top_multimaps_of_model` for retrieving
  corresponding statistics.
- `Database::count_rounds_by_cluster` and `Database::load_rounds_by_cluster` are
  removed. User is advised to use `Table<'d, ColumnStats>::count_rounds_by_cluster`
  and `Table<'d, ColumnStats>::load_rounds_by_cluster` respectively instead.
- `Database::get_column_types_of_model` is removed. User is advised to use
  `Table<'d, ColumnStats>::get_column_types_of_model`.
- `Database::get_top_ip_addresses_of_cluster` and `Database::get_top_ip_addresses_of_model`
  are removed. User is advised to use `Table<'d, CsvColumnExtra>::get_by_model`
  to retrieve `CsvColumnExtra` for the model, and then use
  `Table<'d, ColumnStats>::get_top_ip_addresses_of_cluster` and
  `Table<'d, ColumnStats>::get_top_ip_addresses_of_model` for retrieving
  corresponding statistics.

## [0.39.0] - 2025-07-07

### Added

- Added `confidence` field to all Blocklist detection event structures. The
  confidence value is set to 1.0 since Blocklist events are generated when
  user-specified blocklist IPs match, indicating high confidence in the
  detection.
- Added security-related methods to account management:
  `increment_failed_login`, `clear_failed_logins`, `is_account_locked`,
  `suspend_account`, `unsuspend_account`, and `get_accounts_with_security_status`.
- Added automatic account lockout functionality with configurable thresholds
  and time-based expiration for security protection.

### Changed

- Enhanced `Account` model with user security status fields including
  `failed_login_attempts`, `is_locked_out`, `locked_out_until`, and
  `is_suspended` to support comprehensive user security management.

## [0.38.0] - 2025-06-23

### Added

- Added `update_agent_status_by_hostname` public function to `Node` table. This
  function allows updating an agent’s status using the node’s hostname and the
  agent’s ID.
- Added triage functionality for scoring with attributes of each raw event.
  Previously, all detection events always returned a score of 0.0. It now
  compares the values against the provided attribute correctly and returns a
  score.
- Re-exported `RawEventKind` from attrievent crate to decouple version
  dependencies between review-database and review-web.

### Changed

- Renamed `last_time` to `end_time` in event structs within `src/event/*.rs`.
  This is a breaking API change.
- Renamed `BlockList` to `Blocklist` and `block_list` to `blocklist` in line with
  the Rust API Guidelines for acronyms/compound words. Please note that this is
  a breaking change if you were using identifiers affected by this change.
- Completed comprehensive terminology consolidation for blocklist-related terms:
  - Updated all instances of `BLOCK_LIST` constant to `BLOCKLIST`
  - Updated all instances of "Block List" string literals to "Blocklist"
  - Updated all instances of "block list" string literals to "blocklist"
  - Enhanced search arrays by adding "blocklist" as an additional searchable term
    alongside existing "block" and "list" terms for improved discoverability
- Modify the syslog message generation procedure to use dedicated formatter
  instead of Display trait.
- `Filter::host_name` has been renamed to `Filter::hostname` to align with the
  naming convention used in other parts of the codebase.
- Modified the `ValueKind` enum to support different types of input for packet
  attribute triage.
- Modified the `Node` structure to support managing the configuration of all
  external services that communicate with REview.
  - Introduced `ExternalService`, a new structure that stores configuration
    drafts for external services.
  - Introduced `ExternalServiceConfig`, `ExternalServiceStatus`, and
    `ExternalServiceKind` as types used by the `ExternalService` structure.
    - `ExternalServiceConfig` and `ExternalServiceStatus` are aliases of
      existing types (`node::Config`, `node::Status`).
    - `ExternalServiceKind` is a newly introduced enum with variants such as
      `DataStore` and `TiContainer`.
  - Added an `external_services` field of type `Vec<ExternalService>` to the
    `Node` structure to store all external service configurations.
- Modified `EventCategory` to include all MITRE categories.
  `Collection`, `DefenseEvasion`, `Persistence`, `PrivilegeEscalation`,
  `ResourceDevelopment` are added. And the deprecated member `HttpThreat` is removed.

### Fixed

- Corrected instances of `referrer` to `referer` for the HTTP header field name
  to align with the official HTTP standard's spelling (Issue #427).

## [0.37.0] - 2025-04-13

### Changed

- Added `confidence` field to the `BlockListTlsFields`. This change affects the
  `BlockListTls` and `SuspiciousTlsTraffic` events.

### Fixed

- Fixed the ability to filtering detected events by ip address value to work
  properly. This fix ensures that `ExternalDdos`, `MultiHostPortScan`, and
  `RdpBruteForce` with multiple addresses are filtered correctly.
  - Changed the return types of `src_addr` and `dst_addr` in the `Match` trait
    from `IpAddr` to `&[IpAddr]` to support returning one or more IP addresses.
  - Renamed the methods to `src_addrs` and `dst_addrs` to reflect the
    updated functionality.

## [0.36.0] - 2025-03-18

### Changed

- Added `Account::customer_ids` field to store the customer id that the user
  belongs to.

## Fixed

- Fixed learning method matches for the detected events. The previous
  implementation of learning method match used the `EventCategory`, but now all
  detected events have been modified to return `LearningMethod` (via the new
  `learning_method` method added to `Match` trait), so learning method match is
  performed using this value.

## [0.35.0] - 2025-02-22

### Changed

- Updated the Rust edition to 2024. It requires Rust version 1.85.0 or later.

### Fixed

- Fixed an issue where the `attempt_cluster_upsert` database function was not
  updated to reflect the renaming of the `Cluster::sensors` field. It was
  incorrectly referencing `Cluster::event_sources`, which is no longer
  available. This has been corrected by updating the code to use
  `Cluster::sensors` instead.

## [0.34.0] - 2025-01-20

### Added

- Added `Account::theme` field to represent user's selected screen color theme
  on the user interface.
- Added kind keywords for detailed searching of `RepeatedHttpSessions`,
  `NonBrowser`,`ExternalDdos`, `CryptocurrencyMiningPool`, `BlockListDceRpc`
  detection events.

### Changed

- The APIs taking an ip2location database non longer requires a mutable
  reference to the database. This change improves the ergonomics of the API and
  removes the need for locking the database.
- Modified the type of `cluster_id` from `usize` to `Option<usize>` in the
  detection event structures: `ExtraThreat`, `HttpThreatFields`, `HttpThreat`,
  `NetworkThreat`, and `WindowsThreat`, to account for events that may be
  generated from raw data other than clusters.
- Changed the type of `max_parallel_sessions` of `Account` from `Option<u32>` to
  `Option<u8>`, since the value is expected not to exceed the range of `u8`.

## [0.33.1] - 2024-12-20

### Fixed

- Corrected the migration bug introduced in 0.33.0. If the migration function in
  0.33.0 is called with the database version earlier than 0.30.0, it will fail
  to migrate the database, and the database will be left in an inconsistent
  state. This issue has been fixed in this release. The bug does not affect the
  database version 0.30.0 or later. Users who have already migrated to those
  versions, even though they have seen the migration failure message, can safely
  upgrade to this version.

## [0.33.0] - 2024-12-12 [YANKED]

### Changed

- Modified `Table::get_patterns` to take a reference to a slice of tuples
  instead of taking ownership of a vector, making the function more flexible.
- Replaced the term source with sensor, where it refers to a device or software
  that captures or detects raw events.
  - This update affects not only the fields in the event protocol structs such
    as `DnsEventFields::source` to `DnsEventFields::sensor`, but also in the
    following structs:
    - `Cluster::event_sources` to `Cluster::sensors`
    - `ModelBatchInfo::sources` to `ModelBatchInfo::sensors`
    - `Outlier::event_sources` to `Outlier::sensors`
    - `OutlierInfo::source` to `OutlierInfo::sensor`
    - `TriageResponse::source` to `TriageResponse::sensor`
  - With this update, the `syslog_message` function's return value reflects the
    updated terminology, replacing "source=" with "sensor=".

## [0.32.0] - 2024-11-07

### Changed

- `FromKeyValue` is sealed.
- Added a new variant `TimeSeriesGenerator` to `agent::Kind` and renamed below
  variants:
  - `Reconverge` to `Unsupervised`
  - `Hog` to `SemiSupervised`
  - `Piglet` to `Sensor`

### Removed

- `TrustedDomain` no longer implements `serde::Serialize` and
  `serde::Deserialize`. Its serialized form in the database is internal and
  should not be exposed to other modules.

### Fixed

- Fixed the indexed map name for `SamplingPolicy` in `IndexedTable`
  implementation, changing it from `NETWORKS` to `SAMPLING_POLICY`.

## [0.31.0] - 2024-10-01

### Added

- Introduced a new tool, review-migrate, for managing database migrations. The
  tool can be configured using either environment variables or a TOML file. This
  release introduces greater flexibility for managing REview's database
  migrations, allowing users to leverage both environment variables and TOML
  configuration files.
  - Users can provide a TOML configuration file to define the following settings:
    - `data_dir`: Path for REview's database backup storage. Default is the
      backup directory in the current directory.
    - `backup_dir`: Path for REview's local storage. Default is the data
      directory in the current directory.
    - `database_url`: PostgreSQL connection URI. Default is
      "postgres://review@localhost/review".
    - `ca_certs`: A list of CA certificate files to validate the PostgreSQL
      server's certificate.
  - Seamless Compatibility with REview Configurations. Users can reuse the same
    configuration settings from existing REview deployments to migrate databases
    using review-migrate.

### Changed

- Refactored the `UniqueKey` trait to remove the use of `Cow<[u8]>` as the
  return type for `unique_key`. The return type is now specified by an
  associated type `AsBytes<'a>`, allowing for more flexibliity in the
  implementation of `unique_key`.

### Removed

- `Database::cluster_id`: This method was previously used to convert a cluster
  name to a numerical ID when migrating from a name-based key to a numerical
  key. It is no longer needed as we now use numerical keys for clusters.
- `Database::get_top_clusters_by_score`: This method only returned an empty set
  and did not provide any meaningful functionality. `ClusterScore` and
  `ClusterScoreSet`, which were used by this method, have also been removed.

### Fixed

- Fixed an issue introduced in version 0.7.0 where the values of the `min`,
  `max`, `mean`, and `s_deviation` columns in the `description_int` table were
  not being inserted.

## [0.30.0] - 2024-09-03

### Added

- Added `BlockListBootp`, `BlockListDhcp`, `SuspiciousTlsTraffic` events.

### Changed

- Extended the `Table<'d, Account>::update` method signature to include the
  `language` parameter, enabling language updates alongside existing fields.
- Added `category` field to all the detected event structures.
- Added `category` field to TI db and TI rules.
- Modified all the detected events to use its own category field value
  instead of statically assigned values.
- Added fields to some detected event structures
  - `BlockListConn`: `orig_l2_bytes`, `resp_l2_bytes`
  - `TorConnection`: `orig_filenames`, `orig_mime_types`, `resp_filenames`,
    `resp_mime_types`, `post_body`, `state`
- Added `update` method in `TrustedDomain`.
- Improved platform certificate loading process to skip individual certificates
  that fail to load, allowing the rest of the certificates to be loaded
  successfully. Previously, the entire platform certificate loading process
  would fail if any certificate failed to load.
- Combine the detected event structures that share the same fields.
  - `FtpPlainTextFields`, `BlockListFtpFields` -> `FtpEventFields`
  - `LdapPlainTextFields`, `BlockListLdapFields` -> `LdapEventFields`
  - `TorConnectionFields`, `NonBrowserFields` -> `HttpEventFields`

### Removed

- The outlier table has been removed from the PostgreSQL database.

### Fixed

- Resolved an issue in the `NodeTable::update` method, where changes to
  `NodeUpdate::agents` were not being correctly reflected in the database. This
  fix ensures that any updates to agents are now accurately stored and
  retrieved, maintaining consistency between in-memory data structures and
  persistent storage.

### Security

- Updated `diesel-async` to version 0.5. This change allows the use of newer
  versions of Diesel beyond 2.2.2, addressing a reported security vulnerability
  in the previous version.

## [0.29.1] - 2024-08-05

### Fixed

- Corrected the database migration version number to ensure accurate tracking of
  schema changes and upgrades.

## [0.29.0] - 2024-07-25

### Added

- Introduced `Agent`, `AgentKind`, `AgentConfig` to describe data stored in
  `Table<Agent>`.
  - Each `Agent` is uniquely identified by the node id `Agent::node` and
    node-specific agent key `Agent::key`.
  - `AgentConfig` includes the configuration string of an agent following TOML
    format.
- Added new functions to facilitate insert and remove operations for more
  controlled and secure agent management.
- Introduced `Node::agents` to store `agents` of the `node`.
- Introduced `Giganto` to store giganto status and draft configuration in
  `Node::giganto`.
- Added `Account::password_last_modified_at` field to track the timestamp of the
  last password modification.
- Added `Account::language` field to represent user's selected language on the
  user interface.

### Changed

- Updated fields for events detected from HTTP, SMTP, CONN, NTLM, SSH, and TLS
  protocols.
- Modified to provide crypto libraries directly as `builder_with_provider` when
  generating `rustls::ClientConfig`.
- Changed the display message format of `EventMessage` and `Event` to RFC 5424.
  Modified messages will be sent to syslog.
- Used `FromPrimitive` and `ToPrimitive` for converting `EventCategory` instead of
  manually implementing `TryFrom`.
- `EventCategory` definition is moved to `review-protocol`.

### Removed

- `NodeSettings` is removed. Information stored in `Node::settings` and
  `Node::settings_draft` are split:
  - `NodeProfile` reflects node information in `Node::profile` and
    `Node::profile_draft`.
  - Agent-related information is now stored in `Agent::config` and
    `Agent::draft` as TOML-formatted strings.
  - Giganto-related settings from `Node::settings` are removed; those in
    `Node::settings_draft` are stored in `Node::giganto::draft` as
    TOML-formatted strings.

### Fixed

- Corrected `EventCategory` for events:
  - `RdpBruteForce`: Changed from `Exfiltration` to `Discovery`.
  - `HttpThreat`: Changed from `HttpThreat` to `Reconnaissance`.

### Deprecated

- `EventCategory::HttpThreat` is deprecated and replaced with `Reconnaissance`.
  After the modification of all programs using `EventCategory::HttpThreat`
  are completed, the `HttpThreat` category will be deleted.

## [0.28.0] - 2024-05-16

### Added

- Introduced `OutlierInfoKey`, `OutlierInfoValue` to describe data stored in
  `Table<OutlierInfo>`.
- Added new functions for insert and remove operations in outlier info
  management.
- Added `prefix_iter` to `Iterable` trait for database table prefix iteration.
- Added new functions for initialize, update, and get operations in account
  policy management.
- Added `Table<AccessToken>::tokens` for accessing all access tokens for a given
  username.

### Changed

- Changed return type of `Store::outlier_map` to `Table<OutlierInfo>`.
- Moved `OutlierInfo` from `crate::outlier` to `crate`.
- Included `model_id`, `timestamp`, and `is_saved` fields in `OutlierInfo`.
- Changed return type of `Store::account_policy_map` to `Table<AccountPlicy>`.
- Removed redundant log messages in the backup module.

### Removed

- Removed `PrefixMap` from codebase. Use `prefix_iter` in `Iterable` trait
  instead.
- Hidden `Map`, `IterableMap`, `MapIterator` from users for enhanced security.

## [0.27.1] - 2024-04-15

### Added

- Added new `LockyRansomware` detection event.

## [0.27.0] - 2024-04-02

### Added

- Introduced `SamplingInterval`, `SamplingPeriod`, `SamplingKind`,
  `SamplingPolicy` and `SamplingPolicyUpdate` to describe data stored in
  `IndexedTable<SamplingPolicy>`.
- Added new functions to facilitate insert, remove, and update operations,
  ensuring a more controlled and secure sampling policy management.
- Introduced `CustomerUpdate` to describe data for updating
  `IndexedTable<Customer>`.
- Added new functions to facilitate insert, remove, and update operations,
  ensuring a more controlled and secure customer management.
- Introduced `DataSourceUpdate` to describe data for updating
  `IndexedTable<DataSource>`.
- Added new functions to facilitate insert, remove, and update operations,
  ensuring a more controlled and secure data source management.
- Introduced `TriagePolicyUpdate` to describe data for updating
  `IndexedTable<TriagePolicy>`.
- Added new functions to facilitate insert, remove, and update operations,
  ensuring a more controlled and secure triage policy management.
- Introduced `Node`, `NodeSettings` and `NodeUpdate` to describe data stored in
  `IndexedTable<Node>`.
- Added new functions to facilitate insert, remove, and update operations,
  ensuring a more controlled and secure node management.
- Added new functions to facilitate insert, remove, and update operations,
  ensuring a more controlled and secure tidb management.
- Introduced `TrustedDomain` to describe data stored in `Table<TrustedDomain>`.
- Added new functions to facilitate insert, remove operations, ensuring a more
  controlled and secure trusted domain management.
- Introduced `TrustedUserAgent` to describe data stored in
  `IndexedTable<TrustedUserAgent>`.
- Added new functions to facilitate insert, remove, and update operations,
  ensuring a more controlled and secure trusted user agent management.
- Added new functions to facilitate insert, remove, and update operations,
  ensuring a more controlled and secure traffic filter management.

### Changed

- Changed the return type of `Store::sampling_policy_map` to
  `IndexedTable<SamplingPolicy>` to enhance security by preventing direct
  exposure of internal structure.
- Changed the return type of `Store::customer_map` to `IndexedTable<Customer>`
  to enhance security by preventing direct exposure of internal structure.
- Moved `crate::types::Customer` and `crate::types::CustomerNetwork` to
  `crate::Customer` and `crate::CustomerNetwork` respectively to align with other
  type definitions.
- Associated `Customer`, `CustomerNetwork`, with the customer data table in the
  database.
- Moved `crate::types::DataSource` and `crate::types::DataType` to
  `crate::DataSource` and `crate::DataType` respectively to align with other
  type definitions.
- Associated `DataSource`, `DataType`, with the customer data table in the
  database.
- Moved `AttrCmpKind`, `Confidence`, `PacketAttr`, `Response`, `ResponseKind`,
  `Ti`, `TiCmpKind`, `TriagePolicy`, `ValueKind` from `crate::types` to `crate`
  in order to align with other type definitions.
- Associated `TriagePolicy` with the triage policy data table in the database.
- Changed the return type of `Store::node_map` to `IndexedTable<Node>`
  to enhance security by preventing direct exposure of internal structure.
- Moved `Tidb`, `TidbKind` and `TidbRule` from `crate::types` to `crate` in order
  to align with other type definitions.
- Changed the return type of `Store::tidb_map` to `Table<Tidb>` to enhance
  security by preventing direct exposure of internal structure.
- Modified `Tidb::new` method to require input string serialization using
  `bincode::DefaultOptions::new().serialize` instead of `bincode::serialize` for
  consistency across the library.
- Replaced `Store::trusted_dns_servers_map` with `Store::trusted_domain_map` for
  consistency and to enhance security by preventing direct exposure of internal
  structure.
- Changed the return type of `Store::trusted_user_agent_map` to
  `Table<TrustedUserAgent>` to enhance security by preventing direct exposure of
  internal structure.
- Moved `TrafficFilter` and `ProtocolPorts` from `crate::types` to `crate` in
  order to align with other type definitions.
- Changed the return type of `Store::traffic_filter_map` to
  `Table<TrafficFilter>` to enhance security by preventing direct exposure of
  internal structure.

## [0.26.0] - 2024-03-11

### Added

- Added `Indexable::id` and `Indexable::make_indexed_key` for `Indexable` trait.
  This enhancement provides users with greater flexibility in customizing the
  `indexed_key` associated with `Indexable` trait.
- Introduced `Network` and `NetworkUpdate` to describe data stored in
  `Table<Network>`.
- Added new functions to facilitate insert, remove, and update operations,
  ensuring a more controlled and secure allow network management.
- Introduced `AllowNetwork` and `AllowNetworkUpdate` to describe data stored in
  `Table<Network>`.
- Added new functions to facilitate insert, remove, and update operations,
  ensuring a more controlled and secure network management.
- Introduced `BlockNetwork` and `BlockNetworkUpdate` to describe data stored in
  `Table<Network>`.
- Added new functions to facilitate insert, remove, and update operations,
  ensuring a more controlled and secure block network management.

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
- Replaced the `IndexedTable<Category>::get`, `IndexedTable<Qualifier>::get` and
  `IndexedTable<Status>::get` method with the more general function
  `IndexedTable<R>::get_by_id`. This change enhances flexibility by allowing
  retrieval based on any type R rather than being limited to a specific
  category. Existing code using get for categories should be updated to use
  get_by_id with the appropriate type.
- Changed the return type of `Store::allow_network_map` to
  `IndexedTable<AllowNetwork>` to enhance security by preventing direct exposure
  of internal structure.
- Changed the return type of `Store::block_network_map` to
  `IndexedTable<BlockNetwork>` to enhance security by preventing direct exposure
  of internal structure.

### Removed

- `IndexedMultiMap` has been removed from the codebase, for table that currently
  use `IndexedMultiMap` use `IndexedMap` with a customized
  `Indexable::make_indexed_key` for entries stored instead.
- `IndexedSet` has been removed, replaced by `TagSet`.
- `csv_column_extra` table from PostgreSQL database is now permanently removed.
  - To ensure data integrity and avoid potential data loss, users currently
    utilizing review-database versions below 0.25.0 must migrate to version
    0.25.0 before proceeding with any further migrations.

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
- Introduced `TriageResponse` to describe data stored in
  `IndexedTable<TriageResponse>`.
- Introduced `TriageResponseUpdate` to support `TriageResponse` record update.
- Added new functions to facilitate insert, remove, and update operations,
  ensuring a more controlled and secure triage response management.
- Introduced `TorExitNode` to describe data stored in `Table<TorExitNode>`.
- Added new functions to facilitate replace and list operations, ensuring a
  more controlled and secure tor exit node management.

### Changed

- Moved the csv_column_extra table from the PostgreSQL database to RocksDB.
  - The csv_column_extra table data is now stored in RocksDB for improved
    performance and scalability.
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
- Changed the return type of `Store::access_token_map` to `Table<AccessToken>`
  to enhance security by preventing direct exposure of `Map`.
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
- Changed the return type of `Store::model_indicator_map` to
  `Table<ModelIndicator>` to enhance security by preventing direct exposure of
  `Map`.
- Moved member functions of `ModelIndicator` that are related to database
  operations under `Table<ModelIndicator>` to facilitate insert, remove, update,
  get and list operations, ensuring a more controlled and secure model indicator
  management and improved code organization.
- Modified `ModelIndicator` struct to include the `name` property, representing
  the associated name for the specific `ModelIndicator`.
- `Store::event_tag_set` and `Store::workflow_tag_set` now returns `TagSet`
  instead of `IndexSet`. This change is made to leverage the new `TagSet`
  structure for a more user-friendly approach in accessing tags. The `TagSet`
  allows users to interact with tags through the `Tag` struct, which includes
  `name` and `id` fields, offering a more straightforward and human-readable
  format compared to the raw binary format exposed by `IndexSet`.
- Changed the return type of `Store::template_map` to `Table<Template>` to
  enhance security by preventing direct exposure of `Map`.
- The Template type has been replaced with the enum type. This modification
  reflects the diverse templates supported by the database.
- Changed the return type of `Store::triage_response_map` to
  `IndexedTable<TriageResponse>` to enhance security by preventing direct
  exposure of `IndexedMap`.
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
- `nodes` table's fields are modified. Migration of data is supported by
  function `migrate_0_20_to_0_22`.

### Deprecated

- `category` table from PostgreSQL database is now deprecated.

## [0.21.0] - 2023-12-01

### Added

- Introduced the `batch_ts` attribute to the `Statistics` module, providing users
  with the ability to retrieve the timestamp associated with the batch of column
  statistics. This information is valuable for tracking changes over time and
  aligning statistical insights with specific data batches.

### Changed

- Removed `batch_info` and `scores` arguments from `Model::from_storage`
  function. These arguments were previously used for custom initialization of
  the `batch_info` and `scores` fields within the model. This change means that
  when you create a model using `Model::from_storage`, the `batch_info` and
  `scores` fields will now be initialized with their default values. If you
  previously relied on custom values for these fields, you will need to update
  your code accordingly.

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
  indicates the specific version associated with each model. Existing model
  entry will have default version 0.
- Introduced new database tables `BATCH_INFO` and `SCORES` to facilitate the
  recording of batch information and scores.
- Introduced the `ModelSql` struct, aimed at encapsulating all information
  related to models stored in the PostgreSQL database.
- Introduced the `ModelDigest` struct, designed to encapsulate all the
  information necessary for the web user interface.
- Requires a 16 bytes long header for serializing or deserializing `Model`, encoded
  with version, kind, format version information for `Model`.

### Changed

- Updated the `Model` struct, encompassing all the information pertinent to a
  model.
- Return deleted model id for `delete_model`.
- Enhanced and Modified `add_model`, `update_model` for improved usability and
  clarity. The functions now accept a single parameter of type `SqlModel`
  encapsulating various attributes that are required for adding or updating a
  model.
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

  - Users on versions prior to 0.12.0 will need to manually manage their
    database schema updates if they choose to continue using these older
    versions.
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

- Removed `src_port` field from `FtpBruteForce` and `LdapBruteForce` events. to
  align with the event fields provided by hog.
- Modified `LdapPlainText` fields to appropriate LDAP event fields from wrong
  fields. This changes require updates in dependent projects due to complete
  change of the fields.
- Modified `FtpBruteForce` by adding an `is_internal` field which is a boolean
  indicating whether it is internal or not.

[Unreleased]: https://github.com/petabi/review-database/compare/0.39.0...main
[0.39.0]: https://github.com/petabi/review-database/compare/v0.38.0...0.39.0
[0.38.0]: https://github.com/petabi/review-database/compare/0.37.0...0.38.0
[0.37.0]: https://github.com/petabi/review-database/compare/0.36.0...0.37.0
[0.36.0]: https://github.com/petabi/review-database/compare/0.35.0...0.36.0
[0.35.0]: https://github.com/petabi/review-database/compare/0.34.0...0.35.0
[0.34.0]: https://github.com/petabi/review-database/compare/0.33.1...0.34.0
[0.33.1]: https://github.com/petabi/review-database/compare/0.33.0...0.33.1
[0.33.0]: https://github.com/petabi/review-database/compare/0.32.0...0.33.0
[0.32.0]: https://github.com/petabi/review-database/compare/0.31.0...0.32.0
[0.31.0]: https://github.com/petabi/review-database/compare/0.30.0...0.31.0
[0.30.0]: https://github.com/petabi/review-database/compare/0.29.1...0.30.0
[0.29.1]: https://github.com/petabi/review-database/compare/0.29.0...0.29.1
[0.29.0]: https://github.com/petabi/review-database/compare/0.28.0...0.29.0
[0.28.0]: https://github.com/petabi/review-database/compare/0.27.1...0.28.0
[0.27.1]: https://github.com/petabi/review-database/compare/0.27.0...0.27.1
[0.27.0]: https://github.com/petabi/review-database/compare/0.26.0...0.27.0
[0.26.0]: https://github.com/petabi/review-database/compare/0.25.0...0.26.0
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


CREATE TABLE IF NOT EXISTS column_description (
  id SERIAL PRIMARY KEY,
  cluster_id INTEGER NOT NULL,
  batch_ts TIMESTAMP NOT NULL,
  column_index INTEGER NOT NULL,
  type_id INTEGER NOT NULL,
  count BIGINT NOT NULL,
  unique_count BIGINT NOT NULL
);
<<<<<<< HEAD
=======
CREATE INDEX IF NOT EXISTS column_description_idx ON column_description(event_range_id, column_index);
>>>>>>> 1717a0b (Remove `top_n_*`, `description_*`, `column_description`, `csv_column_extra` tables from PostgresQL)
CREATE TABLE IF NOT EXISTS csv_column_extra (
    id SERIAL PRIMARY KEY,
    model_id INTEGER NOT NULL,
    column_alias TEXT[],
    column_display BOOL[],
    column_top_n BOOL[],
    column_1 BOOL[],
    column_n BOOL[],
    UNIQUE(model_id)
);
CREATE TABLE IF NOT EXISTS description_binary (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  mode BYTEA NOT NULL
);
CREATE TABLE IF NOT EXISTS description_datetime (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  mode TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS description_enum (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  mode TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS description_float (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  min DOUBLE PRECISION,
  max DOUBLE PRECISION,
  mean DOUBLE PRECISION,
  s_deviation DOUBLE PRECISION,
  mode_smallest DOUBLE PRECISION NOT NULL,
  mode_largest DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS description_int (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  min BIGINT,
  max BIGINT,
  mean DOUBLE PRECISION,
  s_deviation DOUBLE PRECISION,
  mode BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS description_ipaddr (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  mode TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS description_text (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  mode TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS top_n_binary (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  value BYTEA NOT NULL,
  count BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS top_n_binary_idx_desc_id ON top_n_binary(description_id);
CREATE TABLE IF NOT EXISTS top_n_datetime (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  value TIMESTAMP NOT NULL,
  count BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS top_n_datetime_idx_desc_id ON top_n_datetime(description_id);
CREATE TABLE IF NOT EXISTS top_n_enum (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  value TEXT NOT NULL,
  count BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS top_n_enum_idx_desc_id ON top_n_enum(description_id);
CREATE TABLE IF NOT EXISTS top_n_float (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  value_smallest DOUBLE PRECISION NOT NULL,
  value_largest DOUBLE PRECISION NOT NULL,
  count BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS top_n_float_idx_desc_id ON top_n_float(description_id);
CREATE TABLE IF NOT EXISTS top_n_int (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  value BIGINT NOT NULL,
  count BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS top_n_int_idx_desc_id ON top_n_int(description_id);
CREATE TABLE IF NOT EXISTS top_n_ipaddr (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  value TEXT NOT NULL,
  count BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS top_n_ipaddr_idx_desc_id ON top_n_ipaddr(description_id);
CREATE TABLE IF NOT EXISTS top_n_text (
  id SERIAL PRIMARY KEY,
  description_id INTEGER NOT NULL,
  value TEXT NOT NULL,
  count BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS top_n_text_idx_desc_id ON top_n_text(description_id);

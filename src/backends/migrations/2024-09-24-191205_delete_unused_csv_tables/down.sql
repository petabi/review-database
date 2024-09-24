CREATE TABLE "csv_column_list"(
	"id" INT4 NOT NULL PRIMARY KEY,
	"model_id" INT4 NOT NULL,
	"column_indicator" TEXT[],
	"column_whitelist" TEXT[]
);

CREATE TABLE "csv_indicator"(
	"id" INT4 NOT NULL PRIMARY KEY,
	"name" TEXT NOT NULL,
	"description" TEXT,
	"list" TEXT NOT NULL,
	"last_modification_time" TIMESTAMP
);

CREATE TABLE "csv_whitelist"(
	"id" INT4 NOT NULL PRIMARY KEY,
	"name" TEXT NOT NULL,
	"description" TEXT,
	"list" TEXT NOT NULL,
	"last_modification_time" TIMESTAMP
);

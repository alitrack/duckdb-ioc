# Extension configuration for `DuckDB`'s build system.
# Required by extension-ci-tools even for pure-Rust (cargo) extensions.
# See: https://github.com/duckdb/extension-ci-tools

duckdb_extension_load(units
	LOAD_TESTS
	GIT_URL https://github.com/alitrack/duckdb-units
	GIT_TAG main
)

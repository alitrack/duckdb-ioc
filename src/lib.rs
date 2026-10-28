// DuckDB loadable extension: IOC (indicator-of-compromise) defang/refang,
// extraction, and classification for threat-intel reports, written in SQL.
//
// This file is a thin quack-rs binding layer over `ioc.rs` (a pure-Rust
// matching engine — lazy-compiled regexes, no VGI, no Arrow IPC, no JSON).
// The engine was ported verbatim from Query-farm's `vgi-ioc` VGI worker (MIT);
// only the Arrow IPC transport layer was removed and replaced with direct
// C-API vector I/O.
//
// Function surface:
//
//   defang(text)            -> VARCHAR  (NULL in -> NULL out)
//   refang(text)            -> VARCHAR  (NULL in -> NULL out)
//   extract_ipv4(text)      -> VARCHAR[]  (refangs first; private/reserved kept)
//   extract_ipv6(text)      -> VARCHAR[]
//   extract_domains(text)   -> VARCHAR[]  (URL/e-mail hosts excluded)
//   extract_urls(text)      -> VARCHAR[]
//   extract_emails(text)    -> VARCHAR[]
//   extract_hashes(text)    -> VARCHAR[]  (md5/sha1/sha256/sha512)
//   extract_cves(text)      -> VARCHAR[]
//   hash_type(s)            -> VARCHAR    (NULL if not a known hash)
//   is_ioc(text)            -> BOOLEAN    (NULL in -> NULL out)
//   extract_iocs(text)      -> table(type VARCHAR, value VARCHAR)
//                                      (text is a bind-time constant)
//
// Semantics (inherited from vgi-ioc):
//   * Every extractor (and `is_ioc`) refangs its input first, so defanged
//     indicators written as `hxxp[://]evil[.]com` / `10[.]0[.]0[.]5` are still
//     found. `defang`/`refang` are the only fns that do not refang first —
//     they *are* the fanging step.
//   * NULL text -> NULL (scalar) or zero rows (table). Empty text -> empty
//     list / zero rows.
//   * Extractors deduplicate; a URL or e-mail host is not also emitted as a
//     bare domain (URLs/e-mails "win" their hosts).
//   * `extract_iocs(text)` takes a *constant* text argument (DuckDB table
//     functions bind positional constants, not row columns), so it reads the
//     value at bind time and emits one (type, value) row per distinct IOC.

use libduckdb_sys::{duckdb_bind_get_parameter, duckdb_bind_get_parameter_count, duckdb_get_varchar, duckdb_vector_size};
use quack_rs::connection::{Connection, Registrar};
use quack_rs::error::ExtensionError;
use quack_rs::scalar::{ScalarFunctionBuilder, ScalarFunctionInfo};
use quack_rs::table::{BindInfo, FfiBindData, FfiInitData, InitInfo, TableFunctionBuilder};
use quack_rs::types::{LogicalType, TypeId};
use quack_rs::vector::{ListBuilder, VectorReader, VectorWriter};

mod ioc;

use ioc::{defang, extract_cves, extract_domains, extract_emails, extract_hashes, extract_iocs, extract_ipv4, extract_ipv6, extract_urls, hash_type, is_ioc, refang};

// Per-call output cap for the LIST-returning extractors. A single pathological
// cell could otherwise force an unbounded child allocation; past this a row is
// written as NULL and we surface an error (mirrors the tiktoken port).
const MAX_INDICATORS_PER_CALL: usize = 10_000;

// ─────────────────────────────────────────────────────────────────────────────
// Scalars: defang / refang (VARCHAR -> VARCHAR)
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(defang_fn, |_info, input, output| {
    unsafe {
        let text = VectorReader::new(input, 0);
        let row_count = text.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            match text.is_valid(row) {
                true => writer.write_varchar(row, &defang(text.read_str(row))),
                false => writer.set_null(row),
            }
        }
    }
});

quack_rs::scalar_callback!(refang_fn, |_info, input, output| {
    unsafe {
        let text = VectorReader::new(input, 0);
        let row_count = text.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            match text.is_valid(row) {
                true => writer.write_varchar(row, &refang(text.read_str(row))),
                false => writer.set_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// Scalars: the 7 LIST(VARCHAR) extractors
// ─────────────────────────────────────────────────────────────────────────────

/// Shared helper: for each row, call `extract(text)` (which already refangs
/// first) and emit the result as a VARCHAR list. NULL text -> NULL list.
macro_rules! extract_list_callback {
    ($cb_name:ident, $extract:expr) => {
        quack_rs::scalar_callback!($cb_name, |info, input, output| {
            unsafe {
                let text = VectorReader::new(input, 0);
                let row_count = text.row_count();
                let fn_info = ScalarFunctionInfo::new(info);
                let mut builder = ListBuilder::new(output).with_element_limit(MAX_INDICATORS_PER_CALL);
                for row in 0..row_count {
                    if !text.is_valid(row) {
                        builder.push_row(row, 0, |_, _| {});
                        VectorWriter::from_vector(output).set_null(row);
                        continue;
                    }
                    let items = $extract(text.read_str(row));
                    let n = items.len();
                    builder.push_row(row, n, |w, base| {
                        for (i, s) in items.iter().enumerate() {
                            w.write_str(base + i, s.as_str());
                        }
                    });
                }
                if builder.overflowed() {
                    fn_info.set_error(&format!(
                        "extract: a row produced more than {n} indicators — process smaller batches",
                        n = MAX_INDICATORS_PER_CALL
                    ));
                }
                builder.finish();
            }
        });
    };
}

extract_list_callback!(extract_ipv4_fn, extract_ipv4);
extract_list_callback!(extract_ipv6_fn, extract_ipv6);
extract_list_callback!(extract_domains_fn, extract_domains);
extract_list_callback!(extract_urls_fn, extract_urls);
extract_list_callback!(extract_emails_fn, extract_emails);
extract_list_callback!(extract_hashes_fn, extract_hashes);
extract_list_callback!(extract_cves_fn, extract_cves);

// ─────────────────────────────────────────────────────────────────────────────
// Scalars: hash_type(VARCHAR) -> VARCHAR ; is_ioc(VARCHAR) -> BOOLEAN
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(hash_type_fn, |_info, input, output| {
    unsafe {
        let text = VectorReader::new(input, 0);
        let row_count = text.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            match text.is_valid(row) {
                true => match hash_type(text.read_str(row)) {
                    Some(kind) => writer.write_varchar(row, kind),
                    None => writer.set_null(row),
                },
                false => writer.set_null(row),
            }
        }
    }
});

quack_rs::scalar_callback!(is_ioc_fn, |_info, input, output| {
    unsafe {
        let text = VectorReader::new(input, 0);
        let row_count = text.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            match text.is_valid(row) {
                true => writer.write_bool(row, is_ioc(text.read_str(row))),
                false => writer.set_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// Table function: extract_iocs(text) -> (type VARCHAR, value VARCHAR)
//
// `text` is a bind-time constant. We read it in bind, store it in bind data,
// compute the rows in init, and stream them in scan.
// ─────────────────────────────────────────────────────────────────────────────

struct IocBind {
    text: String,
}

struct IocState {
    next: usize,
    total: usize,
    rows: Vec<ioc::Indicator>,
}

quack_rs::table_bind_callback!(extract_iocs_bind, |info| {
    unsafe {
        let bind_info = BindInfo::new(info);
        bind_info
            .add_result_column("type", TypeId::Varchar)
            .add_result_column("value", TypeId::Varchar);

        // Read the single positional constant argument. A NULL/absent argument
        // means "no rows".
        let text = if duckdb_bind_get_parameter_count(info) > 0 {
            let v = duckdb_bind_get_parameter(info, 0);
            // SAFETY: `v` is valid while `info` lives; the pointer DuckDB hands
            // back is valid for the bind callback duration, which is exactly
            // where we copy it.
            std::ffi::CStr::from_ptr(duckdb_get_varchar(v))
                .to_string_lossy()
                .into_owned()
        } else {
            String::new()
        };

        FfiBindData::<IocBind>::set(info, IocBind { text });
    }
});

quack_rs::table_init_callback!(extract_iocs_init, |info| {
    unsafe {
        let rows = FfiBindData::<IocBind>::get_from_init(info)
            .map(|b| extract_iocs(&b.text))
            .unwrap_or_default();
        let total = rows.len();
        InitInfo::new(info).set_max_threads(1);
        FfiInitData::<IocState>::set(
            info,
            IocState {
                next: 0,
                total,
                rows,
            },
        );
    }
});

quack_rs::table_scan_callback!(extract_iocs_scan, |info, output| {
    unsafe {
        let chunk = quack_rs::data_chunk::DataChunk::from_raw(output);
        let Some(state) = FfiInitData::<IocState>::get_mut(info) else {
            chunk.set_size(0);
            return;
        };
        if state.next >= state.total {
            chunk.set_size(0);
            return;
        }
        let batch = (state.total - state.next).min(duckdb_vector_size() as usize);
        let mut ty = chunk.writer(0);
        let mut val = chunk.writer(1);
        for i in 0..batch {
            let r = &state.rows[state.next + i];
            ty.write_varchar(i, r.kind);
            val.write_varchar(i, &r.value);
        }
        state.next += batch;
        chunk.set_size(batch)
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// Registration + entry point
// ─────────────────────────────────────────────────────────────────────────────

// LogicalType is a non-Clone FFI handle, so build a fresh one per registration.
fn varchar_list_type() -> LogicalType {
    LogicalType::list(TypeId::Varchar)
}

unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {

    // defang / refang
    con.register_scalar(
        ScalarFunctionBuilder::new("defang")
            .param(TypeId::Varchar)
            .returns(TypeId::Varchar)
            .function(defang_fn),
    )?;
    con.register_scalar(
        ScalarFunctionBuilder::new("refang")
            .param(TypeId::Varchar)
            .returns(TypeId::Varchar)
            .function(refang_fn),
    )?;

    // the 7 LIST(VARCHAR) extractors
    con.register_scalar(
        ScalarFunctionBuilder::new("extract_ipv4")
            .param(TypeId::Varchar)
            .returns_logical(varchar_list_type())
            .function(extract_ipv4_fn),
    )?;
    con.register_scalar(
        ScalarFunctionBuilder::new("extract_ipv6")
            .param(TypeId::Varchar)
            .returns_logical(varchar_list_type())
            .function(extract_ipv6_fn),
    )?;
    con.register_scalar(
        ScalarFunctionBuilder::new("extract_domains")
            .param(TypeId::Varchar)
            .returns_logical(varchar_list_type())
            .function(extract_domains_fn),
    )?;
    con.register_scalar(
        ScalarFunctionBuilder::new("extract_urls")
            .param(TypeId::Varchar)
            .returns_logical(varchar_list_type())
            .function(extract_urls_fn),
    )?;
    con.register_scalar(
        ScalarFunctionBuilder::new("extract_emails")
            .param(TypeId::Varchar)
            .returns_logical(varchar_list_type())
            .function(extract_emails_fn),
    )?;
    con.register_scalar(
        ScalarFunctionBuilder::new("extract_hashes")
            .param(TypeId::Varchar)
            .returns_logical(varchar_list_type())
            .function(extract_hashes_fn),
    )?;
    con.register_scalar(
        ScalarFunctionBuilder::new("extract_cves")
            .param(TypeId::Varchar)
            .returns_logical(varchar_list_type())
            .function(extract_cves_fn),
    )?;

    // hash_type / is_ioc
    con.register_scalar(
        ScalarFunctionBuilder::new("hash_type")
            .param(TypeId::Varchar)
            .returns(TypeId::Varchar)
            .function(hash_type_fn),
    )?;
    con.register_scalar(
        ScalarFunctionBuilder::new("is_ioc")
            .param(TypeId::Varchar)
            .returns(TypeId::Boolean)
            .function(is_ioc_fn),
    )?;

    // extract_iocs(text) -> table(type, value)
    con.register_table(
        TableFunctionBuilder::new("extract_iocs")
            .param(TypeId::Varchar)
            .bind(extract_iocs_bind)
            .init(extract_iocs_init)
            .scan(extract_iocs_scan),
    )?;

    Ok(())
}

quack_rs::entry_point_v2!(ioc_init_c_api, |con| register_all(con));

// SPDX-License-Identifier: GPL-3.0-only

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};
use serde_json::Value;
use sysdiagnose_extractor_library::parsers::clamp_logarchive_decode_max_lines;
use sysdiagnose_extractor_library::{
    all_parser_types, parser_for_with_options, retention_plan, run_parsers_concurrently,
    ArchiveOptions, ParseOptions, ParserType, SysdiagnoseArchive,
};

#[pyfunction]
fn list_parsers() -> Vec<String> {
    all_parser_types()
        .into_iter()
        .map(|p| p.as_str().to_string())
        .collect()
}

#[pyfunction]
#[pyo3(signature = (path, parsers=None, logarchive_max_lines=None, logarchive_memory_threshold=None))]
fn parse(
    py: Python<'_>,
    path: &str,
    parsers: Option<Vec<String>>,
    logarchive_max_lines: Option<usize>,
    logarchive_memory_threshold: Option<u64>,
) -> PyResult<Py<PyAny>> {
    let selected = match parsers {
        Some(names) => {
            let mut out = Vec::new();
            for name in names {
                let kind = name.parse::<ParserType>().map_err(|_| {
                    PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                        "unknown sysdiagnose parser: {name}"
                    ))
                })?;
                out.push(kind);
            }
            out
        }
        None => all_parser_types(),
    };
    let mut opts = ParseOptions::default();
    if let Some(n) = logarchive_max_lines {
        opts.logarchive_decode_max_lines = clamp_logarchive_decode_max_lines(n);
    }
    if let Some(n) = logarchive_memory_threshold {
        opts.logarchive_memory_threshold = n;
    }
    let plan = retention_plan(&selected);
    let archive = SysdiagnoseArchive::open_path_with_plan(path, ArchiveOptions::default(), &plan)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string()))?;
    let jobs: Vec<_> = selected
        .into_iter()
        .map(|t| (t, parser_for_with_options(t, opts.clone())))
        .collect();
    let results = py.detach(|| run_parsers_concurrently(std::sync::Arc::new(archive), jobs));
    let dict = PyDict::new(py);
    for (kind, res, dur) in results {
        let obj = PyDict::new(py);
        let ms = dur.as_millis() as u64;
        match res {
            Ok(val) => {
                obj.set_item("ok", true)?;
                obj.set_item("ms", ms)?;
                obj.set_item("data", json_to_py(py, &val)?)?;
            }
            Err(err) => {
                obj.set_item("ok", false)?;
                obj.set_item("ms", ms)?;
                obj.set_item("error", err.to_string())?;
            }
        }
        dict.set_item(kind.as_str(), obj)?;
    }
    Ok(dict.into_any().unbind())
}

fn json_to_py(py: Python<'_>, v: &Value) -> PyResult<Py<PyAny>> {
    let s = serde_json::to_string(v).unwrap_or_else(|_| "null".into());
    let json = py.import("json")?;
    Ok(json.call_method1("loads", (s,))?.unbind())
}

#[pymodule]
fn sysdiagnose_extractor(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(list_parsers, m)?)?;
    m.add_function(wrap_pyfunction!(parse, m)?)?;
    Ok(())
}

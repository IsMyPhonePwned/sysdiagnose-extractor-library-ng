// SPDX-License-Identifier: GPL-3.0-only

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use serde_json::{json, Map, Value};
use sysdiagnose_extractor_library::{
    all_parser_types, parser_for_with_options, retention_plan, run_parsers_concurrently,
    ArchiveOptions, ParseOptions, ParserType, SysdiagnoseArchive,
};
use sysdiagnose_extractor_library::parsers::clamp_logarchive_decode_max_lines;

#[derive(Parser, Debug)]
#[command(name = "sdx-cli", about = "Parse an Apple sysdiagnose archive")]
struct Args {
    archive: Option<PathBuf>,
    #[arg(long)]
    parsers: Option<String>,
    #[arg(long)]
    list_parsers: bool,
    #[arg(long)]
    show_parser_results: bool,
    #[arg(long)]
    threads: Option<usize>,
    #[arg(long)]
    mem_budget: Option<u64>,
    #[arg(long)]
    spill_dir: Option<PathBuf>,
    #[arg(long)]
    profile: Option<String>,
    #[arg(long)]
    jsonl_out: Option<PathBuf>,
    #[arg(long)]
    stats: bool,
    #[arg(long)]
    ioservice_full_tree: bool,
    #[arg(long)]
    logarchive_inventory_only: bool,
    /// Max unified-log lines. `0` means 250000, the same ceiling as the other CLI.
    #[arg(long)]
    logarchive_decode_max_lines: Option<usize>,
    /// Stop unified-log decode after this many retained bytes. Omit to leave the limit off.
    #[arg(long)]
    logarchive_memory_threshold: Option<u64>,
}

fn main() {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();
    let args = Args::parse();
    if args.list_parsers {
        for p in all_parser_types() {
            println!("{}\t{}", p.as_str(), p.description());
        }
        return;
    }
    let Some(path) = args.archive else {
        eprintln!("missing archive path");
        std::process::exit(2);
    };
    let parsers = match &args.parsers {
        Some(s) if !s.is_empty() => s
            .split(',')
            .filter_map(|p| p.trim().parse::<ParserType>().ok())
            .collect(),
        _ => all_parser_types(),
    };
    let mut opts = ArchiveOptions::default();
    if let Some(n) = args.mem_budget {
        opts.mem_budget = n;
    }
    if let Some(dir) = args.spill_dir.clone() {
        opts.spill_dir = Some(dir);
    }
    match args.profile.as_deref() {
        Some("low") => {
            opts.inline_threshold = 64 * 1024;
            opts.mem_budget = opts.mem_budget.min(64 * 1024 * 1024);
        }
        Some("max") => {
            opts.inline_threshold = 8 * 1024 * 1024;
        }
        _ => {}
    }
    let _ = args.threads;
    let plan = retention_plan(&parsers);
    let archive = match SysdiagnoseArchive::open_path_with_plan(&path, opts, &plan) {
        Ok(a) => Arc::new(a),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let mut popts = ParseOptions {
        ioservice_full_tree: args.ioservice_full_tree,
        logarchive_inventory_only: args.logarchive_inventory_only,
        ..ParseOptions::default()
    };
    if let Some(n) = args.logarchive_decode_max_lines {
        popts.logarchive_decode_max_lines = clamp_logarchive_decode_max_lines(n);
    }
    if let Some(n) = args.logarchive_memory_threshold {
        popts.logarchive_memory_threshold = n;
    }
    let jobs: Vec<_> = parsers
        .into_iter()
        .map(|t| (t, parser_for_with_options(t, popts.clone())))
        .collect();
    let results = run_parsers_concurrently(Arc::clone(&archive), jobs);
    let mut doc = Map::new();
    for (kind, res, dur) in results {
        let id = kind.as_str().to_string();
        let ms = dur.as_millis() as u64;
        match res {
            Ok(val) => {
                if let Some(dir) = &args.jsonl_out {
                    let _ = fs::create_dir_all(dir);
                    if let Some(events) = val.get("events") {
                        let path = dir.join(format!("{id}.jsonl"));
                        if let Ok(mut f) = fs::File::create(path) {
                            if let Some(arr) = events.as_array() {
                                for ev in arr {
                                    let _ = writeln!(f, "{}", ev);
                                }
                            }
                        }
                    }
                }
                doc.insert(id, json!({"ok": true, "duration_ms": ms, "data": val}));
            }
            Err(err) => {
                doc.insert(id, json!({"ok": false, "duration_ms": ms, "error": err.to_string()}));
            }
        }
    }
    if args.stats {
        let stats = archive.stats();
        eprintln!("{stats:?}");
    }
    if args.show_parser_results {
        println!("{}", serde_json::to_string(&Value::Object(doc)).unwrap_or_else(|_| "{}".into()));
    } else {
        for (k, v) in &doc {
            let ms = v.get("duration_ms").and_then(|n| n.as_u64()).unwrap_or(0);
            let ok = v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false);
            println!("{k}\t{ok}\t{ms}ms");
        }
    }
}

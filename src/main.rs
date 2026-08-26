#![allow(dead_code, unused_imports)]
mod catalog;
mod engine;
mod model;
mod notes;
mod parse;
mod ui;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "warden", version, about = "Recon-to-exploitation orchestration framework")]
struct Cli {
    /// Engagement name (also the workspace directory name if --workspace is omitted).
    #[arg(short, long, default_value = "engagement")]
    name: String,
    /// Workspace directory (created if absent). Defaults to ./<name>-warden.
    #[arg(short, long)]
    workspace: Option<PathBuf>,
    /// Seed targets: IPs/CIDRs, or a path to a hosts file.
    #[arg(short, long)]
    targets: Vec<String>,
    /// Import an existing nmap -oX XML file at startup.
    #[arg(long)]
    import: Vec<PathBuf>,
    /// Max commands to run in parallel.
    #[arg(short = 'j', long, default_value_t = 8)]
    parallel: usize,
    /// Non-interactive: print the enumeration plan and exit.
    #[arg(long)]
    plan: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let ws_path = cli
        .workspace
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("{}-warden", cli.name)));

    let (ws, mut eng) = engine::Workspace::open_or_create(&ws_path, &cli.name)?;

    // Seed targets.
    for t in &cli.targets {
        ui::app::seed_target(&mut eng, t)?;
    }
    // Import nmap XML.
    for path in &cli.import {
        let xml = std::fs::read_to_string(path)?;
        let n = parse::intel::ingest_nmap(&mut eng, &xml)?;
        eng.note(model::Phase::PortScan, format!("imported {n} hosts from {}", path.display()));
    }
    eng.recompute_segments();
    ws.save(&eng)?;

    if cli.plan {
        println!("{}", notes::render(&eng));
        return Ok(());
    }

    ui::app::run(ws, eng, cli.parallel).await
}

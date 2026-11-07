//! Print one isolated-workspace measurement.
//!
//! The numbers are this process, this build, and the scratch directory.
//! They are not a comparison with any other run unless that run's report is
//! in front of you. Physical energy is unknown.

use std::env;
use std::path::Path;
use std::process::ExitCode;

use rcevc_proj_git::isolate::IsolateReport;
use rcevc_proj_git::measure_isolated;

fn main() -> ExitCode {
    let root = env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/rcevc-isolate".to_string());
    let report = match measure_isolated(Path::new(&root)) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("isolate_bench failed: {err}");
            return ExitCode::from(1);
        }
    };
    print_report(&root, &report);
    if report.poison_rejected
        && report.corrupt_blob_rejected
        && report.isolation_held
        && report.stale_cas_rejected
        && report.replay_still_tip
    {
        ExitCode::from(0)
    } else {
        eprintln!("isolate_bench adversaries did not all hold");
        ExitCode::from(2)
    }
}

fn print_report(root: &str, report: &IsolateReport) {
    println!("rcevc isolate measurement (this run only)");
    println!("scratch: {root}");
    println!("arch: {}", report.arch);
    println!("os: {}", report.os);
    println!("debug_assertions: {}", report.debug_assertions);
    println!("workload: {}", report.workload);
    println!("cache_boundary: {}", report.cache_boundary);
    println!("dependency_boundary: {}", report.dependency_boundary);
    println!("target_boundary: {}", report.target_boundary);
    println!("physical_energy: {:?}", report.physical_energy);
    println!("blob_count: {}", report.blob_count);
    println!("cold_wall_ns: {}", report.cold_wall_ns);
    println!("warm_wall_ns: {}", report.warm_wall_ns);
    println!("poison_rejected: {}", report.poison_rejected);
    println!("corrupt_blob_rejected: {}", report.corrupt_blob_rejected);
    println!("isolation_held: {}", report.isolation_held);
    println!("stale_cas_rejected: {}", report.stale_cas_rejected);
    println!("replay_still_tip: {}", report.replay_still_tip);
}

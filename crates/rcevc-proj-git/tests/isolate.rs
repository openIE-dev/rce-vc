//! The measurement harness returns samples from this call and keeps energy unknown.

use rcevc_core::assure::PhysicalEnergy;
use rcevc_proj_git::isolate::IsolateReport;
use rcevc_proj_git::measure_isolated;

#[test]
fn isolate_report_measures_this_process_and_does_not_invent_joules() {
    let root = std::env::temp_dir().join(format!("rcevc-isolate-test-{}", std::process::id()));
    let report = measure_isolated(&root).expect("harness");
    assert_eq!(report.arch, std::env::consts::ARCH);
    assert_eq!(report.os, std::env::consts::OS);
    assert_eq!(report.debug_assertions, cfg!(debug_assertions));
    assert_eq!(report.blob_count, 32);
    assert!(report.poison_rejected);
    assert!(report.corrupt_blob_rejected);
    assert!(report.isolation_held);
    assert!(report.stale_cas_rejected);
    assert!(report.replay_still_tip);
    assert_eq!(report.physical_energy, PhysicalEnergy::unknown());
    assert!(!format!("{report:?}").contains("joules"));
    let _typed: IsolateReport = report;
    let _ = std::fs::remove_dir_all(&root);
}

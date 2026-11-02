//! OS isolation backend selection and reporting.

mod common;

use agent_sandbox::isolation::{self, Prepared};
use common::fixture;

#[test]
fn off_mode_uses_no_backend() {
    let fx = fixture("[isolation]\nmode = \"off\"\n");
    let (prepared, report) = isolation::prepare(fx.sandbox.policy(), "/bin/sh".as_ref()).unwrap();
    assert!(matches!(prepared, Prepared::None));
    assert_eq!(report.backend, "none");
    assert!(report.filesystem.starts_with("engine"));
    assert!(report.notes.iter().any(|n| n.contains("off")));
    let out = fx.run(&["echo", "still runs"]);
    assert_eq!(out.enforcement.unwrap().backend, "none");
}

#[test]
fn auto_mode_reports_what_is_enforced() {
    let fx = fixture("");
    let (prepared, report) = isolation::prepare(fx.sandbox.policy(), "/bin/sh".as_ref()).unwrap();
    if cfg!(target_os = "macos") && isolation::macos::available() {
        assert_eq!(report.backend, "sandbox-exec");
        assert!(report.network.starts_with("os"));
        let Prepared::Seatbelt { profile } = prepared else {
            panic!("expected a Seatbelt profile");
        };
        assert!(profile.contains("(deny network*)"));
        assert!(profile.contains("(deny file-write*)"));
        assert!(profile.contains(&format!("(subpath \"{}\")", fx.scratch().display())));
        assert!(profile.contains(&format!(
            "(deny file-read* file-write* (subpath \"{}\"))",
            fx.home.join(".ssh").display()
        )));
    } else if cfg!(target_os = "linux") && report.backend != "none" {
        assert!(report.backend.starts_with("landlock-abi-"));
        assert!(report.filesystem.starts_with("os"));
    } else {
        assert!(report.notes.iter().any(|n| n.contains("unavailable")));
    }
}

#[test]
fn required_mode_matches_availability() {
    let fx = fixture("[isolation]\nmode = \"required\"\n");
    let result = isolation::prepare(fx.sandbox.policy(), "/bin/sh".as_ref());
    let auto = fixture("");
    let available = common::os_isolation_available(&auto);
    assert_eq!(result.is_ok(), available);
    if !available {
        let err = fx
            .sandbox
            .run(&common::argv_of(&["echo"]), &Default::default())
            .unwrap_err();
        assert!(err.to_string().contains("unavailable"));
    }
}

#[test]
fn network_allow_profile_has_no_network_rule() {
    let fx = fixture("[network]\nmode = \"allow\"\n");
    let profile = isolation::macos::profile(fx.sandbox.policy());
    assert!(!profile.contains("network"));
    let (_, report) = isolation::prepare(fx.sandbox.policy(), "/bin/sh".as_ref()).unwrap();
    assert_eq!(report.network, "allowed");
}

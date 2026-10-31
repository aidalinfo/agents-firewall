//! Bridge to `afw-dlp`: builds the scanner from the policy's data classes and converts
//! findings into event findings.

use std::sync::Arc;

use afw_core::policy::{DataCategory, DataClass, Detector};
use afw_dlp::{ClassSpec, DetectorSpec, ScannerOptions};
pub use afw_dlp::{Finding as DlpFinding, Scanner, decode_content, mask_bytes};

fn category(c: DataCategory) -> afw_dlp::DataCategory {
    match c {
        DataCategory::Secret => afw_dlp::DataCategory::Secret,
        DataCategory::Infra => afw_dlp::DataCategory::Infra,
        DataCategory::Commercial => afw_dlp::DataCategory::Commercial,
        DataCategory::Personal => afw_dlp::DataCategory::Personal,
        DataCategory::Custom => afw_dlp::DataCategory::Custom,
    }
}

pub fn core_category(c: afw_dlp::DataCategory) -> DataCategory {
    match c {
        afw_dlp::DataCategory::Secret => DataCategory::Secret,
        afw_dlp::DataCategory::Infra => DataCategory::Infra,
        afw_dlp::DataCategory::Commercial => DataCategory::Commercial,
        afw_dlp::DataCategory::Personal => DataCategory::Personal,
        afw_dlp::DataCategory::Custom => DataCategory::Custom,
    }
}

/// Scanner for a policy's data classes (class id = the class UUID as text). An unknown
/// built-in detector or an invalid pattern is an error: the policy is then rejected.
pub fn build_scanner(classes: &[DataClass]) -> Result<Arc<Scanner>, String> {
    let specs: Vec<ClassSpec> = classes
        .iter()
        .map(|c| ClassSpec {
            id: c.id.to_string(),
            name: c.name.clone(),
            category: category(c.category),
            detectors: c
                .detectors
                .iter()
                .map(|d| match d {
                    Detector::Builtin { id } => DetectorSpec::Builtin { id: id.clone() },
                    Detector::Regex { name, pattern } => DetectorSpec::Regex {
                        name: name.clone(),
                        pattern: pattern.clone(),
                    },
                })
                .collect(),
        })
        .collect();
    Scanner::new(&specs, ScannerOptions::default())
        .map(Arc::new)
        .map_err(|e| e.to_string())
}

pub fn to_event(f: &DlpFinding) -> afw_core::events::Finding {
    afw_core::events::Finding {
        class: f.class_name.clone(),
        category: core_category(f.category),
        kind: f.kind.clone(),
        fingerprint: f.fingerprint.clone(),
        location: f.location.clone(),
    }
}

pub fn is_secret(f: &DlpFinding) -> bool {
    f.category == afw_dlp::DataCategory::Secret
}

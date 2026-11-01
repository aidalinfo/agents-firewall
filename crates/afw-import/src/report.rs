//! Import report: what was converted, what needs review, what was not converted.

use afw_core::policy::ZoneMode;
use serde::{Deserialize, Serialize};

/// One converted element: where it comes from in the source file and what it became.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct MappedItem {
    /// Path in the source file (`destinations.allow[3]`, `matrix.secrets.trusted`…).
    pub source: String,
    /// Resulting agents-firewall element, in words.
    pub target: String,
}

/// A warning or an element that was not converted, with its path in the source file.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ReportItem {
    pub path: String,
    pub message: String,
}

/// Import report (shown by `afw import egress-guard`, French, for operators).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct ImportReport {
    pub zone: String,
    pub zone_mode: ZoneMode,
    pub mapped: Vec<MappedItem>,
    /// Approximations and elements to review. Unknown fields are always reported here.
    pub warnings: Vec<ReportItem>,
    /// Elements with no equivalent, or rejected (invalid pattern, global wildcard…).
    pub unsupported: Vec<ReportItem>,
    /// `deny`/`gate` decisions of the source that the plan does not enforce (unknown class or
    /// tier, LLM exemption…). Non-empty ⇒ [`crate::ImportPlan::is_safe`] is false.
    #[serde(default)]
    pub blocking: Vec<ReportItem>,
}

impl ImportReport {
    pub(crate) fn new(zone: &str, zone_mode: ZoneMode) -> Self {
        Self {
            zone: zone.to_string(),
            zone_mode,
            mapped: Vec::new(),
            warnings: Vec::new(),
            unsupported: Vec::new(),
            blocking: Vec::new(),
        }
    }

    pub(crate) fn map(&mut self, source: impl Into<String>, target: impl Into<String>) {
        self.mapped.push(MappedItem {
            source: source.into(),
            target: target.into(),
        });
    }

    pub(crate) fn warn(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.warnings.push(ReportItem {
            path: path.into(),
            message: message.into(),
        });
    }

    pub(crate) fn unsupported(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.unsupported.push(ReportItem {
            path: path.into(),
            message: message.into(),
        });
    }

    pub(crate) fn block(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.blocking.push(ReportItem {
            path: path.into(),
            message: message.into(),
        });
    }

    /// Human-readable report (Markdown, French).
    pub fn to_markdown(&self) -> String {
        let mode = match self.zone_mode {
            ZoneMode::Observe => {
                "observe (observation : rien n'est bloqué, les refus sont journalisés)"
            }
            ZoneMode::Enforce => "enforce (application : les refus bloquent)",
        };
        let mut md = String::from("# Rapport d'import egress-guard\n\n");
        md.push_str(&format!(
            "- Zone : `{}`, mode {mode}\n- Converti : {} élément(s)\n- Avertissements : {}\n- Non converti : {}\n- Bloquant : {}\n\n",
            escape(&self.zone),
            self.mapped.len(),
            self.warnings.len(),
            self.unsupported.len(),
            self.blocking.len()
        ));
        if !self.blocking.is_empty() {
            md.push_str(
                "## Bloquant\n\nCes refus de la politique source ne sont **pas** appliqués par le plan : \
                 corrigez le fichier ou ajoutez les règles à la main avant de publier.\n\n",
            );
            for i in &self.blocking {
                md.push_str(&format!(
                    "- `{}` : {}\n",
                    escape(&i.path),
                    escape(&i.message)
                ));
            }
            md.push('\n');
        }
        md.push_str("## Converti\n\n");
        if self.mapped.is_empty() {
            md.push_str("_Rien._\n");
        } else {
            md.push_str("| Source | Résultat |\n|---|---|\n");
            for m in &self.mapped {
                md.push_str(&format!(
                    "| `{}` | {} |\n",
                    escape(&m.source),
                    escape(&m.target)
                ));
            }
        }
        for (title, items) in [
            ("Avertissements (à relire)", &self.warnings),
            ("Non converti", &self.unsupported),
        ] {
            md.push_str(&format!("\n## {title}\n\n"));
            if items.is_empty() {
                md.push_str("_Rien._\n");
            }
            for i in items {
                md.push_str(&format!(
                    "- `{}` : {}\n",
                    escape(&i.path),
                    escape(&i.message)
                ));
            }
        }
        md.push_str(
            "\n## Étapes suivantes\n\n\
             1. Relire la session ouverte par l'import, puis la publier et l'installer.\n\
             2. Laisser la zone en observation quelques jours (EF-71), l'egress-guard restant actif.\n\
             3. Autoriser les flux légitimes marqués `observed`, puis passer la zone en `enforce`.\n",
        );
        md
    }
}

/// Keeps table cells and inline code intact.
fn escape(s: &str) -> String {
    s.replace('|', "\\|").replace('`', "'").replace('\n', " ")
}

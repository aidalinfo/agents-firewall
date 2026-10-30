//! egress-guard « v2 egress-first » importer (ADR 0026).
//!
//! Mapping (conception §11, `docs/migration-egress-guard.md`):
//! - allowed hosts → domain/IP objects, one group per tier, one accept rule per tier (plus one
//!   per port set for entries with `ports`), in the zone layer;
//! - denied hosts → objects + one baseline deny rule scoped to the zone;
//! - `default: deny` → the implicit cleanup (agents-firewall always denies by default);
//! - data classes (regex) → data classes; patterns that match a presigned S3/GCS URL are dropped
//!   and the `secret` class gets the built-in `afw-dlp` secret detectors (EF-72);
//! - matrix → zone content rules: `deny` and `gate` → deny rules, then `log` → accept rules
//!   with the data class (dedicated rule, so the hit is attributed), `allow` → no rule;
//! - action classes → [`IntentPolicy`] for the Hermes plugin (ADR 0015).

mod format;

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use afw_core::api::{ActionClass, IntentDecision, IntentPolicy};
use afw_core::policy::{
    Action, DataCategory, DataClass, DestCategory, Detector, L4Proto, Layer, NetObject,
    NetObjectSpec, PolicyDocument, PortRange, Rule, Service, Track, Zone, ZoneMode,
};
use ipnet::IpNet;
use serde::de::DeserializeOwned;
use serde_yaml::{Mapping, Value};
use uuid::Uuid;

use self::format::{
    ActionClassSpec, DataClassSpec, Destinations, Extra, PatternEntry, Root, TierSpec,
};
use crate::ImportError;
use crate::plan::{ImportPlan, ZoneChange};
use crate::report::ImportReport;

/// Import options.
#[derive(Clone, Debug)]
pub struct ImportOptions<'a> {
    /// Zone receiving the imported rules (created if it does not exist).
    pub zone_name: String,
    /// Mode of the zone; `Observe` by default (EF-71).
    pub zone_mode: ZoneMode,
    /// Current policy: objects (same domain/address), services, data classes (same name),
    /// the zone (same name) and rules (same name in the same layer) are reused.
    pub existing: Option<&'a PolicyDocument>,
    /// Allows changing the mode of an existing zone (for example enforce → observe). Without
    /// it, an existing zone keeps its mode: an import never downgrades a zone (review I1).
    pub downgrade: bool,
}

impl<'a> ImportOptions<'a> {
    pub fn new(zone_name: impl Into<String>) -> Self {
        Self {
            zone_name: zone_name.into(),
            zone_mode: ZoneMode::Observe,
            existing: None,
            downgrade: false,
        }
    }
}

/// Matrix tier keys meaning « every listed destination ».
const ANY_TIERS: [&str; 2] = ["any", "*"];
/// Matrix tier keys meaning « destinations not listed » (already denied by default).
const UNLISTED_TIERS: [&str; 4] = ["unlisted", "unknown", "other", "others"];
/// Largest accepted file (review I4).
pub const MAX_YAML_BYTES: usize = 1024 * 1024;
/// Deepest `[`/`{` nesting accepted, counted before parsing.
pub const MAX_FLOW_DEPTH: usize = 64;
/// Patterns per data class or action class.
pub const MAX_PATTERNS: usize = 200;
/// Characters per pattern.
pub const MAX_PATTERN_LEN: usize = 512;

/// Tier of allowed hosts declared without one.
const DEFAULT_TIER: &str = "default";
/// Standard action classes of the plugin's built-in policy (ADR 0015).
const STANDARD_ACTIONS: [&str; 4] = [
    "irreversible",
    "access",
    "infra_destructive",
    "paid_generation",
];

/// Imports an egress-guard YAML policy. Syntax or shape errors fail; everything else is
/// converted or reported.
pub fn import(yaml: &str, opts: &ImportOptions<'_>) -> Result<ImportPlan, ImportError> {
    let zone_name = opts.zone_name.trim();
    if zone_name.is_empty() {
        return Err(ImportError::Options("zone name must not be empty".into()));
    }
    if yaml.len() > MAX_YAML_BYTES {
        return Err(ImportError::Limit(format!(
            "file larger than {MAX_YAML_BYTES} bytes ({} bytes)",
            yaml.len()
        )));
    }
    let depth = flow_depth(yaml);
    if depth > MAX_FLOW_DEPTH {
        return Err(ImportError::Limit(format!(
            "nesting deeper than {MAX_FLOW_DEPTH} levels of `[`/`{{` ({depth})"
        )));
    }
    let value: Value = serde_yaml::from_str(yaml).map_err(|e| ImportError::Yaml(e.to_string()))?;
    let root: Root = match value {
        Value::Null => Root::default(),
        Value::Mapping(_) => serde_yaml::from_str(yaml).map_err(|e| ImportError::Invalid {
            path: "$".into(),
            message: e.to_string(),
        })?,
        _ => {
            return Err(ImportError::Invalid {
                path: "$".into(),
                message: "the document must be a mapping (egress-guard v2 policy)".into(),
            });
        }
    };
    let empty = PolicyDocument::default();
    let cx = Ctx {
        existing: opts.existing.unwrap_or(&empty),
        zone_name: zone_name.to_string(),
        report: ImportReport::new(zone_name, opts.zone_mode),
        objects: Vec::new(),
        updated: BTreeSet::new(),
        services: Vec::new(),
        data_classes: Vec::new(),
        class_ids: BTreeMap::new(),
        rules: Vec::new(),
    };
    cx.run(root, opts.zone_mode, opts.downgrade)
}

/// Maximum nesting of `[`/`{` (simple count, quotes not interpreted: conservative).
fn flow_depth(yaml: &str) -> usize {
    let (mut depth, mut max) = (0usize, 0usize);
    for b in yaml.bytes() {
        match b {
            b'[' | b'{' => {
                depth += 1;
                max = max.max(depth);
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max
}

/// Destination handling of one tier.
#[derive(Default)]
struct Tier {
    description: Option<String>,
    category: Option<DestCategory>,
    /// Every host object of the tier (content rules).
    members: Vec<Uuid>,
    /// Host objects without port restriction.
    plain: Vec<Uuid>,
    /// Host objects restricted to ports, by port set.
    ported: BTreeMap<Vec<u16>, Vec<Uuid>>,
    group: Option<Uuid>,
}

/// Accept destination set: objects and an optional port restriction.
struct AcceptSpec {
    label: String,
    destinations: Vec<Uuid>,
    ports: Option<Vec<u16>>,
}

struct Ctx<'a> {
    existing: &'a PolicyDocument,
    zone_name: String,
    report: ImportReport,
    objects: Vec<NetObject>,
    updated: BTreeSet<Uuid>,
    services: Vec<Service>,
    data_classes: Vec<DataClass>,
    /// egress-guard class key → data class id (new or reused).
    class_ids: BTreeMap<String, Uuid>,
    rules: Vec<Rule>,
}

impl Ctx<'_> {
    fn run(
        mut self,
        root: Root,
        zone_mode: ZoneMode,
        downgrade: bool,
    ) -> Result<ImportPlan, ImportError> {
        self.extra("", &root.extra);
        match &root.version {
            None => self
                .report
                .warn("version", "version absente : format v2 supposé"),
            Some(Value::Number(n)) if n.as_u64() == Some(2) => {
                self.report.map("version", "format egress-guard v2 reconnu")
            }
            Some(v) => self.report.warn(
                "version",
                format!(
                    "version {} inattendue : importée comme un format v2",
                    show(v)
                ),
            ),
        }
        for (key, v) in [
            ("profile", &root.profile),
            ("name", &root.name),
            ("description", &root.description),
        ] {
            if v.is_some() {
                self.report
                    .map(key, "métadonnée, reprise dans le commentaire de la zone");
            }
        }
        if root.senders.is_some() {
            self.report.unsupported(
                "senders",
                "expéditeurs autorisés : pas d'équivalent réseau (la passerelle ne contrôle pas l'expéditeur d'un mail) ; \
                 à reprendre dans la configuration de l'outil d'envoi ou par une classe d'actions",
            );
        }
        if root.logging.is_some() {
            self.report.map(
                "logging",
                "remplacé par le journal de la console (flux, DNS, HTTP, appels d'outil)",
            );
        }

        let zone = self.zone(&root, zone_mode, downgrade);
        self.report.zone_mode = zone.0.mode;
        let zone_id = zone.0.id;
        let mut tiers = self.tiers(root.tiers.as_ref())?;
        self.destinations(root.destinations.unwrap_or_default(), &mut tiers, zone_id)?;
        self.classes(root.data_classes.as_ref())?;
        self.matrix(root.matrix.as_ref(), &tiers, zone_id)?;
        self.tier_accepts(&tiers, zone_id);
        let intent_policy = self.actions(root.action_classes.as_ref())?;
        self.assign_positions();

        Ok(ImportPlan {
            objects: self.objects,
            services: self.services,
            data_classes: self.data_classes,
            zone: zone.0,
            zone_change: zone.1,
            rules: self.rules,
            intent_policy,
            report: self.report,
            updated: self.updated,
        })
    }

    fn extra(&mut self, base: &str, extra: &Extra) {
        for key in extra.keys() {
            self.report.warn(
                join(base, key),
                format!("champ inconnu « {key} » : non converti, à vérifier"),
            );
        }
    }

    // ---- zone ---------------------------------------------------------------------------------

    fn zone(&mut self, root: &Root, mode: ZoneMode, downgrade: bool) -> (Zone, ZoneChange) {
        let label = root
            .profile
            .as_ref()
            .or(root.name.as_ref())
            .map(|v| format!(" ({})", show(v)))
            .unwrap_or_default();
        let description = root
            .description
            .as_ref()
            .map(|v| format!(" : {}", show(v)))
            .unwrap_or_default();
        if let Some(z) = self
            .existing
            .zones
            .iter()
            .find(|z| z.name.eq_ignore_ascii_case(&self.zone_name))
        {
            let mut zone = z.clone();
            if zone.mode == mode {
                self.report
                    .map("zone", format!("zone existante « {} » réutilisée", z.name));
                return (zone, ZoneChange::Unchanged);
            }
            if !downgrade {
                self.report.warn(
                    "zone",
                    format!(
                        "zone existante « {} » : mode {} conservé (mode {} demandé) ; \
                         l'import ne change jamais le mode d'une zone existante sans `downgrade`",
                        z.name,
                        mode_str(zone.mode),
                        mode_str(mode)
                    ),
                );
                return (zone, ZoneChange::Unchanged);
            }
            self.report.warn(
                "zone",
                format!(
                    "zone existante « {} » : mode {} → {} (downgrade explicite)",
                    z.name,
                    mode_str(zone.mode),
                    mode_str(mode)
                ),
            );
            zone.mode = mode;
            return (zone, ZoneChange::Update);
        }
        self.report.map(
            "zone",
            format!(
                "zone « {} » créée en mode {}",
                self.zone_name,
                mode_str(mode)
            ),
        );
        (
            Zone {
                id: Uuid::new_v4(),
                name: self.zone_name.clone(),
                comment: format!("Importée d'une politique egress-guard{label}{description}"),
                mode,
                delegated_to_mcp: false,
            },
            ZoneChange::Create,
        )
    }

    // ---- tiers and destinations ---------------------------------------------------------------

    fn tiers(&mut self, map: Option<&Mapping>) -> Result<BTreeMap<String, Tier>, ImportError> {
        let mut tiers = BTreeMap::new();
        for (raw_key, v) in entries(map, "tiers")? {
            let path = format!("tiers.{raw_key}");
            let key = raw_key.trim().to_ascii_lowercase();
            if tiers.contains_key(&key) {
                self.report.warn(
                    &path,
                    format!("tier « {raw_key} » déclaré deux fois (casse ignorée) : seconde déclaration ignorée"),
                );
                continue;
            }
            let spec: TierSpec = from_value(v, &path)?;
            self.extra(&path, &spec.extra);
            let category = match spec
                .category
                .as_deref()
                .map(str::to_ascii_lowercase)
                .as_deref()
            {
                None | Some("") | Some("none") | Some("external") | Some("public") => None,
                Some("internal") => Some(DestCategory::Internal),
                Some("llm_provider") | Some("llm") => Some(DestCategory::LlmProvider),
                Some(other) => {
                    self.report.warn(
                        format!("{path}.category"),
                        format!("catégorie « {other} » inconnue : ignorée (internal ou llm_provider attendu)"),
                    );
                    None
                }
            };
            tiers.insert(
                key,
                Tier {
                    category,
                    description: spec.description,
                    ..Tier::default()
                },
            );
        }
        Ok(tiers)
    }

    fn destinations(
        &mut self,
        d: Destinations,
        tiers: &mut BTreeMap<String, Tier>,
        zone_id: Uuid,
    ) -> Result<(), ImportError> {
        self.extra("destinations", &d.extra);
        match d.default.as_deref().map(str::to_ascii_lowercase).as_deref() {
            None => self.report.map(
                "destinations.default",
                "refus par défaut (règle de nettoyage implicite)",
            ),
            Some("deny") | Some("block") => self.report.map(
                "destinations.default",
                "refus par défaut (règle de nettoyage implicite)",
            ),
            Some(other) => self.report.warn(
                "destinations.default",
                format!(
                    "« {other} » non repris : agents-firewall refuse toujours par défaut ; \
                     la zone en observation montre ce qui serait refusé"
                ),
            ),
        }

        // Denied hosts first: a host both allowed and denied stays denied.
        let mut denied: Vec<Uuid> = Vec::new();
        let mut denied_specs: Vec<NetObjectSpec> = Vec::new();
        for (i, entry) in d.deny.iter().enumerate() {
            let path = format!("destinations.deny[{i}]");
            let (host, tier, ports, comment, extra) = entry.parts();
            if let Some(extra) = extra {
                self.extra(&path, extra);
            }
            if tier.is_some() || !ports.is_empty() {
                self.report.warn(
                    &path,
                    "tier et ports ignorés pour un hôte refusé : refusé sur tous les ports",
                );
            }
            let Some(spec) = self.host_spec(host, &path, false) else {
                continue;
            };
            // A denied wildcard also covers its apex (review M1).
            let mut specs = vec![spec.clone()];
            if let NetObjectSpec::Domain { pattern } = &spec
                && let Some(apex) = pattern.strip_prefix("*.")
            {
                specs.push(NetObjectSpec::Domain {
                    pattern: apex.to_string(),
                });
            }
            for spec in specs {
                let id = self.leaf(&spec, None, comment, &path);
                if !denied.contains(&id) {
                    denied.push(id);
                    denied_specs.push(spec);
                }
            }
        }

        let mut seen: Vec<(NetObjectSpec, String)> = Vec::new();
        for (i, entry) in d.allow.iter().enumerate() {
            let path = format!("destinations.allow[{i}]");
            let (host, tier, ports, comment, extra) = entry.parts();
            if let Some(extra) = extra {
                self.extra(&path, extra);
            }
            let tier_key = match tier {
                Some(t) if !t.trim().is_empty() => t.trim().to_ascii_lowercase(),
                _ => {
                    self.report.warn(
                        &path,
                        format!("hôte sans tier : rangé dans le tier « {DEFAULT_TIER} »"),
                    );
                    DEFAULT_TIER.to_string()
                }
            };
            if !tiers.contains_key(&tier_key) {
                if tier.is_some() && !tiers.is_empty() {
                    self.report.warn(
                        format!("{path}.tier"),
                        format!(
                            "tier « {tier_key} » non déclaré dans `tiers` : créé sans catégorie"
                        ),
                    );
                }
                tiers.insert(tier_key.clone(), Tier::default());
            }
            let ports = if ports.is_empty() {
                None
            } else {
                let mut p = ports.to_vec();
                p.sort_unstable();
                p.dedup();
                if p.contains(&0) {
                    self.report.warn(format!("{path}.ports"), "port 0 ignoré");
                    p.retain(|x| *x != 0);
                }
                if p.is_empty() {
                    self.report.unsupported(
                        &path,
                        format!(
                            "« {host} » : liste de ports vide après nettoyage, hôte non ouvert"
                        ),
                    );
                    continue;
                }
                Some(p)
            };
            let Some(spec) = self.host_spec(host, &path, true) else {
                continue;
            };
            if denied_specs.iter().any(|d| same_leaf(d, &spec)) {
                self.report.warn(
                    &path,
                    format!("« {host} » est aussi dans `destinations.deny` : il reste refusé"),
                );
                continue;
            }
            if let Some((_, first)) = seen.iter().find(|(s, _)| same_leaf(s, &spec)) {
                self.report.warn(
                    &path,
                    format!("« {host} » déjà listé ({first}) : entrée ignorée"),
                );
                continue;
            }
            seen.push((spec.clone(), path.clone()));
            let category = tiers[&tier_key].category;
            let id = self.leaf(&spec, category, comment, &path);
            let t = tiers.get_mut(&tier_key).expect("tier inserted above");
            t.members.push(id);
            match ports {
                None => t.plain.push(id),
                Some(p) => t.ported.entry(p).or_default().push(id),
            }
        }

        // One group per tier.
        let names: Vec<String> = tiers.keys().cloned().collect();
        for name in names {
            let t = &tiers[&name];
            if t.members.is_empty() {
                continue;
            }
            let group_name = format!("egress-guard/{}/{name}", self.zone_name);
            let (members, category) = (t.members.clone(), t.category);
            let comment = t.description.clone();
            let id = self.group(
                &group_name,
                members,
                category,
                comment,
                &format!("tiers.{name}"),
            );
            tiers.get_mut(&name).expect("tier").group = Some(id);
        }

        // Denied hosts: one group, one baseline deny rule scoped to the zone.
        if !denied.is_empty() {
            let group_name = format!("egress-guard/{}/refusés", self.zone_name);
            let gid = self.group(
                &group_name,
                denied,
                None,
                Some("Destinations refusées par egress-guard".into()),
                "destinations.deny",
            );
            self.rule(
                Layer::Baseline,
                format!("egress-guard {} : destinations refusées", self.zone_name),
                zone_id,
                vec![gid],
                vec![],
                vec![],
                Action::Deny,
                "Liste de refus de l'egress-guard. Limitée à la zone importée : à élargir à toutes \
                 les zones (source vide) si elle vaut pour toute la flotte.",
                "destinations.deny",
            );
        }
        Ok(())
    }

    /// Parses an egress-guard host into an object spec; `None` (reported) when not convertible.
    fn host_spec(&mut self, raw: &str, path: &str, allow: bool) -> Option<NetObjectSpec> {
        let h = raw.trim();
        if let Ok(ip) = h.parse::<IpAddr>() {
            return Some(NetObjectSpec::Host { ip });
        }
        if let Ok(net) = h.parse::<IpNet>() {
            let prefix = net.prefix_len();
            if prefix == 0 {
                self.report.unsupported(
                    path,
                    format!(
                        "réseau « {raw} » (/0) non converti : il couvrirait toutes les adresses"
                    ),
                );
                return None;
            }
            let broad = match net {
                IpNet::V4(_) => prefix < 8,
                IpNet::V6(_) => prefix < 32,
            };
            if allow && broad {
                self.report.unsupported(
                    path,
                    format!("réseau « {raw} » trop large pour une autorisation (plus large que /8 en IPv4 ou /32 en IPv6) : non converti"),
                );
                self.report.warn(
                    path,
                    format!("ATTENTION : l'egress-guard autorisait « {raw} », une part très large d'Internet ; \
                             autorisation non reprise, à remplacer par des destinations précises"),
                );
                return None;
            }
            return Some(NetObjectSpec::Network { cidr: net.trunc() });
        }
        let lower = h.strip_suffix('.').unwrap_or(h).to_ascii_lowercase();
        if lower.is_empty() || lower == "*" || lower == "*." {
            self.report.unsupported(
                path,
                format!("joker global « {raw} » non converti : il autoriserait toute destination"),
            );
            return None;
        }
        if !lower.is_ascii() {
            self.report.unsupported(
                path,
                format!("« {raw} » : nom non ASCII, à écrire sous forme punycode (xn--…)"),
            );
            return None;
        }
        let (wildcard, name) = match lower.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, lower.as_str()),
        };
        if !valid_name(name) {
            self.report.unsupported(
                path,
                format!(
                    "« {raw} » : hôte invalide (seuls un nom exact, un joker « *.domaine » en tête, \
                     une adresse IP ou un réseau CIDR sont convertis)"
                ),
            );
            return None;
        }
        if wildcard && allow {
            self.report.warn(
                path,
                format!(
                    "joker « {lower} » : couvre les sous-domaines de {name}, pas {name} lui-même ; \
                     ajoutez-le explicitement s'il est concerné"
                ),
            );
        } else if wildcard {
            self.report.map(
                path,
                format!("refus de « {lower} » étendu au domaine {name} lui-même"),
            );
        }
        Some(NetObjectSpec::Domain { pattern: lower })
    }

    /// Reuses an existing or already planned leaf object with the same spec, or plans a new one.
    fn leaf(
        &mut self,
        spec: &NetObjectSpec,
        category: Option<DestCategory>,
        comment: Option<&str>,
        path: &str,
    ) -> Uuid {
        let display = spec_name(spec);
        if let Some(o) = self
            .existing
            .objects
            .iter()
            .find(|o| same_leaf(&o.spec, spec))
        {
            self.report
                .map(path, format!("objet existant « {} » réutilisé", o.name));
            return o.id;
        }
        if let Some(o) = self.objects.iter().find(|o| same_leaf(&o.spec, spec)) {
            return o.id;
        }
        let id = Uuid::new_v4();
        self.objects.push(NetObject {
            id,
            name: display.clone(),
            comment: comment.unwrap_or("Importé d'egress-guard").to_string(),
            category,
            spec: spec.clone(),
        });
        self.report.map(path, format!("objet « {display} » créé"));
        id
    }

    /// Plans a group, or updates an existing group of the same name (union of members).
    fn group(
        &mut self,
        name: &str,
        members: Vec<Uuid>,
        category: Option<DestCategory>,
        comment: Option<String>,
        path: &str,
    ) -> Uuid {
        if let Some(g) = self.existing.objects.iter().find(|o| o.name == name) {
            if let NetObjectSpec::Group { members: old } = &g.spec {
                let mut all = old.clone();
                for m in members {
                    if !all.contains(&m) {
                        all.push(m);
                    }
                }
                let category = g.category.or(category);
                if all.len() != old.len() || category != g.category {
                    let mut updated = g.clone();
                    updated.spec = NetObjectSpec::Group { members: all };
                    updated.category = category;
                    self.updated.insert(g.id);
                    self.objects.push(updated);
                    self.report
                        .map(path, format!("groupe existant « {name} » complété"));
                } else {
                    self.report
                        .map(path, format!("groupe existant « {name} » réutilisé"));
                }
                return g.id;
            }
            self.report.warn(
                path,
                format!(
                    "un objet « {name} » existe déjà et n'est pas un groupe : nouveau groupe créé"
                ),
            );
        }
        let id = Uuid::new_v4();
        self.objects.push(NetObject {
            id,
            name: name.to_string(),
            comment: comment
                .unwrap_or_else(|| "Tier de destinations importé d'egress-guard".into()),
            category,
            spec: NetObjectSpec::Group { members },
        });
        self.report.map(path, format!("groupe « {name} » créé"));
        id
    }

    fn service(&mut self, ports: &[u16]) -> Uuid {
        let ranges: Vec<PortRange> = ports
            .iter()
            .map(|p| PortRange { start: *p, end: *p })
            .collect();
        let same = |s: &Service| s.protocol == L4Proto::Tcp && s.app.is_none() && s.ports == ranges;
        if let Some(s) = self.existing.services.iter().find(|s| same(s)) {
            return s.id;
        }
        if let Some(s) = self.services.iter().find(|s| same(s)) {
            return s.id;
        }
        let label: Vec<String> = ports.iter().map(u16::to_string).collect();
        let id = Uuid::new_v4();
        self.services.push(Service {
            id,
            name: format!("tcp/{}", label.join(",")),
            comment: "Importé d'egress-guard".into(),
            protocol: L4Proto::Tcp,
            ports: ranges,
            app: None,
        });
        id
    }

    // ---- data classes -------------------------------------------------------------------------

    fn classes(&mut self, map: Option<&Mapping>) -> Result<(), ImportError> {
        for (key, v) in entries(map, "data_classes")? {
            let path = format!("data_classes.{key}");
            let spec: DataClassSpec = from_value(v, &path)?;
            self.extra(&path, &spec.extra);
            let name = spec.name.clone().unwrap_or_else(|| key.clone());
            let category = match spec.category.as_deref() {
                Some(c) => parse_category(c).unwrap_or_else(|| {
                    self.report.warn(
                        format!("{path}.category"),
                        format!("catégorie « {c} » inconnue : custom"),
                    );
                    DataCategory::Custom
                }),
                None => infer_category(&key),
            };
            if let Some(c) = self
                .existing
                .data_classes
                .iter()
                .find(|c| c.name.eq_ignore_ascii_case(&name))
            {
                self.report.map(
                    &path,
                    format!(
                        "classe de données existante « {} » réutilisée (motifs non modifiés)",
                        c.name
                    ),
                );
                self.class_ids.insert(key, c.id);
                continue;
            }

            if spec.patterns.len() > MAX_PATTERNS {
                return Err(ImportError::Limit(format!(
                    "{path}.patterns: more than {MAX_PATTERNS} patterns ({})",
                    spec.patterns.len()
                )));
            }
            // (path, unique name, regex) of the candidate patterns.
            let mut candidates: Vec<(String, String, String)> = Vec::new();
            for (i, p) in spec.patterns.iter().enumerate() {
                let ppath = format!("{path}.patterns[{i}]");
                let (pname, regex) = match p {
                    PatternEntry::Bare(r) => (format!("{key}_{}", i + 1), r.clone()),
                    PatternEntry::Full(f) => {
                        self.extra(&ppath, &f.extra);
                        (
                            f.name.clone().unwrap_or_else(|| format!("{key}_{}", i + 1)),
                            f.regex.clone(),
                        )
                    }
                };
                if regex.chars().count() > MAX_PATTERN_LEN {
                    self.report.unsupported(
                        &ppath,
                        format!(
                            "motif « {pname} » non converti : plus de {MAX_PATTERN_LEN} caractères"
                        ),
                    );
                    continue;
                }
                let mut unique = pname.clone();
                let mut n = 2;
                while candidates.iter().any(|(_, u, _)| *u == unique) {
                    unique = format!("{pname}_{n}");
                    n += 1;
                }
                candidates.push((ppath, unique, regex));
            }
            for (ppath, pname, reason) in check_patterns(&mut candidates) {
                match reason {
                    Some(reason) => self
                        .report
                        .unsupported(&ppath, format!("motif « {pname} » non converti : {reason}")),
                    None => self.report.warn(
                        &ppath,
                        format!(
                            "motif « {pname} » retiré : il détecte les URL S3/GCS présignées \
                             (faux positif quotidien, EF-72)"
                        ),
                    ),
                }
            }
            let mut detectors: Vec<Detector> = candidates
                .into_iter()
                .map(|(_, name, pattern)| Detector::Regex { name, pattern })
                .collect();
            if category == DataCategory::Secret {
                let builtin = afw_dlp::builtin_classes()
                    .into_iter()
                    .find(|c| c.id == "secrets")
                    .map(|c| c.detectors)
                    .unwrap_or_default();
                let n = builtin.len();
                let mut all: Vec<Detector> = builtin
                    .into_iter()
                    .filter_map(|d| match d {
                        afw_dlp::DetectorSpec::Builtin { id } => Some(Detector::Builtin { id }),
                        afw_dlp::DetectorSpec::Regex { .. } => None,
                    })
                    .collect();
                all.append(&mut detectors);
                detectors = all;
                self.report.warn(
                    &path,
                    format!(
                        "classe de secrets remplacée par les {n} détecteurs intégrés d'afw-dlp, qui \
                         excluent les signatures des URL présignées (X-Amz-Signature, EF-72) ; \
                         les motifs propres non concernés sont conservés"
                    ),
                );
            }
            if detectors.is_empty() {
                self.report.unsupported(
                    &path,
                    format!("classe « {name} » sans motif utilisable : non créée"),
                );
                continue;
            }
            let id = Uuid::new_v4();
            self.report.map(
                &path,
                format!(
                    "classe de données « {name} » ({}, {} détecteur(s))",
                    category_str(category),
                    detectors.len()
                ),
            );
            self.data_classes.push(DataClass {
                id,
                name,
                comment: spec
                    .description
                    .unwrap_or_else(|| "Importée d'egress-guard".into()),
                category,
                detectors,
            });
            self.class_ids.insert(key, id);
        }
        Ok(())
    }

    // ---- matrix -------------------------------------------------------------------------------

    fn matrix(
        &mut self,
        map: Option<&Mapping>,
        tiers: &BTreeMap<String, Tier>,
        zone_id: Uuid,
    ) -> Result<(), ImportError> {
        // (class key, egress decision) → destination groups; insertion order kept.
        let mut denies: Vec<(String, &'static str, Vec<String>)> = Vec::new();
        let mut logs: Vec<(String, Vec<String>)> = Vec::new();
        for (class_key, row) in entries(map, "matrix")? {
            let path = format!("matrix.{class_key}");
            let known_class = self.class_ids.contains_key(&class_key);
            if !known_class {
                self.report.unsupported(
                    &path,
                    format!("classe « {class_key} » inconnue ou non convertie : ligne ignorée"),
                );
            }
            let row = match row {
                Value::Mapping(m) => m,
                other => {
                    return Err(ImportError::Invalid {
                        path,
                        message: format!(
                            "expected a mapping tier → decision, got {}",
                            kind(&other)
                        ),
                    });
                }
            };
            for (tier_key, decision) in entries(Some(&row), &path)? {
                let cpath = format!("{path}.{tier_key}");
                let raw = match decision {
                    Value::String(s) => s.trim().to_ascii_lowercase(),
                    other => show(&other),
                };
                let decision = match raw.as_str() {
                    "allow" | "log" | "gate" | "deny" => raw.clone(),
                    "block" | "refuse" => "deny".into(),
                    "ask" | "confirm" | "approval" => "gate".into(),
                    _ => {
                        self.report.warn(
                            &cpath,
                            format!(
                                "décision « {raw} » inconnue : traitée comme deny (la plus stricte)"
                            ),
                        );
                        "deny".into()
                    }
                };
                let strict = decision == "deny" || decision == "gate";
                if !known_class {
                    if strict {
                        self.report.block(
                            &cpath,
                            format!("« {decision} » non appliqué : classe « {class_key} » inconnue ou non convertie"),
                        );
                    }
                    continue;
                }
                let tier_key = tier_key.trim().to_ascii_lowercase();
                let declared = tiers.contains_key(&tier_key);
                // Reserved names only when no tier of that name is declared (review C1).
                if !declared && UNLISTED_TIERS.contains(&tier_key.as_str()) {
                    if decision == "allow" || decision == "log" {
                        self.report.warn(
                            &cpath,
                            "destinations non listées : refusées par défaut dans agents-firewall (plus strict)",
                        );
                    } else {
                        self.report.map(&cpath, "couvert par le refus par défaut");
                    }
                    continue;
                }
                let any = !declared && ANY_TIERS.contains(&tier_key.as_str());
                if !any {
                    let Some(t) = tiers.get(&tier_key) else {
                        self.report.unsupported(
                            &cpath,
                            format!("tier « {tier_key} » inconnu : case ignorée"),
                        );
                        if strict {
                            self.report.block(
                                &cpath,
                                format!(
                                    "« {decision} » non appliqué : tier « {tier_key} » inconnu"
                                ),
                            );
                        }
                        continue;
                    };
                    if t.group.is_none() {
                        self.report.warn(
                            &cpath,
                            format!("tier « {tier_key} » sans destination autorisée : déjà refusé par défaut"),
                        );
                        continue;
                    }
                    if t.category == Some(DestCategory::LlmProvider) {
                        if strict {
                            self.report.warn(
                                &cpath,
                                format!(
                                    "tier « {tier_key} » = fournisseurs de LLM : exemptés du blocage par \
                                     classe de données (EF-25), « {decision} » non repris ; trafic journalisé en détail"
                                ),
                            );
                            self.report.block(
                                &cpath,
                                format!("« {decision} » non appliqué : fournisseurs de LLM exemptés (EF-25)"),
                            );
                        } else {
                            self.report
                                .map(&cpath, "fournisseur de LLM : journalisé en détail (EF-25)");
                        }
                        continue;
                    }
                }
                match decision.as_str() {
                    "allow" => self
                        .report
                        .map(&cpath, "autorisé par la règle d'acceptation du tier"),
                    "log" => push_cell(&mut logs, &class_key, &tier_key),
                    d => {
                        if d == "gate" {
                            self.report.warn(
                                &cpath,
                                "gate → deny à la passerelle (pas de file de validation en V1) ; \
                                 le « gate » métier reste porté par les classes d'actions du plugin",
                            );
                        }
                        let d: &'static str = if d == "gate" { "gate" } else { "deny" };
                        match denies
                            .iter_mut()
                            .find(|(c, dd, _)| *c == class_key && *dd == d)
                        {
                            Some((_, _, t)) => t.push(tier_key.clone()),
                            None => denies.push((class_key.clone(), d, vec![tier_key.clone()])),
                        }
                    }
                }
            }
        }

        // Deny rules first: a log (accept) rule must never shadow a deny on another class.
        for (class_key, decision, tiers_of) in denies {
            let class = self.class_ids[&class_key];
            let destinations: Vec<Uuid> = if tiers_of.iter().any(|t| is_any(t, tiers)) {
                vec![]
            } else {
                tiers_of.iter().filter_map(|t| tiers[t].group).collect()
            };
            let target = if destinations.is_empty() {
                "toute destination".to_string()
            } else {
                format!("tier {}", tiers_of.join(", "))
            };
            self.rule(
                Layer::Zone { zone_id },
                format!("{class_key} → {target} : {decision}"),
                zone_id,
                destinations,
                vec![],
                vec![class],
                Action::Deny,
                if decision == "gate" {
                    "Matrice egress-guard : « gate » appliqué en refus (pas de file de validation en V1)."
                } else {
                    "Matrice egress-guard : refus."
                },
                &format!("matrix.{class_key}"),
            );
        }
        for (class_key, tiers_of) in logs {
            let class = self.class_ids[&class_key];
            let only = if tiers_of.iter().any(|t| is_any(t, tiers)) {
                None
            } else {
                Some(tiers_of.as_slice())
            };
            for spec in accept_specs(tiers, only, false) {
                let services = match &spec.ports {
                    Some(p) => vec![self.service(p)],
                    None => vec![],
                };
                self.rule(
                    Layer::Zone { zone_id },
                    format!("{class_key} → {} : log", spec.label),
                    zone_id,
                    spec.destinations,
                    services,
                    vec![class],
                    Action::Accept,
                    "Matrice egress-guard : autorisé et journalisé en détail (règle dédiée pour \
                     identifier les envois de cette classe).",
                    &format!("matrix.{class_key}"),
                );
            }
        }
        Ok(())
    }

    /// One accept rule per tier (plain hosts), and one per port set.
    fn tier_accepts(&mut self, tiers: &BTreeMap<String, Tier>, zone_id: Uuid) {
        for spec in accept_specs(tiers, None, true) {
            let services = match &spec.ports {
                Some(p) => vec![self.service(p)],
                None => vec![],
            };
            self.rule(
                Layer::Zone { zone_id },
                format!("{} : autorisé", spec.label),
                zone_id,
                spec.destinations,
                services,
                vec![],
                Action::Accept,
                "Destinations autorisées par egress-guard.",
                "destinations.allow",
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn rule(
        &mut self,
        layer: Layer,
        name: String,
        zone_id: Uuid,
        destinations: Vec<Uuid>,
        services: Vec<Uuid>,
        data_classes: Vec<Uuid>,
        action: Action,
        comment: &str,
        path: &str,
    ) {
        let sorted = |v: &[Uuid]| {
            let mut v = v.to_vec();
            v.sort();
            v.dedup();
            v
        };
        let mut name = name;
        if let Some(r) = self
            .existing
            .rules
            .iter()
            .find(|r| r.layer == layer && r.name == name)
        {
            // Reused only when identical in effect (review I3).
            if r.enabled
                && r.action == action
                && sorted(&r.destinations) == sorted(&destinations)
                && sorted(&r.services) == sorted(&services)
                && sorted(&r.data_classes) == sorted(&data_classes)
                && sorted(&r.sources) == vec![zone_id]
                && r.expires_at.is_none()
            {
                self.report.map(
                    path,
                    format!("règle existante « {name} » conservée (identique)"),
                );
                return;
            }
            let base = name.clone();
            let mut n = 2;
            while self
                .existing
                .rules
                .iter()
                .any(|r| r.layer == layer && r.name == name)
            {
                name = format!("{base} (import {n})");
                n += 1;
            }
            self.report.warn(
                path,
                format!(
                    "une règle « {base} » existe déjà mais diffère (action, destinations, services, \
                     classes ou activation) : nouvelle règle « {name} » créée ; relisez l'ancienne"
                ),
            );
        }
        let position = 0; // assigned by `assign_positions`
        let section = match layer {
            Layer::Baseline => "egress-guard : destinations refusées",
            Layer::Zone { .. } if data_classes.is_empty() => "egress-guard : destinations",
            Layer::Zone { .. } => "egress-guard : matrice",
        };
        self.report.map(path, format!("règle « {name} »"));
        self.rules.push(Rule {
            id: Uuid::new_v4(),
            name,
            layer,
            section: Some(section.into()),
            position,
            sources: vec![zone_id],
            destinations,
            services,
            data_classes,
            action,
            track: Track::Detailed,
            expires_at: None,
            comment: comment.into(),
            enabled: true,
        });
    }

    /// Places imported rules before the existing rules of their layer when there is room,
    /// otherwise after them with a shadowing warning (review M2).
    fn assign_positions(&mut self) {
        let mut layers: Vec<Layer> = Vec::new();
        for r in &self.rules {
            if !layers.contains(&r.layer) {
                layers.push(r.layer);
            }
        }
        for layer in layers {
            let existing: Vec<u32> = self
                .existing
                .rules
                .iter()
                .filter(|r| r.layer == layer)
                .map(|r| r.position)
                .collect();
            let n = self.rules.iter().filter(|r| r.layer == layer).count() as u32;
            let (start, step) = match (existing.iter().min(), existing.iter().max()) {
                (None, _) | (_, None) => (10, 10),
                (Some(&min), _) if min > n => {
                    let step = ((min - 1) / n).clamp(1, 10);
                    (step, step)
                }
                (_, Some(&max)) => {
                    let what = match layer {
                        Layer::Baseline => "du socle".to_string(),
                        Layer::Zone { .. } => format!("de la zone « {} »", self.zone_name),
                    };
                    self.report.warn(
                        "rules",
                        format!(
                            "pas de place avant les règles existantes {what} : règles importées placées \
                             après elles, elles peuvent être masquées par une règle existante plus haute ; \
                             renumérotez les règles existantes ou déplacez les règles importées"
                        ),
                    );
                    (max.saturating_add(10), 10)
                }
            };
            for (i, r) in self
                .rules
                .iter_mut()
                .filter(|r| r.layer == layer)
                .enumerate()
            {
                r.position = start.saturating_add(step.saturating_mul(i as u32));
            }
        }
    }

    // ---- action classes -----------------------------------------------------------------------

    fn actions(&mut self, map: Option<&Mapping>) -> Result<IntentPolicy, ImportError> {
        let mut classes = Vec::new();
        for (key, v) in entries(map, "action_classes")? {
            let path = format!("action_classes.{key}");
            let spec: ActionClassSpec = from_value(v, &path)?;
            self.extra(&path, &spec.extra);
            let id = slug(&key);
            let raw = spec
                .decision
                .as_deref()
                .map(|d| d.trim().to_ascii_lowercase())
                .unwrap_or_default();
            let decision = match raw.as_str() {
                "allow" => IntentDecision::Allow,
                "log" => IntentDecision::Log,
                "gate" => IntentDecision::Gate,
                "deny" => IntentDecision::Deny,
                "block" | "refuse" => IntentDecision::Deny,
                "ask" | "confirm" | "approval" => {
                    self.report.warn(
                        format!("{path}.decision"),
                        format!("« {raw} » interprété comme gate"),
                    );
                    IntentDecision::Gate
                }
                "" => {
                    self.report.warn(
                        format!("{path}.decision"),
                        "décision absente : gate (validation humaine)",
                    );
                    IntentDecision::Gate
                }
                _ => {
                    self.report.warn(
                        format!("{path}.decision"),
                        format!("décision « {raw} » inconnue : deny (la plus stricte)"),
                    );
                    IntentDecision::Deny
                }
            };
            if spec.patterns.len() > MAX_PATTERNS {
                return Err(ImportError::Limit(format!(
                    "{path}.patterns: more than {MAX_PATTERNS} patterns ({})",
                    spec.patterns.len()
                )));
            }
            let mut patterns = Vec::new();
            for (i, p) in spec.patterns.iter().enumerate() {
                if p.chars().count() > MAX_PATTERN_LEN {
                    self.report.unsupported(
                        format!("{path}.patterns[{i}]"),
                        format!("motif non converti : plus de {MAX_PATTERN_LEN} caractères"),
                    );
                    continue;
                }
                if nested_quantifier(p) {
                    self.report.unsupported(
                        format!("{path}.patterns[{i}]"),
                        "motif non converti : quantificateurs imbriqués (risque de retour arrière \
                         exponentiel dans le moteur Python du plugin)",
                    );
                    continue;
                }
                if regex::Regex::new(p).is_err() {
                    self.report.warn(
                        format!("{path}.patterns[{i}]"),
                        "motif non vérifiable avec la syntaxe Rust : conservé, à valider (le plugin \
                         rejette toute la politique si Python ne le compile pas)",
                    );
                }
                patterns.push(p.clone());
            }
            if spec.tools.is_empty() && patterns.is_empty() {
                self.report.warn(
                    &path,
                    "ni outils ni motifs : la classe s'applique à tous les appels d'outil",
                );
            }
            self.report.map(
                &path,
                format!(
                    "classe d'actions « {id} » du plugin Hermes ({})",
                    decision_str(decision)
                ),
            );
            classes.push(ActionClass {
                id,
                name: spec.name.unwrap_or_else(|| key.clone()),
                tools: spec.tools,
                patterns,
                decision,
            });
        }
        for std in STANDARD_ACTIONS {
            if !classes.iter().any(|c| c.id == std) {
                self.report.warn(
                    "action_classes",
                    format!(
                        "classe « {std} » absente : la politique intégrée du plugin ne s'applique plus \
                         une fois la politique servie par la console"
                    ),
                );
            }
        }
        if !classes.is_empty() {
            self.report.warn(
                "action_classes",
                "la politique d'intention s'applique par PUT /intent-policy, qui remplace toute la \
                 politique servie aux plugins (pas de fusion avec l'existante)",
            );
        }
        Ok(IntentPolicy {
            version: 1,
            action_classes: classes,
        })
    }
}

/// Heuristic for nested quantifiers: a group whose body contains an unescaped `+` or `*`,
/// directly followed by `+`, `*` or `{` (`(a+)+`, `(?:\w*)*`, `(ab+)*`).
fn nested_quantifier(p: &str) -> bool {
    let b = p.as_bytes();
    // Stack of (group start, body has a quantifier).
    let mut stack: Vec<bool> = Vec::new();
    let mut i = 0;
    let mut in_class = false;
    while i < b.len() {
        match b[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'[' if !in_class => in_class = true,
            b']' if in_class => in_class = false,
            _ if in_class => {}
            b'(' => stack.push(false),
            b'+' | b'*' => {
                if let Some(top) = stack.last_mut() {
                    *top = true;
                }
            }
            b')' => {
                let quantified = stack.pop().unwrap_or(false);
                let next = b.get(i + 1).copied();
                if quantified && matches!(next, Some(b'+' | b'*' | b'{')) {
                    return true;
                }
                if quantified && let Some(top) = stack.last_mut() {
                    *top = true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

fn push_cell(cells: &mut Vec<(String, Vec<String>)>, class: &str, tier: &str) {
    match cells.iter_mut().find(|(c, _)| c == class) {
        Some((_, t)) => t.push(tier.to_string()),
        None => cells.push((class.to_string(), vec![tier.to_string()])),
    }
}

fn is_any(t: &str, tiers: &BTreeMap<String, Tier>) -> bool {
    !tiers.contains_key(t) && ANY_TIERS.contains(&t)
}

/// Accept destination sets: plain hosts (any port) and one set per port list. With
/// `per_tier`, one set list per tier (tier accept rules); otherwise the selected tiers (all
/// when `only` is `None`) are merged (matrix `log` rules).
fn accept_specs(
    tiers: &BTreeMap<String, Tier>,
    only: Option<&[String]>,
    per_tier: bool,
) -> Vec<AcceptSpec> {
    let selected: Vec<(&String, &Tier)> = tiers
        .iter()
        .filter(|(name, t)| !t.members.is_empty() && only.is_none_or(|o| o.contains(name)))
        .collect();
    let groups: Vec<Vec<(&String, &Tier)>> = if per_tier {
        selected.into_iter().map(|x| vec![x]).collect()
    } else if selected.is_empty() {
        vec![]
    } else {
        vec![selected]
    };
    let mut out = Vec::new();
    for group in groups {
        let names: Vec<&str> = group.iter().map(|(n, _)| n.as_str()).collect();
        let label = format!("tier {}", names.join(", "));
        let mut plain = Vec::new();
        let mut ported: BTreeMap<Vec<u16>, Vec<Uuid>> = BTreeMap::new();
        for (_, t) in &group {
            plain.extend(t.plain.iter().copied());
            for (p, ids) in &t.ported {
                ported
                    .entry(p.clone())
                    .or_default()
                    .extend(ids.iter().copied());
            }
        }
        if !plain.is_empty() {
            out.push(AcceptSpec {
                label: label.clone(),
                destinations: plain,
                ports: None,
            });
        }
        for (p, ids) in ported {
            out.push(AcceptSpec {
                label: format!("{label} (ports {})", ports_str(&p)),
                destinations: ids,
                ports: Some(p),
            });
        }
    }
    out
}

fn ports_str(p: &[u16]) -> String {
    p.iter().map(u16::to_string).collect::<Vec<_>>().join(",")
}

/// Compiles the candidate patterns of one class with `afw-dlp` (as the gateway does), once
/// per class: invalid patterns are removed (reason `Some`), then patterns firing on a
/// presigned URL are removed (reason `None`, EF-72). Returns the removed patterns.
fn check_patterns(
    candidates: &mut Vec<(String, String, String)>,
) -> Vec<(String, String, Option<String>)> {
    let mut removed = Vec::new();
    let samples = presigned_samples();
    loop {
        if candidates.is_empty() {
            return removed;
        }
        let class = afw_dlp::ClassSpec {
            id: "import-check".into(),
            name: "import-check".into(),
            category: afw_dlp::DataCategory::Custom,
            detectors: candidates
                .iter()
                .map(|(_, name, pattern)| afw_dlp::DetectorSpec::Regex {
                    name: name.clone(),
                    pattern: pattern.clone(),
                })
                .collect(),
        };
        let scanner = match afw_dlp::Scanner::new(&[class], afw_dlp::ScannerOptions::default()) {
            Ok(s) => s,
            Err(e) => {
                // Remove the faulty pattern (named in the error) or, failing that, all.
                let name = match &e {
                    afw_dlp::DlpError::InvalidPattern { name, .. } => Some(name.clone()),
                    _ => None,
                };
                let idx = name.and_then(|n| candidates.iter().position(|c| c.1 == n));
                match idx {
                    Some(i) => {
                        let (p, n, _) = candidates.remove(i);
                        removed.push((p, n, Some(e.to_string())));
                    }
                    None => {
                        for (p, n, _) in candidates.drain(..) {
                            removed.push((p, n, Some(e.to_string())));
                        }
                    }
                }
                continue;
            }
        };
        let mut hits: BTreeSet<String> = BTreeSet::new();
        for s in &samples {
            let json = format!("{{\"upload_url\":\"{s}\"}}");
            let decoded = s.replace("%2F", "/");
            for f in scanner
                .scan_url(s)
                .into_iter()
                .chain(scanner.scan(s.as_bytes(), "body"))
                .chain(scanner.scan(json.as_bytes(), "body"))
                .chain(scanner.scan(decoded.as_bytes(), "body"))
            {
                hits.insert(f.kind);
            }
        }
        if hits.is_empty() {
            return removed;
        }
        candidates.retain(|(p, n, _)| {
            if hits.contains(n) {
                removed.push((p.clone(), n.clone(), None));
                false
            } else {
                true
            }
        });
    }
}

/// Representative presigned upload URLs (SigV4 with session token, SigV2, GCS V4). The
/// access key id is split so the source does not look like a leaked key.
fn presigned_samples() -> [String; 3] {
    let key = ["AK", "IA", "Q3EXAMPLE7ZK4M2P"].concat();
    [
        format!(
            "https://bucket.s3.eu-west-3.amazonaws.com/uploads/report.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential={key}%2F20261030%2Feu-west-3%2Fs3%2Faws4_request&X-Amz-Date=20261030T120000Z\
             &X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEJr%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMyJHMEUCIQD\
             x9mLq2Vt7Zk4Pw8Rn1Hb6Jc3Ys0Ga5Fd8Kt2Lm9Qp4Wv7Xz1Bn6Cr3Ej0Hu5Ik8Ol2Ma9Pq4Rs7Tt1Uv6Wx3Yz0\
             &X-Amz-SignedHeaders=host&X-Amz-Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        ),
        format!(
            "https://bucket.s3.amazonaws.com/uploads/report.pdf?AWSAccessKeyId={key}&Expires=1700000000\
             &Signature=vjbyPxybdZaNmGa%2ByT272YEAiv4%3D"
        ),
        "https://storage.googleapis.com/bucket/report.pdf?X-Goog-Algorithm=GOOG4-RSA-SHA256\
         &X-Goog-Credential=sa%40proj.iam.gserviceaccount.com%2F20261030%2Fauto%2Fstorage%2Fgoog4_request\
         &X-Goog-Date=20261030T000000Z&X-Goog-Expires=900&X-Goog-SignedHeaders=host\
         &X-Goog-Signature=a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
            .to_string(),
    ]
}

// ---- helpers -----------------------------------------------------------------------------------

fn entries(map: Option<&Mapping>, path: &str) -> Result<Vec<(String, Value)>, ImportError> {
    let Some(map) = map else {
        return Ok(Vec::new());
    };
    map.iter()
        .map(|(k, v)| match k {
            Value::String(s) => Ok((s.clone(), v.clone())),
            Value::Number(n) => Ok((n.to_string(), v.clone())),
            other => Err(ImportError::Invalid {
                path: path.to_string(),
                message: format!("keys must be strings, got {}", kind(other)),
            }),
        })
        .collect()
}

fn from_value<T: DeserializeOwned + Default>(v: Value, path: &str) -> Result<T, ImportError> {
    if v.is_null() {
        return Ok(T::default());
    }
    serde_yaml::from_value(v).map_err(|e| ImportError::Invalid {
        path: path.to_string(),
        message: e.to_string(),
    })
}

fn join(base: &str, key: &str) -> String {
    if base.is_empty() {
        key.to_string()
    } else {
        format!("{base}.{key}")
    }
}

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Sequence(_) => "a sequence",
        Value::Mapping(_) => "a mapping",
        Value::Tagged(_) => "a tagged value",
    }
}

fn show(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        other => kind(other).to_string(),
    }
}

/// Same rule as the engine's domain names (ADR 0016): lowercase ASCII labels.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
        })
}

fn same_leaf(a: &NetObjectSpec, b: &NetObjectSpec) -> bool {
    match (a, b) {
        (NetObjectSpec::Domain { pattern: x }, NetObjectSpec::Domain { pattern: y }) => {
            let n = |p: &str| p.strip_suffix('.').unwrap_or(p).to_ascii_lowercase();
            n(x) == n(y)
        }
        (NetObjectSpec::Host { ip: x }, NetObjectSpec::Host { ip: y }) => x == y,
        (NetObjectSpec::Network { cidr: x }, NetObjectSpec::Network { cidr: y }) => {
            x.trunc() == y.trunc()
        }
        _ => false,
    }
}

fn spec_name(spec: &NetObjectSpec) -> String {
    match spec {
        NetObjectSpec::Domain { pattern } => pattern.clone(),
        NetObjectSpec::Host { ip } => ip.to_string(),
        NetObjectSpec::Network { cidr } => cidr.to_string(),
        _ => "objet".into(),
    }
}

fn parse_category(c: &str) -> Option<DataCategory> {
    match c.trim().to_ascii_lowercase().as_str() {
        "secret" | "secrets" => Some(DataCategory::Secret),
        "infra" | "infrastructure" => Some(DataCategory::Infra),
        "commercial" | "business" => Some(DataCategory::Commercial),
        "personal" | "pii" => Some(DataCategory::Personal),
        "custom" => Some(DataCategory::Custom),
        _ => None,
    }
}

fn infer_category(key: &str) -> DataCategory {
    let k = key.to_ascii_lowercase();
    if k.contains("secret") || k.contains("credential") || k.contains("token") {
        DataCategory::Secret
    } else if k.contains("infra") {
        DataCategory::Infra
    } else if k.contains("commercial") || k.contains("business") {
        DataCategory::Commercial
    } else if k.contains("personal") || k.contains("pii") {
        DataCategory::Personal
    } else {
        DataCategory::Custom
    }
}

fn category_str(c: DataCategory) -> &'static str {
    match c {
        DataCategory::Secret => "secret",
        DataCategory::Infra => "infra",
        DataCategory::Commercial => "commercial",
        DataCategory::Personal => "personnel",
        DataCategory::Custom => "personnalisée",
    }
}

fn decision_str(d: IntentDecision) -> &'static str {
    match d {
        IntentDecision::Allow => "allow",
        IntentDecision::Log => "log",
        IntentDecision::Gate => "gate",
        IntentDecision::Deny => "deny",
    }
}

fn mode_str(m: ZoneMode) -> &'static str {
    match m {
        ZoneMode::Observe => "observe",
        ZoneMode::Enforce => "enforce",
    }
}

fn slug(key: &str) -> String {
    let mut s = String::new();
    for c in key.trim().chars() {
        if c.is_ascii_alphanumeric() {
            s.push(c.to_ascii_lowercase());
        } else if !s.ends_with('_') {
            s.push('_');
        }
    }
    s.trim_matches('_').to_string()
}

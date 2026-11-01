//! Recognition of infrastructure administration calls from method + path (EF-81): Kubernetes,
//! Docker Engine, Coolify and Proxmox VE APIs.

use afw_core::events::{AdminAction, AdminSystem};

fn action(system: AdminSystem, action: &str, resource: String) -> Option<AdminAction> {
    Some(AdminAction {
        system,
        action: action.to_string(),
        resource,
    })
}

fn verb(method: &str, collection: bool) -> &'static str {
    match method {
        "POST" => "create",
        "PUT" | "PATCH" => "update",
        "DELETE" => "delete",
        _ if collection => "list",
        _ => "get",
    }
}

/// `path` without query string. Returns `None` when the call is not recognised.
pub fn recognize(method: &str, path: &str) -> Option<AdminAction> {
    let method = method.to_ascii_uppercase();
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    proxmox(&method, &segs)
        .or_else(|| coolify(&method, &segs))
        .or_else(|| kubernetes(&method, &segs))
        .or_else(|| docker(&method, &segs))
}

fn proxmox(m: &str, s: &[&str]) -> Option<AdminAction> {
    if s.len() < 3 || s[0] != "api2" || s[1] != "json" {
        return None;
    }
    let rest = &s[2..];
    let resource = rest.join("/");
    // nodes/<node>/(qemu|lxc)/<vmid>/...
    if rest.first() == Some(&"nodes") && rest.len() >= 3 && matches!(rest[2], "qemu" | "lxc") {
        let guest = rest[..rest.len().min(4)].join("/");
        return match (m, &rest[3.min(rest.len())..]) {
            ("POST", []) => action(AdminSystem::Proxmox, "create", guest),
            ("DELETE", [_]) => action(AdminSystem::Proxmox, "delete", guest),
            ("POST", [_, "status", op]) => action(AdminSystem::Proxmox, op, guest),
            (_, [_, "termproxy" | "vncproxy" | "spiceproxy" | "vncwebsocket"]) => {
                action(AdminSystem::Proxmox, "exec", guest)
            }
            ("POST", [_, "clone" | "migrate" | "snapshot" | "resize"]) => {
                action(AdminSystem::Proxmox, rest[4], guest)
            }
            ("PUT" | "POST", [_, "config"]) => action(AdminSystem::Proxmox, "update", guest),
            _ => action(AdminSystem::Proxmox, verb(m, false), resource),
        };
    }
    if m == "GET" {
        return None;
    }
    action(AdminSystem::Proxmox, verb(m, false), resource)
}

fn coolify(m: &str, s: &[&str]) -> Option<AdminAction> {
    if s.len() < 3 || s[0] != "api" || s[1] != "v1" {
        return None;
    }
    let kinds = [
        "deploy",
        "applications",
        "services",
        "databases",
        "servers",
        "projects",
        "deployments",
    ];
    if !kinds.contains(&s[2]) {
        return None;
    }
    if s[2] == "deploy" {
        return action(AdminSystem::Coolify, "deploy", "deploy".into());
    }
    let resource = s[2..s.len().min(4)].join("/");
    match (m, &s[3.min(s.len())..]) {
        (_, [_, op @ ("start" | "stop" | "restart" | "deploy")]) => {
            action(AdminSystem::Coolify, op, resource)
        }
        ("DELETE", [_]) => action(AdminSystem::Coolify, "delete", resource),
        ("PATCH" | "PUT", _) => action(AdminSystem::Coolify, "update", resource),
        ("POST", _) => action(AdminSystem::Coolify, "create", resource),
        _ => None,
    }
}

fn kubernetes(m: &str, s: &[&str]) -> Option<AdminAction> {
    // /api/v1/... or /apis/<group>/<version>/...
    let rest = match s {
        ["api", "v1", rest @ ..] => rest,
        ["apis", _group, _version, rest @ ..] => rest,
        _ => return None,
    };
    if rest.is_empty() {
        return None;
    }
    if rest[0] != "namespaces"
        && ![
            "nodes",
            "persistentvolumes",
            "clusterroles",
            "clusterrolebindings",
            "customresourcedefinitions",
        ]
        .contains(&rest[0])
    {
        return None;
    }
    // namespaces/<ns>/<kind>/<name>/<sub>
    let (base_len, sub) = if rest[0] == "namespaces" && rest.len() >= 3 {
        (rest.len().min(4), rest.get(4).copied())
    } else {
        (rest.len().min(2), rest.get(2).copied())
    };
    let resource = rest[..base_len].join("/");
    let collection = if rest[0] == "namespaces" && rest.len() >= 3 {
        rest.len() == 3
    } else {
        rest.len() == 1 || (rest[0] == "namespaces" && rest.len() == 1)
    };
    let act = match sub {
        Some(op @ ("exec" | "attach" | "portforward" | "proxy" | "eviction" | "log" | "scale")) => {
            op
        }
        Some("status") if m != "GET" => "update",
        _ => verb(m, collection),
    };
    action(AdminSystem::Kubernetes, act, resource)
}

fn docker(m: &str, s: &[&str]) -> Option<AdminAction> {
    let s = match s.first() {
        Some(v)
            if v.starts_with('v')
                && v[1..]
                    .split('.')
                    .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())) =>
        {
            &s[1..]
        }
        _ => s,
    };
    match (m, s) {
        ("POST", ["containers", "create"]) => {
            action(AdminSystem::Docker, "create", "containers".into())
        }
        ("POST", ["containers", id, "exec"]) => {
            action(AdminSystem::Docker, "exec", format!("containers/{id}"))
        }
        ("POST", ["exec", id, "start"]) => {
            action(AdminSystem::Docker, "exec", format!("exec/{id}"))
        }
        (
            "POST",
            [
                "containers",
                id,
                op @ ("start" | "stop" | "restart" | "kill" | "pause" | "unpause" | "update"
                | "rename" | "attach"),
            ],
        ) => action(AdminSystem::Docker, op, format!("containers/{id}")),
        ("DELETE", ["containers", id]) => {
            action(AdminSystem::Docker, "delete", format!("containers/{id}"))
        }
        ("POST", ["images", "create"]) => action(AdminSystem::Docker, "pull", "images".into()),
        ("DELETE", ["images", id]) => action(AdminSystem::Docker, "delete", format!("images/{id}")),
        ("POST", ["services", "create"]) => {
            action(AdminSystem::Docker, "create", "services".into())
        }
        ("DELETE", [kind @ ("services" | "volumes" | "networks"), id]) => {
            action(AdminSystem::Docker, "delete", format!("{kind}/{id}"))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(m: &str, p: &str) -> Option<(AdminSystem, String, String)> {
        recognize(m, p).map(|a| (a.system, a.action, a.resource))
    }

    #[test]
    fn kubernetes_calls() {
        assert_eq!(
            r("POST", "/api/v1/namespaces/prod/pods"),
            Some((
                AdminSystem::Kubernetes,
                "create".into(),
                "namespaces/prod/pods".into()
            ))
        );
        assert_eq!(
            r("POST", "/api/v1/namespaces/prod/pods/web-0/exec"),
            Some((
                AdminSystem::Kubernetes,
                "exec".into(),
                "namespaces/prod/pods/web-0".into()
            ))
        );
        assert_eq!(
            r("GET", "/api/v1/namespaces/prod/pods/web-0/exec"),
            Some((
                AdminSystem::Kubernetes,
                "exec".into(),
                "namespaces/prod/pods/web-0".into()
            ))
        );
        assert_eq!(
            r("DELETE", "/apis/apps/v1/namespaces/prod/deployments/web"),
            Some((
                AdminSystem::Kubernetes,
                "delete".into(),
                "namespaces/prod/deployments/web".into()
            ))
        );
        assert_eq!(
            r("GET", "/api/v1/namespaces/prod/pods"),
            Some((
                AdminSystem::Kubernetes,
                "list".into(),
                "namespaces/prod/pods".into()
            ))
        );
        assert_eq!(r("GET", "/api/v1/messages"), None);
    }

    #[test]
    fn docker_coolify_proxmox_calls() {
        assert_eq!(
            r("POST", "/v1.43/containers/create"),
            Some((AdminSystem::Docker, "create".into(), "containers".into()))
        );
        assert_eq!(
            r("POST", "/containers/abc/exec"),
            Some((AdminSystem::Docker, "exec".into(), "containers/abc".into()))
        );
        assert_eq!(
            r("DELETE", "/containers/abc"),
            Some((
                AdminSystem::Docker,
                "delete".into(),
                "containers/abc".into()
            ))
        );
        assert_eq!(
            r("GET", "/api/v1/deploy"),
            Some((AdminSystem::Coolify, "deploy".into(), "deploy".into()))
        );
        assert_eq!(
            r("POST", "/api/v1/applications/u1/restart"),
            Some((
                AdminSystem::Coolify,
                "restart".into(),
                "applications/u1".into()
            ))
        );
        assert_eq!(
            r("POST", "/api2/json/nodes/pve/qemu/101/status/stop"),
            Some((
                AdminSystem::Proxmox,
                "stop".into(),
                "nodes/pve/qemu/101".into()
            ))
        );
        assert_eq!(
            r("POST", "/api2/json/nodes/pve/qemu"),
            Some((
                AdminSystem::Proxmox,
                "create".into(),
                "nodes/pve/qemu".into()
            ))
        );
        assert_eq!(
            r("DELETE", "/api2/json/nodes/pve/lxc/200"),
            Some((
                AdminSystem::Proxmox,
                "delete".into(),
                "nodes/pve/lxc/200".into()
            ))
        );
        assert_eq!(r("GET", "/v1/models"), None);
    }
}

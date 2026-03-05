use super::*;

pub(super) fn pretty_json(value: JsonValue) -> String {
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
}

pub(super) fn format_hub_profile_output(
    ok: bool,
    version: &str,
    profile_id: &str,
    hub_id: &str,
    features: &RemoteHubProfileFeatures,
    use_json: bool,
) -> String {
    if use_json {
        let mut root = JsonMap::new();
        root.insert("ok".to_string(), JsonValue::Bool(ok));
        root.insert(
            "version".to_string(),
            JsonValue::String(version.to_string()),
        );
        root.insert(
            "profile_id".to_string(),
            JsonValue::String(profile_id.to_string()),
        );
        root.insert("hub_id".to_string(), JsonValue::String(hub_id.to_string()));
        let mut feature_map = JsonMap::new();
        feature_map.insert("core".to_string(), JsonValue::Bool(features.core));
        feature_map.insert("fed1".to_string(), JsonValue::Bool(features.fed1));
        feature_map.insert("auth1".to_string(), JsonValue::Bool(features.auth1));
        feature_map.insert("kex1_plus".to_string(), JsonValue::Bool(features.kex1_plus));
        feature_map.insert("sh1_plus".to_string(), JsonValue::Bool(features.sh1_plus));
        feature_map.insert("lclass0".to_string(), JsonValue::Bool(features.lclass0));
        feature_map.insert(
            "meta0_plus".to_string(),
            JsonValue::Bool(features.meta0_plus),
        );
        root.insert("features".to_string(), JsonValue::Object(feature_map));
        pretty_json(JsonValue::Object(root))
    } else {
        [
            format!("version: {version}"),
            format!("profile_id: {profile_id}"),
            format!("hub_id: {hub_id}"),
            "features:".to_string(),
            format!("  core: {}", features.core),
            format!("  fed1: {}", features.fed1),
            format!("  auth1: {}", features.auth1),
            format!("  kex1_plus: {}", features.kex1_plus),
            format!("  sh1_plus: {}", features.sh1_plus),
            format!("  lclass0: {}", features.lclass0),
            format!("  meta0_plus: {}", features.meta0_plus),
        ]
        .join("\n")
    }
}

pub(super) fn format_hub_role_output(
    ok: bool,
    hub_id: &str,
    role: &str,
    stream: Option<&RemoteHubRoleStream>,
    use_json: bool,
) -> String {
    if use_json {
        let mut root = JsonMap::new();
        root.insert("ok".to_string(), JsonValue::Bool(ok));
        root.insert("hub_id".to_string(), JsonValue::String(hub_id.to_string()));
        root.insert("role".to_string(), JsonValue::String(role.to_string()));
        if let Some(stream) = stream {
            let mut stream_map = JsonMap::new();
            if let Some(value) = &stream.realm_id {
                stream_map.insert("realm_id".to_string(), JsonValue::String(value.clone()));
            } else {
                stream_map.insert("realm_id".to_string(), JsonValue::Null);
            }
            stream_map.insert(
                "stream_id".to_string(),
                JsonValue::String(stream.stream_id.clone()),
            );
            stream_map.insert("label".to_string(), JsonValue::String(stream.label.clone()));
            stream_map.insert(
                "policy".to_string(),
                JsonValue::String(stream.policy.clone()),
            );
            if let Some(primary) = &stream.primary_hub {
                stream_map.insert(
                    "primary_hub".to_string(),
                    JsonValue::String(primary.clone()),
                );
            } else {
                stream_map.insert("primary_hub".to_string(), JsonValue::Null);
            }
            stream_map.insert(
                "local_is_primary".to_string(),
                JsonValue::Bool(stream.local_is_primary),
            );
            root.insert("stream".to_string(), JsonValue::Object(stream_map));
        }
        pretty_json(JsonValue::Object(root))
    } else if let Some(stream) = stream {
        let realm_out = stream
            .realm_id
            .clone()
            .unwrap_or_else(|| "unspecified".to_string());
        let primary = stream
            .primary_hub
            .clone()
            .unwrap_or_else(|| "none".to_string());
        [
            format!("hub_id: {hub_id}"),
            format!("role: {role}"),
            format!("realm_id: {realm_out}"),
            format!("stream_id: {}", stream.stream_id),
            format!("label: {}", stream.label),
            format!("policy: {}", stream.policy),
            format!("primary_hub: {primary}"),
            format!("local_is_primary: {}", stream.local_is_primary),
        ]
        .join("\n")
    } else {
        [format!("role: {role}"), format!("hub_id: {hub_id}")].join("\n")
    }
}

pub(super) fn format_authority_record_output(
    descriptor: &RemoteAuthorityRecordDescriptor,
    use_json: bool,
) -> String {
    if use_json {
        let output = json!({
            "ok": true,
            "realm_id": descriptor.realm_id,
            "stream_id": descriptor.stream_id,
            "primary_hub": descriptor.primary_hub,
            "replica_hubs": descriptor.replica_hubs,
            "policy": descriptor.policy,
            "ts": descriptor.ts,
            "ttl": descriptor.ttl,
            "expires_at": descriptor.expires_at,
            "active_now": descriptor.active_now,
        });
        pretty_json(output)
    } else {
        let primary = descriptor
            .primary_hub
            .clone()
            .unwrap_or_else(|| "none".to_string());
        let replicas = if descriptor.replica_hubs.is_empty() {
            "[]".to_string()
        } else {
            format!("[{}]", descriptor.replica_hubs.join(","))
        };
        let expires = descriptor
            .expires_at
            .map(|value| value.to_string())
            .unwrap_or_else(|| "0".to_string());
        [
            format!("realm_id: {}", descriptor.realm_id),
            format!("stream_id: {}", descriptor.stream_id),
            format!("primary_hub: {primary}"),
            format!("replica_hubs: {replicas}"),
            format!("policy: {}", descriptor.policy),
            format!("ts: {}", descriptor.ts),
            format!("ttl: {}", descriptor.ttl),
            format!("expires_at: {expires}"),
            format!("active_now: {}", descriptor.active_now),
        ]
        .join("\n")
    }
}

pub(super) fn format_label_authority_output(
    descriptor: &RemoteLabelAuthorityDescriptor,
    use_json: bool,
) -> String {
    if use_json {
        let output = json!({
            "ok": true,
            "label": descriptor.label,
            "realm_id": descriptor.realm_id,
            "stream_id": descriptor.stream_id,
            "policy": descriptor.policy,
            "primary_hub": descriptor.primary_hub,
            "replica_hubs": descriptor.replica_hubs,
            "local_hub_id": descriptor.local_hub_id,
            "locally_authorized": descriptor.local_is_authorized,
        });
        pretty_json(output)
    } else {
        let realm_display = descriptor
            .realm_id
            .clone()
            .unwrap_or_else(|| "unspecified".to_string());
        let primary = descriptor
            .primary_hub
            .clone()
            .unwrap_or_else(|| "none".to_string());
        [
            format!("label: {}", descriptor.label),
            format!("realm_id: {realm_display}"),
            format!("stream_id: {}", descriptor.stream_id),
            format!("policy: {}", descriptor.policy),
            format!("primary_hub: {primary}"),
            format!("local_hub_id: {}", descriptor.local_hub_id),
            format!("locally_authorized: {}", descriptor.local_is_authorized),
        ]
        .join("\n")
    }
}

pub(super) fn format_label_class_descriptor_output(
    descriptor: &RemoteLabelClassDescriptor,
    use_json: bool,
) -> String {
    if use_json {
        let output = json!({
            "ok": true,
            "label": descriptor.label,
            "class": descriptor.class,
            "sensitivity": descriptor.sensitivity,
            "retention_hint": descriptor.retention_hint,
            "pad_block_effective": descriptor.pad_block_effective,
            "retention_policy": descriptor.retention_policy,
            "rate_policy": descriptor.rate_policy,
        });
        pretty_json(output)
    } else {
        let class = descriptor
            .class
            .clone()
            .unwrap_or_else(|| "unset".to_string());
        let sensitivity = descriptor
            .sensitivity
            .clone()
            .unwrap_or_else(|| "none".to_string());
        let retention_hint = descriptor
            .retention_hint
            .map(|value| value.to_string())
            .unwrap_or_else(|| "0".to_string());
        [
            format!("label: {}", descriptor.label),
            format!("class: {class}"),
            format!("sensitivity: {sensitivity}"),
            format!("retention_hint: {retention_hint}"),
            format!("pad_block_effective: {}", descriptor.pad_block_effective),
            format!("retention_policy: {}", descriptor.retention_policy),
            format!("rate_policy: {}", descriptor.rate_policy),
        ]
        .join("\n")
    }
}

pub(super) fn format_label_class_list_output(
    list: &RemoteLabelClassList,
    use_json: bool,
) -> String {
    if use_json {
        let entries = list
            .entries
            .iter()
            .map(|entry| {
                json!({
                    "label": entry.label,
                    "class": entry.class,
                    "sensitivity": entry.sensitivity,
                    "retention_hint": entry.retention_hint,
                })
            })
            .collect::<Vec<_>>();
        let output = json!({ "ok": true, "entries": entries });
        pretty_json(output)
    } else if list.entries.is_empty() {
        "no label classifications found".to_string()
    } else {
        let mut rows = Vec::with_capacity(list.entries.len() + 1);
        rows.push(
            "label                                                             class      sensitivity retention_hint"
                .to_string(),
        );
        for entry in &list.entries {
            let sensitivity = entry
                .sensitivity
                .clone()
                .unwrap_or_else(|| "none".to_string());
            let retention_hint = entry
                .retention_hint
                .map(|value| value.to_string())
                .unwrap_or_else(|| "0".to_string());
            rows.push(format!(
                "{:<66} {:<10} {:<11} {}",
                entry.label, entry.class, sensitivity, retention_hint
            ));
        }
        rows.join("\n")
    }
}

pub(super) fn format_schema_descriptor_output(
    descriptor: &RemoteSchemaDescriptorEntry,
    usage: Option<&RemoteSchemaUsage>,
    use_json: bool,
) -> String {
    if use_json {
        let usage_json = usage.map(|stats| {
            json!({
                "used_labels": stats.used_labels,
                "used_count": stats.used_count,
                "first_used_ts": stats.first_used_ts,
                "last_used_ts": stats.last_used_ts,
            })
        });
        let output = json!({
            "ok": true,
            "schema_id": descriptor.schema_id,
            "name": descriptor.name,
            "version": descriptor.version,
            "doc_url": descriptor.doc_url,
            "owner": descriptor.owner,
            "ts": descriptor.ts,
            "created_at": descriptor.created_at,
            "updated_at": descriptor.updated_at,
            "usage": usage_json,
        });
        pretty_json(output)
    } else {
        let doc_url = descriptor
            .doc_url
            .clone()
            .unwrap_or_else(|| "none".to_string());
        let owner = descriptor
            .owner
            .clone()
            .unwrap_or_else(|| "none".to_string());
        let created_at = descriptor
            .created_at
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let updated_at = descriptor
            .updated_at
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let usage_labels = usage
            .map(|stats| {
                if stats.used_labels.is_empty() {
                    "none".to_string()
                } else {
                    format!("[{}]", stats.used_labels.join(","))
                }
            })
            .unwrap_or_else(|| "none".to_string());
        let used_count = usage
            .and_then(|stats| stats.used_count)
            .map(|value| value.to_string())
            .unwrap_or_else(|| "0".to_string());
        let first_used = usage
            .and_then(|stats| stats.first_used_ts)
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let last_used = usage
            .and_then(|stats| stats.last_used_ts)
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        [
            format!("schema_id: {}", descriptor.schema_id),
            format!("name: {}", descriptor.name),
            format!("version: {}", descriptor.version),
            format!("doc_url: {doc_url}"),
            format!("owner: {owner}"),
            format!("ts: {}", descriptor.ts),
            format!("created_at: {created_at}"),
            format!("updated_at: {updated_at}"),
            format!("used_labels: {usage_labels}"),
            format!("used_count: {used_count}"),
            format!("first_used_ts: {first_used}"),
            format!("last_used_ts: {last_used}"),
        ]
        .join("\n")
    }
}

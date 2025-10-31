#!/usr/bin/env python3
"""
Script to add session information fields to Blocklist event structures.
"""

import re
import sys

def add_serde_import(content):
    """Add serde::ts_nanoseconds import if not present."""
    if 'serde::ts_nanoseconds' in content:
        return content

    pattern = r'(use chrono::\{DateTime, Utc)(}\;)'
    replacement = r'\1, serde::ts_nanoseconds\2'
    return re.sub(pattern, replacement, content)

def update_v0_42_struct(content, struct_name):
    """Update the V0_42 struct to add session fields."""
    # Pattern to find the struct definition and add fields after end_time
    pattern = rf'(pub struct {struct_name}V0_42 \{{.*?pub proto: u8,\s+)(pub start_time: i64,\s+pub end_time: i64,)'

    replacement = r'\1#[serde(with = "ts_nanoseconds")]\n    pub start_time: DateTime<Utc>,\n    #[serde(with = "ts_nanoseconds")]\n    pub end_time: DateTime<Utc>,\n    pub duration: i64,\n    pub orig_pkts: u64,\n    pub resp_pkts: u64,\n    pub orig_l2_bytes: u64,\n    pub resp_l2_bytes: u64,'

    return re.sub(pattern, replacement, content, flags=re.DOTALL)

def update_migrate_from(content, struct_name):
    """Update MigrateFrom implementation."""
    # Find and update the MigrateFrom impl block
    pattern = rf'(impl MigrateFrom<{struct_name}V0_41> for {struct_name}V0_42 \{{.*?fn new\(value: {struct_name}V0_41, start_time: i64\) -> Self \{{)'
    replacement = r'\1\n        let start_time_dt = chrono::DateTime::from_timestamp_nanos(start_time);\n        let end_time_nanos = value.end_time;\n        let end_time_dt = chrono::DateTime::from_timestamp_nanos(end_time_nanos);\n        let duration = end_time_nanos.saturating_sub(start_time);\n'
    content = re.sub(pattern, replacement, content, flags=re.DOTALL)

    # Update the Self initialization in MigrateFrom
    pattern = r'(proto: value\.proto,\s+)start_time,\s+end_time: value\.end_time,'
    replacement = r'\1start_time: start_time_dt,\n            end_time: end_time_dt,\n            duration,\n            orig_pkts: 0,\n            resp_pkts: 0,\n            orig_l2_bytes: 0,\n            resp_l2_bytes: 0,'
    content = re.sub(pattern, replacement, content)

    return content

def update_syslog_method(content):
    """Update syslog_rfc5424 method."""
    # Remove the timestamp conversion lines
    content = re.sub(r'\s+let start_time_str = DateTime::from_timestamp_nanos\(self\.start_time\)\.to_rfc3339\(\);\s+let end_time_str = DateTime::from_timestamp_nanos\(self\.end_time\)\.to_rfc3339\(\);\n', '', content)

    # Update format string to add new fields
    content = re.sub(
        r'proto=\{:?\?\} start_time=\{:?\?\} end_time=\{:?\?\}',
        'proto={:?} start_time={:?} end_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?}',
        content
    )

    # Update the values in format!
    pattern = r'(self\.proto\.to_string\(\),\s+)start_time_str,\s+end_time_str,'
    replacement = r'\1self.start_time.to_rfc3339(),\n            self.end_time.to_rfc3339(),\n            self.duration.to_string(),\n            self.orig_pkts.to_string(),\n            self.resp_pkts.to_string(),\n            self.orig_l2_bytes.to_string(),\n            self.resp_l2_bytes.to_string(),'
    content = re.sub(pattern, replacement, content)

    return content

def update_blocklist_struct(content, struct_name_prefix):
    """Update the main Blocklist struct."""
    pattern = rf'(pub struct {struct_name_prefix} \{{.*?pub proto: u8,\s+pub start_time: i64,\s+pub end_time: i64,)'
    replacement = r'\1\n    pub duration: i64,\n    pub orig_pkts: u64,\n    pub resp_pkts: u64,\n    pub orig_l2_bytes: u64,\n    pub resp_l2_bytes: u64,'
    return re.sub(pattern, replacement, content, flags=re.DOTALL)

def update_display_impl(content):
    """Update Display implementation."""
    # Update format string
    content = re.sub(
        r'proto=\{:?\?\} start_time=\{:?\?\} end_time=\{:?\?\}',
        'proto={:?} start_time={:?} end_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?}',
        content
    )

    # Update the values - look for pattern in Display impl (not syslog)
    pattern = r'(impl fmt::Display for \w+ \{.*?self\.proto\.to_string\(\),\s+start_time_str,\s+end_time_str,)'
    replacement = r'\1\n            self.duration.to_string(),\n            self.orig_pkts.to_string(),\n            self.resp_pkts.to_string(),\n            self.orig_l2_bytes.to_string(),\n            self.resp_l2_bytes.to_string(),'
    content = re.sub(pattern, replacement, content, flags=re.DOTALL)

    return content

def update_new_method(content):
    """Update the new() constructor."""
    pattern = r'(proto: fields\.proto,\s+)start_time: fields\.start_time,\s+end_time: fields\.end_time,'
    replacement = r'\1start_time: fields.start_time.timestamp_nanos_opt().unwrap_or_default(),\n            end_time: fields.end_time.timestamp_nanos_opt().unwrap_or_default(),\n            duration: fields.duration,\n            orig_pkts: fields.orig_pkts,\n            resp_pkts: fields.resp_pkts,\n            orig_l2_bytes: fields.orig_l2_bytes,\n            resp_l2_bytes: fields.resp_l2_bytes,'
    return re.sub(pattern, replacement, content)

def process_file(filepath, struct_name):
    """Process a single file."""
    try:
        with open(filepath, 'r') as f:
            content = f.read()

        original_content = content

        # Apply all transformations
        content = add_serde_import(content)
        content = update_v0_42_struct(content, struct_name)
        content = update_migrate_from(content, struct_name)
        content = update_syslog_method(content)
        content = update_blocklist_struct(content, struct_name.replace('Fields', ''))
        content = update_display_impl(content)
        content = update_new_method(content)

        if content != original_content:
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"✓ Updated {filepath}")
            return True
        else:
            print(f"- No changes needed for {filepath}")
            return False
    except Exception as e:
        print(f"✗ Error processing {filepath}: {e}")
        return False

if __name__ == "__main__":
    import os
    base_path = "/Users/msk/.cache/octoaide/git/petabi/review-database/src/event"

    files_to_process = [
        ("smtp.rs", "BlocklistSmtpFields"),
        ("nfs.rs", "BlocklistNfsFields"),
        ("ssh.rs", "BlocklistSshFields"),
        ("dcerpc.rs", "BlocklistDceRpcFields"),
        ("rdp.rs", "BlocklistRdpFields"),
        ("ntlm.rs", "BlocklistNtlmFields"),
        ("smb.rs", "BlocklistSmbFields"),
        ("mqtt.rs", "BlocklistMqttFields"),
        ("bootp.rs", "BlocklistBootpFields"),
        ("dhcp.rs", "BlocklistDhcpFields"),
    ]

    success_count = 0
    for filename, struct_name in files_to_process:
        filepath = os.path.join(base_path, filename)
        if process_file(filepath, struct_name):
            success_count += 1

    print(f"\nProcessed {success_count}/{len(files_to_process)} files successfully")

//! KeePass XML parsing and generation
//!
//! Handles parsing and generation of KeePass 2.x XML format.

use super::KeePassEntry;
use crate::{PasswordManagerError, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::io::{BufRead, BufReader};
use std::path::Path;

// These structs are for potential future serde-based XML parsing
// Currently, the code uses manual parsing in parse_keepass2_from_string
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct KeePassXmlDoc {
    #[serde(rename = "Root")]
    root: Root,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Root {
    #[serde(rename = "Group")]
    group: Vec<Group>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Group {
    #[serde(rename = "Name")]
    name: String,

    #[serde(rename = "Entry")]
    entries: Vec<Option<XmlEntry>>,
    #[serde(default)]
    #[serde(rename = "Group")]
    subgroups: Vec<SubGroup>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SubGroup {
    #[serde(rename = "Name")]
    name: String,

    #[serde(rename = "Entry")]
    entries: Vec<Option<XmlEntry>>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct XmlEntry {
    #[serde(rename = "String")]
    strings: Vec<KeePassString>,

    #[serde(rename = "Times")]
    times: Option<EntryTimes>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct KeePassString {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "Value")]
    value: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct EntryTimes {
    #[serde(rename = "CreationTime")]
    creation_time: Option<String>,
    #[serde(rename = "LastModTime")]
    last_mod_time: Option<String>,
    #[serde(rename = "ExpiryTime")]
    expiry_time: Option<String>,
}

/// Parse KeePass XML file
pub fn parse_keepass_xml(input: &Path) -> Result<Vec<KeePassEntry>> {
    let file = std::fs::File::open(input).map_err(|e| {
        PasswordManagerError::from(crate::DatabaseError::FileIo(format!(
            "Failed to open KeePass XML file: {}",
            e
        )))
    })?;

    let reader = BufReader::new(file);

    // Quickscan to find the opening tag and detect version
    let mut version = None;
    for line in reader.lines() {
        let line = line.map_err(|e| {
            PasswordManagerError::from(crate::DatabaseError::FileIo(format!(
                "Failed to read XML file: {}",
                e
            )))
        })?;

        if line.contains("<?xml") {
            continue;
        }
        if line.contains("KeePassFile") {
            version = Some("1");
            break;
        } else if line.contains("KeePass") && line.contains("xr") {
            // Check for xmlns which indicates the XML format
            if line.contains("xmlns") {
                version = Some("2");
            }
            break;
        }
    }

    // Re-open file and parse based on version
    let file = std::fs::File::open(input).map_err(|e| {
        PasswordManagerError::from(crate::DatabaseError::FileIo(format!(
            "Failed to open KeePass XML file: {}",
            e
        )))
    })?;

    let entries = match version {
        Some("1") | None => {
            // Try to parse as KeePass 2 XML (most common)
            try_parse_keepass2_xml(&file).map_err(|_| PasswordManagerError::InvalidInput(
                "Failed to parse KeePass XML. Please ensure it's a valid KeePass 2.x XML export.".to_string()
            ))?
        }
        Some("2") => try_parse_keepass2_xml(&file)?,
        _ => {
            return Err(PasswordManagerError::InvalidInput(
                "Unknown KeePass XML version".to_string(),
            ));
        }
    };

    if entries.is_empty() {
        return Err(PasswordManagerError::InvalidInput(
            "No entries found in KeePass XML file".to_string(),
        ));
    }

    Ok(entries)
}

/// Try to parse KeePass 2.x XML format
fn try_parse_keepass2_xml(file: &std::fs::File) -> Result<Vec<KeePassEntry>> {
    let reader = BufReader::new(file);
    let lines: std::io::Result<Vec<String>> = reader.lines().collect();
    let lines = lines.map_err(|e| {
        PasswordManagerError::from(crate::DatabaseError::FileIo(format!(
            "Failed to read XML: {}",
            e
        )))
    })?;
    let xml_content = lines.join("\n");

    // Parse with quick-xml (simpler than serde for this use case)
    parse_keepass2_from_string(&xml_content)
}

/// Parse KeePass 2.x XML from string
fn parse_keepass2_from_string(xml: &str) -> Result<Vec<KeePassEntry>> {
    let mut entries = Vec::new();

    // Simple XML parser for KeePass 2 format
    // Structure: <Root><Group><Name>Group Name</Name><Entry>...</Entry></Group></Root>
    let mut current_group: Option<String> = None;
    let mut in_entry = false;
    let mut current_title = String::new();
    let mut current_username = String::new();
    let mut current_password = String::new();
    let mut current_url = String::new();
    let mut current_notes = String::new();
    let mut current_created: Option<DateTime<Utc>> = None;
    let mut current_modified: Option<DateTime<Utc>> = None;

    for line in xml.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with("<!--") {
            continue;
        }

        // Track group name
        if let Some(start) = line.strip_prefix("<Name>") {
            if let Some(end) = start.find("</Name>") {
                let name = &start[..end];
                if !in_entry {
                    current_group = Some(name.to_string());
                }
            }
        }

        // Track entry boundaries
        if line.contains("<Entry>") {
            in_entry = true;
        } else if line.contains("</Entry>") {
            // Push completed entry
            if !current_title.is_empty() {
                let tags = if current_group.is_some() {
                    vec![current_group.clone().unwrap_or_default()]
                } else {
                    Vec::new()
                };

                entries.push(KeePassEntry {
                    title: current_title.clone(),
                    username: current_username.clone(),
                    password: current_password.clone(),
                    url: if current_url.is_empty() {
                        None
                    } else {
                        Some(current_url.clone())
                    },
                    notes: if current_notes.is_empty() {
                        None
                    } else {
                        Some(current_notes.clone())
                    },
                    tags: if tags.is_empty() { None } else { Some(tags) },
                    created_at: current_created,
                    modified_at: current_modified,
                });
            }

            // Reset for next entry
            current_title.clear();
            current_username.clear();
            current_password.clear();
            current_url.clear();
            current_notes.clear();
            current_created = None;
            current_modified = None;
            in_entry = false;
            continue;
        }

        if !in_entry {
            continue;
        }

        // Parse entry fields
        if let Some(start) = line.strip_prefix("<String>") {
            if let Some(end) = start.find("</String>") {
                // Check for Key inside this String element
                let content = &start[..end];
                if let Some(key_start) = content.find("<Key>") {
                    if let Some(key_end) = content[key_start + 5..].find("</Key>") {
                        let key = &content[key_start + 5..key_start + 5 + key_end];

                        // Find Value
                        if let Some(value_start) = content.find("<Value>") {
                            if let Some(value_end) = content[value_start + 7..].find("</Value>") {
                                let value = &content[value_start + 7..value_start + 7 + value_end];

                                match key {
                                    "Title" => current_title = value.to_string(),
                                    "UserName" => current_username = value.to_string(),
                                    "Password" => current_password = value.to_string(),
                                    "URL" => current_url = value.to_string(),
                                    "Notes" => current_notes = value.to_string(),
                                    _ => {} // Ignore other fields
                                }
                            }
                        }
                    }
                }
            }
        }

        // Parse times
        if let Some(start) = line.strip_prefix("<Times>") {
            // Look for times in the following lines
            if let Some(created_start) = start.find("<CreationTime>") {
                if let Some(created_end) = start[created_start + 15..].find("</CreationTime>") {
                    let created_str = &start[created_start + 15..created_start + 15 + created_end];
                    current_created = parse_datetime(created_str);
                }
            }
            if let Some(mod_start) = start.find("<LastModTime>") {
                if let Some(mod_end) = start[mod_start + 13..].find("</LastModTime>") {
                    let mod_str = &start[mod_start + 13..mod_start + 13 + mod_end];
                    current_modified = parse_datetime(mod_str);
                }
            }
        }
    }

    Ok(entries)
}

/// Parse ISO 8601 datetime string
fn parse_datetime(s: &str) -> Option<DateTime<Utc>> {
    // Try standard ISO 8601 format
    s.parse().ok()
}

/// Generate KeePass 2.x XML from entries
pub fn generate_keepass_xml(entries: &[KeePassEntry]) -> Result<String> {
    let mut xml = String::new();

    xml.push_str(r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>"#);
    xml.push('\n');
    xml.push_str(r#"<Root>"#);
    xml.push('\n');

    // Group all entries under "Imported" group
    xml.push_str("  <Group>\n");
    xml.push_str("    <Name>Imported</Name>\n");
    xml.push_str("    <Entry>\n");

    for entry in entries {
        xml.push_str("      <Entry>\n");

        // Title
        xml.push_str("        <String>\n");
        xml.push_str("          <Key>Title</Key>\n");
        xml.push_str(&format!(
            "          <Value>{}</Value>\n",
            escape_xml(&entry.title)
        ));
        xml.push_str("        </String>\n");

        // Username
        xml.push_str("        <String>\n");
        xml.push_str("          <Key>UserName</Key>\n");
        xml.push_str(&format!(
            "          <Value>{}</Value>\n",
            escape_xml(&entry.username)
        ));
        xml.push_str("        </String>\n");

        // Password
        xml.push_str("        <String>\n");
        xml.push_str("          <Key>Password</Key>\n");
        xml.push_str(&format!(
            "          <Value>{}</Value>\n",
            escape_xml(&entry.password)
        ));
        xml.push_str("        </String>\n");

        // URL
        if let Some(ref url) = entry.url {
            xml.push_str("        <String>\n");
            xml.push_str("          <Key>URL</Key>\n");
            xml.push_str(&format!("          <Value>{}</Value>\n", escape_xml(url)));
            xml.push_str("        </String>\n");
        }

        // Notes
        if let Some(ref notes) = entry.notes {
            xml.push_str("        <String>\n");
            xml.push_str("          <Key>Notes</Key>\n");
            xml.push_str(&format!("          <Value>{}</Value>\n", escape_xml(notes)));
            xml.push_str("        </String>\n");
        }

        // Times
        xml.push_str("        <Times>\n");
        if let Some(ref created) = entry.created_at {
            xml.push_str(&format!(
                "          <CreationTime>{}</CreationTime>\n",
                created.to_rfc3339()
            ));
        }
        if let Some(ref modified) = entry.modified_at {
            xml.push_str(&format!(
                "          <LastModTime>{}</LastModTime>\n",
                modified.to_rfc3339()
            ));
        }
        xml.push_str("        </Times>\n");

        xml.push_str("      </Entry>\n");
    }

    xml.push_str("    </Entry>\n");
    xml.push_str("  </Group>\n");
    xml.push_str("</Root>\n");

    Ok(xml)
}

/// Escape special XML characters
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_escape_xml() {
        assert_eq!(escape_xml("hello"), "hello");
        assert_eq!(escape_xml("a&b"), "a&amp;b");
        assert_eq!(escape_xml("a<b"), "a&lt;b");
        assert_eq!(escape_xml("a>b"), "a&gt;b");
        assert_eq!(escape_xml("a\"b"), "a&quot;b");
    }

    #[test]
    fn test_generate_keepass_xml() {
        let entries = vec![KeePassEntry {
            title: "Test Entry".to_string(),
            username: "user@example.com".to_string(),
            password: "password123".to_string(),
            url: Some("https://example.com".to_string()),
            notes: Some("Test notes".to_string()),
            tags: Some(vec!["work".to_string()]),
            created_at: Some(Utc::now()),
            modified_at: Some(Utc::now()),
        }];

        let xml = generate_keepass_xml(&entries).unwrap();
        assert!(xml.contains("<Key>Title</Key>"));
        assert!(xml.contains("<Value>Test Entry</Value>"));
        assert!(xml.contains("<Key>Password</Key>"));
        assert!(xml.contains("<Value>password123</Value>"));
    }

    #[test]
    fn test_parse_datetime() {
        let dt_str = "2024-01-15T10:30:00Z";
        let parsed = parse_datetime(dt_str);
        assert!(parsed.is_some());
    }
}

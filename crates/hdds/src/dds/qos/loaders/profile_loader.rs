// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Unified profile loader with format auto-detection.
//!
//! Automatically detects file format (XML or YAML) and loads QoS profiles.

use crate::dds::qos::QoS;
use std::path::Path;

use super::fastdds::FastDdsLoader;
use super::yaml::YamlLoader;

/// Supported configuration file formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    /// XML format (FastDDS, RTI, Cyclone DDS)
    Xml,
    /// YAML format (HDDS native)
    Yaml,
}

impl ConfigFormat {
    /// Detect format from file extension.
    pub fn from_extension(path: &Path) -> Option<Self> {
        match path.extension().and_then(|e| e.to_str()) {
            Some("xml") => Some(ConfigFormat::Xml),
            Some("yaml") | Some("yml") => Some(ConfigFormat::Yaml),
            _ => None,
        }
    }

    /// Detect format from file content.
    pub fn from_content(content: &str) -> Option<Self> {
        let trimmed = content.trim();
        if trimmed.starts_with("<?xml") || trimmed.starts_with('<') {
            Some(ConfigFormat::Xml)
        } else if trimmed.starts_with("profiles:")
            || trimmed.starts_with("default_profile:")
            || trimmed.contains("\nprofiles:")
        {
            Some(ConfigFormat::Yaml)
        } else {
            None
        }
    }
}

/// Unified profile loader with auto-detection.
pub struct ProfileLoader;

impl ProfileLoader {
    /// Load QoS from file with format auto-detection.
    ///
    /// Format is detected from file extension (.xml, .yaml, .yml).
    /// Falls back to content-based detection if extension is unrecognized.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to configuration file
    /// * `profile_name` - Optional profile name (uses default if None)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use hdds::dds::qos::loaders::ProfileLoader;
    ///
    /// // Load from YAML file
    /// let qos = ProfileLoader::load("config.yaml", Some("reliable"))?;
    ///
    /// // Load default profile from XML
    /// let qos = ProfileLoader::load("fastdds_profiles.xml", None)?;
    /// ```
    pub fn load<P: AsRef<Path>>(path: P, profile_name: Option<&str>) -> Result<QoS, String> {
        crate::trace_fn!("ProfileLoader::load");
        let path = path.as_ref();

        // Try extension-based detection first
        let format = ConfigFormat::from_extension(path)
            .or_else(|| {
                // Fall back to content-based detection
                std::fs::read_to_string(path)
                    .ok()
                    .and_then(|content| ConfigFormat::from_content(&content))
            })
            .ok_or_else(|| {
                format!(
                    "Unable to detect config format for '{}'. Use .xml, .yaml, or .yml extension.",
                    path.display()
                )
            })?;

        match format {
            ConfigFormat::Xml => {
                // For XML, we currently only support FastDDS format
                // profile_name is ignored (uses default profile in XML)
                FastDdsLoader::load_from_file(path)
            }
            ConfigFormat::Yaml => YamlLoader::load_qos(path, profile_name),
        }
    }

    /// Load QoS from string content with explicit format.
    pub fn load_from_str(
        content: &str,
        format: ConfigFormat,
        profile_name: Option<&str>,
    ) -> Result<QoS, String> {
        match format {
            ConfigFormat::Xml => FastDdsLoader::parse_xml(content),
            ConfigFormat::Yaml => {
                let doc = YamlLoader::parse_yaml(content)?;
                match profile_name {
                    Some(name) => YamlLoader::get_profile(&doc, name),
                    None => YamlLoader::get_default_profile(&doc),
                }
            }
        }
    }

    /// Load QoS from string content with format auto-detection.
    pub fn load_from_str_auto(content: &str, profile_name: Option<&str>) -> Result<QoS, String> {
        let format = ConfigFormat::from_content(content)
            .ok_or("Unable to detect config format from content")?;
        Self::load_from_str(content, format, profile_name)
    }

    /// Check if a file path appears to be a supported config file.
    pub fn is_config_file<P: AsRef<Path>>(path: P) -> bool {
        ConfigFormat::from_extension(path.as_ref()).is_some()
    }

    /// Get the detected format for a file path.
    pub fn detect_format<P: AsRef<Path>>(path: P) -> Option<ConfigFormat> {
        ConfigFormat::from_extension(path.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dds::qos::{Durability, History, Reliability};

    #[test]
    fn test_format_detection_by_extension() {
        assert_eq!(
            ConfigFormat::from_extension(Path::new("config.xml")),
            Some(ConfigFormat::Xml)
        );
        assert_eq!(
            ConfigFormat::from_extension(Path::new("config.yaml")),
            Some(ConfigFormat::Yaml)
        );
        assert_eq!(
            ConfigFormat::from_extension(Path::new("config.yml")),
            Some(ConfigFormat::Yaml)
        );
        assert_eq!(ConfigFormat::from_extension(Path::new("config.json")), None);
        assert_eq!(ConfigFormat::from_extension(Path::new("config")), None);
    }

    #[test]
    fn test_format_detection_by_content() {
        // XML detection
        assert_eq!(
            ConfigFormat::from_content("<?xml version=\"1.0\"?><root></root>"),
            Some(ConfigFormat::Xml)
        );
        assert_eq!(
            ConfigFormat::from_content("<dds><profiles></profiles></dds>"),
            Some(ConfigFormat::Xml)
        );

        // YAML detection
        assert_eq!(
            ConfigFormat::from_content("profiles:\n  test:\n    reliability: RELIABLE"),
            Some(ConfigFormat::Yaml)
        );
        assert_eq!(
            ConfigFormat::from_content("default_profile: test\nprofiles: {}"),
            Some(ConfigFormat::Yaml)
        );

        // Unknown
        assert_eq!(ConfigFormat::from_content("some random text"), None);
    }

    #[test]
    fn test_load_from_yaml_str() {
        let yaml = r#"
profiles:
  test:
    reliability: RELIABLE
    durability: TRANSIENT_LOCAL
    history:
      kind: KEEP_LAST
      depth: 50
"#;

        let qos = ProfileLoader::load_from_str(yaml, ConfigFormat::Yaml, Some("test"))
            .expect("should parse YAML");

        assert!(matches!(qos.reliability, Reliability::Reliable));
        assert!(matches!(qos.durability, Durability::TransientLocal));
        assert!(matches!(qos.history, History::KeepLast(50)));
    }

    #[test]
    fn test_load_from_xml_str() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns="http://www.eprosima.com/XMLSchemas/fastRTPS_Profiles">
  <profiles>
    <data_writer profile_name="test" is_default_profile="true">
      <qos>
        <reliability><kind>RELIABLE</kind></reliability>
        <durability><kind>VOLATILE</kind></durability>
      </qos>
    </data_writer>
  </profiles>
</dds>"#;

        let qos =
            ProfileLoader::load_from_str(xml, ConfigFormat::Xml, None).expect("should parse XML");

        assert!(matches!(qos.reliability, Reliability::Reliable));
        assert!(matches!(qos.durability, Durability::Volatile));
    }

    #[test]
    fn test_load_from_str_auto() {
        // Auto-detect YAML
        let yaml = r#"profiles:
  auto:
    reliability: BEST_EFFORT
"#;
        let qos = ProfileLoader::load_from_str_auto(yaml, Some("auto")).expect("auto YAML");
        assert!(matches!(qos.reliability, Reliability::BestEffort));

        // Auto-detect XML
        let xml = r#"<?xml version="1.0"?>
<dds>
  <profiles>
    <data_writer profile_name="x" is_default_profile="true">
      <qos><reliability><kind>RELIABLE</kind></reliability></qos>
    </data_writer>
  </profiles>
</dds>"#;
        let qos = ProfileLoader::load_from_str_auto(xml, None).expect("auto XML");
        assert!(matches!(qos.reliability, Reliability::Reliable));
    }

    #[test]
    fn test_is_config_file() {
        assert!(ProfileLoader::is_config_file("test.xml"));
        assert!(ProfileLoader::is_config_file("test.yaml"));
        assert!(ProfileLoader::is_config_file("test.yml"));
        assert!(!ProfileLoader::is_config_file("test.json"));
        assert!(!ProfileLoader::is_config_file("test.txt"));
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
//
// QoS Validator Generator
//
// Generates 48 QoS XML profiles + 96 test scripts from:
// - config.yaml (policy definitions)
// - baseline.xml (template)
// - test_script.sh.j2 (template)

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tera::Tera;

/// Policy variant definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVariant {
    pub name: String,
    pub values: HashMap<String, serde_yaml::Value>,
    pub description: Option<String>,
}

/// Single QoS policy definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosPolicy {
    pub id: usize,
    pub name: String,
    pub category: String,
    pub description: Option<String>,
    pub xml_path: Vec<String>,
    pub scope: Vec<String>,
    pub variants: Vec<PolicyVariant>,
}

/// Complete configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosValidatorConfig {
    pub policies: Vec<QosPolicy>,
    pub generator: GeneratorConfig,
    pub baseline_config: BaselineConfig,
    pub test_config: TestConfig,
    pub metadata: Metadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratorConfig {
    pub output_dirs: HashMap<String, String>,
    pub baseline_template: String,
    pub test_script_template: String,
    pub shared_utilities: Vec<String>,
    pub manifest_output: String,
    pub agent_snippet_output: String,
    pub makefile_snippet_output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineConfig {
    pub transport: String,
    pub topic_name: String,
    pub data_type: String,
    pub defaults: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestConfig {
    pub subscriber_timeout: u32,
    pub publisher_timeout: u32,
    pub discovery_delay: u32,
    pub network: HashMap<String, String>,
    pub remote: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub version: String,
    pub created_date: String,
    pub description: String,
}

/// Generator state
pub struct QosGenerator {
    config: QosValidatorConfig,
    base_dir: PathBuf,
    tera: Tera,
}

impl QosGenerator {
    /// Load configuration and initialize generator
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        let config_path = base_dir.join("interop/validator/generator/config.yaml");

        tracing::info!("Loading config from: {:?}", config_path);
        let config_content =
            fs::read_to_string(&config_path).context("Failed to read config.yaml")?;
        let config: QosValidatorConfig =
            serde_yaml::from_str(&config_content).context("Failed to parse config.yaml")?;

        // Initialize Tera template engine
        let mut tera = Tera::default();

        // Load baseline.xml template
        let baseline_path = base_dir.join(&config.generator.baseline_template);
        tracing::info!("Loading baseline template: {:?}", baseline_path);
        let baseline_content =
            fs::read_to_string(&baseline_path).context("Failed to read baseline.xml")?;
        tera.add_raw_template("baseline", &baseline_content)
            .context("Failed to parse baseline.xml template")?;

        // Load test_script.sh.j2 template
        let test_template_path = base_dir.join(&config.generator.test_script_template);
        tracing::info!("Loading test script template: {:?}", test_template_path);
        let test_template_content =
            fs::read_to_string(&test_template_path).context("Failed to read test_script.sh.j2")?;
        tera.add_raw_template("test_script", &test_template_content)
            .context("Failed to parse test_script.sh.j2 template")?;

        Ok(Self {
            config,
            base_dir,
            tera,
        })
    }

    /// Generate all artifacts (48 QoS + 96 scripts + manifest + snippets)
    pub fn generate(&self) -> Result<GenerationReport> {
        tracing::info!("Starting QoS validator generation");

        let mut report = GenerationReport::new();

        // Stage 1: Generate QoS profiles
        tracing::info!("Stage 1: Generating QoS XML profiles");
        self.generate_qos_profiles(&mut report)?;

        // Stage 2: Generate test scripts
        tracing::info!("Stage 2: Generating test scripts");
        self.generate_test_scripts(&mut report)?;

        // Stage 3: Generate manifest
        tracing::info!("Stage 3: Generating manifest");
        self.generate_manifest(&report)?;

        // Stage 4: Generate integration snippets
        tracing::info!("Stage 4: Generating integration snippets");
        self.generate_agent_snippet(&report)?;
        self.generate_makefile_snippet(&report)?;

        tracing::info!("[OK] Generation complete");
        Ok(report)
    }

    /// Generate 48 QoS XML profiles
    fn generate_qos_profiles(&self, report: &mut GenerationReport) -> Result<()> {
        let output_dir = self.base_dir.join("interop/validator/qos");
        fs::create_dir_all(&output_dir).context("Failed to create qos directory")?;

        for policy in &self.config.policies {
            for variant in &policy.variants {
                let filename =
                    format!("policy_{:03}_{}_{}", policy.id, policy.name, variant.name) + ".xml";
                let filepath = output_dir.join(&filename);

                // Build context for template rendering
                let mut ctx = tera::Context::new();
                ctx.insert("policy_id", &format!("{:03}", policy.id));
                ctx.insert("policy_name", &policy.name);
                ctx.insert("variant_name", &variant.name);

                // Render baseline template
                let mut rendered = self
                    .tera
                    .render("baseline", &ctx)
                    .context(format!("Failed to render baseline for {}", policy.name))?;

                // Apply variant-specific XML overrides
                rendered = self
                    .apply_variant_overrides(&rendered, policy, variant)
                    .context(format!(
                        "Failed to apply overrides for policy {}",
                        policy.id
                    ))?;

                fs::write(&filepath, &rendered).context(format!("Failed to write {}", filename))?;

                report.qos_files_generated.push(filename);
            }
        }

        tracing::info!(
            "[OK] Generated {} QoS profiles",
            report.qos_files_generated.len()
        );
        Ok(())
    }

    /// Apply variant-specific XML value overrides to baseline XML
    fn apply_variant_overrides(
        &self,
        baseline_xml: &str,
        _policy: &QosPolicy,
        variant: &PolicyVariant,
    ) -> Result<String> {
        let mut result = baseline_xml.to_string();

        // Apply each variant value to the XML
        // The xml_path format is "parent/child" (e.g., "reliability/kind")
        for (xml_path, override_value) in &variant.values {
            // Convert YAML value to string
            let value_str = match override_value {
                serde_yaml::Value::String(s) => s.clone(),
                serde_yaml::Value::Number(n) => n.to_string(),
                serde_yaml::Value::Bool(b) => if *b { "TRUE" } else { "FALSE" }.to_string(),
                _ => continue,
            };

            // Split path into parent and child
            let parts: Vec<&str> = xml_path.split('/').collect();
            if parts.len() < 2 {
                continue; // Need at least parent/child
            }

            let parent_elem = parts[parts.len() - 2];
            let child_elem = parts[parts.len() - 1];

            // Build a regex pattern that matches <parent>...<child>...</child>...</parent>
            // Using [\s\S]*? for non-greedy multiline matching
            let pattern = format!(
                "<{}>[\\s\\S]*?<{}>[^<]*</{}>",
                regex::escape(parent_elem),
                regex::escape(child_elem),
                regex::escape(child_elem)
            );

            if let Ok(re) = Regex::new(&pattern) {
                // Build replacement that preserves the parent element
                let replacement = format!(
                    "<{}><{}>{}</{}>",
                    parent_elem, child_elem, value_str, child_elem
                );

                result = re.replace_all(&result, &replacement).to_string();
            }
        }

        Ok(result)
    }

    /// Generate 96 test scripts (48 variants x 2 directions)
    fn generate_test_scripts(&self, report: &mut GenerationReport) -> Result<()> {
        let output_dir = self.base_dir.join("interop/validator/scripts");
        fs::create_dir_all(&output_dir).context("Failed to create scripts directory")?;

        let directions = vec![("fd2hd", "FastDDS to HDDS"), ("hd2fd", "HDDS to FastDDS")];

        for policy in &self.config.policies {
            for variant in &policy.variants {
                for (dir, dir_label) in &directions {
                    let filename = format!(
                        "policy_{:03}_{}_{}_{}",
                        policy.id, policy.name, variant.name, dir
                    ) + ".sh";
                    let filepath = output_dir.join(&filename);

                    let qos_filename = format!(
                        "policy_{:03}_{}_{}.xml",
                        policy.id, policy.name, variant.name
                    );

                    // Build context for test script template
                    let mut ctx = tera::Context::new();
                    ctx.insert("policy_id", &format!("{:03}", policy.id));
                    ctx.insert("policy_name", &policy.name);
                    ctx.insert("policy_category", &policy.category);
                    ctx.insert("variant_name", &variant.name);
                    ctx.insert(
                        "variant_description",
                        &variant.description.as_ref().unwrap_or(&"".to_string()),
                    );
                    ctx.insert("direction", dir);
                    ctx.insert("direction_label", dir_label);
                    ctx.insert(
                        "profile_name",
                        &format!("policy_{:03}_{}_{}", policy.id, policy.name, variant.name),
                    );
                    ctx.insert("qos_file", &qos_filename);

                    let rendered = match self.tera.render("test_script", &ctx) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("Tera error: {}", e);
                            eprintln!("Context: policy_id={}, direction={}", policy.id, dir);
                            Err(e).context(format!(
                                "Failed to render test script for policy {} variant {}",
                                policy.id, variant.name
                            ))?
                        }
                    };

                    fs::write(&filepath, &rendered)
                        .context(format!("Failed to write {}", filename))?;

                    // Make executable
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let perms = fs::Permissions::from_mode(0o755);
                        fs::set_permissions(&filepath, perms)
                            .context(format!("Failed to chmod {}", filename))?;
                    }

                    report.test_scripts_generated.push(filename);
                }
            }
        }

        tracing::info!(
            "[OK] Generated {} test scripts",
            report.test_scripts_generated.len()
        );
        Ok(())
    }

    /// Generate manifest.json
    fn generate_manifest(&self, report: &GenerationReport) -> Result<()> {
        let output_dir = self.base_dir.join("interop/validator/generator/output");
        fs::create_dir_all(&output_dir).context("Failed to create output directory")?;

        let manifest = serde_json::json!({
            "generated_date": chrono::Local::now().to_rfc3339(),
            "qos_profiles": report.qos_files_generated,
            "test_scripts": report.test_scripts_generated,
            "total_tests": report.test_scripts_generated.len(),
            "policies_count": self.config.policies.len(),
            "variants_count": report.qos_files_generated.len(),
        });

        let manifest_path = output_dir.join("manifest.json");
        fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)
            .context("Failed to write manifest.json")?;

        tracing::info!("[OK] Generated manifest.json");
        Ok(())
    }

    /// Generate agent_watch.sh snippet
    fn generate_agent_snippet(&self, _report: &GenerationReport) -> Result<()> {
        let output_dir = self.base_dir.join("interop/validator/generator/output");
        fs::create_dir_all(&output_dir).context("Failed to create output directory")?;

        let mut snippet =
            String::from("# Auto-generated agent cases (append to agent_watch.sh)\n\n");

        let directions = vec!["fd2hd", "hd2fd"];
        for policy in &self.config.policies {
            for variant in &policy.variants {
                for dir in &directions {
                    let task_name = format!(
                        "validator_policy_{:03}_{}_{}_{}",
                        policy.id, policy.name, variant.name, dir
                    );
                    let script_name = format!(
                        "policy_{:03}_{}_{}_{}.sh",
                        policy.id, policy.name, variant.name, dir
                    );

                    snippet.push_str(&format!(
                        "    {}) \n        bash {}\n        ;;\n\n",
                        task_name, script_name
                    ));
                }
            }
        }

        let snippet_path = output_dir.join("agent_watch_snippet.sh");
        fs::write(&snippet_path, snippet).context("Failed to write agent_watch_snippet.sh")?;

        tracing::info!("[OK] Generated agent_watch_snippet.sh");
        Ok(())
    }

    /// Generate Makefile snippet
    fn generate_makefile_snippet(&self, _report: &GenerationReport) -> Result<()> {
        let output_dir = self.base_dir.join("interop/validator/generator/output");
        fs::create_dir_all(&output_dir).context("Failed to create output directory")?;

        let mut snippet =
            String::from("# Auto-generated Makefile targets (append to Makefile)\n\n");

        let directions = vec!["fd2hd", "hd2fd"];
        for policy in &self.config.policies {
            for variant in &policy.variants {
                for dir in &directions {
                    let target_name = format!(
                        "run-validator-policy-{:03}-{}-{}-{}",
                        policy.id,
                        policy.name.replace("_", "-"),
                        variant.name.replace("_", "-"),
                        dir
                    );
                    let task_name = format!(
                        "validator_policy_{:03}_{}_{}_{}",
                        policy.id, policy.name, variant.name, dir
                    );

                    snippet.push_str(&format!(
                        "{}:\n\t@printf 'TASK={}\\n' > agent_triggers/run\n\n",
                        target_name, task_name
                    ));
                }
            }
        }

        let snippet_path = output_dir.join("makefile_snippet.mk");
        fs::write(&snippet_path, snippet).context("Failed to write makefile_snippet.mk")?;

        tracing::info!("[OK] Generated makefile_snippet.mk");
        Ok(())
    }
}

/// Generation report
#[derive(Default)]
pub struct GenerationReport {
    pub qos_files_generated: Vec<String>,
    pub test_scripts_generated: Vec<String>,
}

impl GenerationReport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn summary(&self) {
        println!("\n{}", "=".repeat(60));
        println!("  QoS Validator Generation Report");
        println!("{}", "=".repeat(60));
        println!();
        println!(
            "  [OK] QoS Profiles:    {} files",
            self.qos_files_generated.len()
        );
        println!(
            "  [OK] Test Scripts:    {} files",
            self.test_scripts_generated.len()
        );
        println!(
            "  [OK] Total Tests:     {} (variants x 2 directions)",
            self.test_scripts_generated.len() / 2
        );
        println!();
        println!("  Generated in:");
        println!("    - <base_dir>/interop/validator/qos/");
        println!("    - <base_dir>/interop/validator/scripts/");
        println!("    - <base_dir>/interop/validator/generator/output/");
        println!();
        println!("{}", "=".repeat(60));
    }
}

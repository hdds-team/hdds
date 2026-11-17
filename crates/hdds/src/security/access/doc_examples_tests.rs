// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Every governance example we publish, parsed FROM THE FILE THAT PUBLISHES IT.
//!
//! The tests next to the parser carry their documents as string literals. That
//! proves the parser accepts those bytes; it proves nothing about whether the
//! documentation still contains them. A published example that nothing ever
//! executes can be refused by the parser without anybody noticing, and
//! hand-checking only stays accurate until the next edit.
//!
//! So this module goes the other way: it walks the published files, pulls out
//! whatever governance document each one actually contains today, and feeds it
//! to the real parser. An example edited into an invalid shape fails here, and
//! an example DELETED fails here too, which a literal copy can never notice.
//!
//! Files are read at run time rather than through `include_str!` on purpose: a
//! packaged crate may not ship `docs/` or `sdk/`, and a missing file has to be
//! a visible skip rather than a build failure. The count of what was checked
//! is printed for the same reason the cast oracle prints what it cleared -
//! "nothing failed" and "nothing ran" must not look alike.

use super::permissions::GovernanceConfig;
use std::path::{Path, PathBuf};

/// The repository root, derived from this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .to_path_buf()
}

/// Every published file that carries a governance document, and how the
/// document is spelled inside it.
///
/// A source file prints its document line by line, so the XML is wrapped in
/// `println!`/`printf`/`print` calls and string quoting. Markdown and shell
/// carry it plainly. Rather than write a parser per language, we pull out
/// everything between the first `<domain_rule` and the matching
/// `</domain_rule>`, then strip the surrounding noise line by line.
const PUBLISHED_EXAMPLES: &[&str] = &[
    "docs/security-guide.md",
    "docs/guides/security/access-control.md",
    "sdk/samples/05_security/README.md",
    "sdk/samples/05_security/certs/generate_certs.sh",
    "sdk/samples/05_security/rust/src/bin/access_control.rs",
    "sdk/samples/05_security/rust/src/bin/secure_discovery.rs",
    "sdk/samples/05_security/c/access_control.c",
    "sdk/samples/05_security/c/secure_discovery.c",
    "sdk/samples/05_security/cpp/access_control.cpp",
    "sdk/samples/05_security/cpp/secure_discovery.cpp",
    "sdk/samples/05_security/python/access_control.py",
    "sdk/samples/05_security/python/secure_discovery.py",
];

/// Pull every `<domain_rule>...</domain_rule>` block out of a published file
/// and rebuild it as XML the parser can read.
fn extract_domain_rules(text: &str) -> Vec<String> {
    let mut rules = Vec::new();
    let mut current: Option<Vec<String>> = None;

    for raw in text.lines() {
        let line = strip_host_language(raw);
        let trimmed = line.trim();

        if trimmed.starts_with("<domain_rule") {
            current = Some(vec![trimmed.to_string()]);
            continue;
        }
        if let Some(block) = current.as_mut() {
            block.push(trimmed.to_string());
            if trimmed.starts_with("</domain_rule") {
                rules.push(block.join("\n"));
                current = None;
            }
        }
    }
    rules
}

/// Strip the host language around an XML line.
///
/// `println!("      <domains>0</domains>");`, `printf("  <x/>\n");`,
/// `print("  <x/>")` and `std::cout << "  <x/>\n";` all wrap the same XML.
///
/// A STRING LITERAL is tried first, and that ordering is the whole of the
/// function's correctness. Reaching for the first `<` instead works for three
/// of those four and is defeated by the fourth: C++ stream insertion puts `<<`
/// before the quote, so the extractor grabbed `<< "    <domain_rule>` and
/// found no rule at all. The test caught it on its first run, which is the
/// argument for this module in one line - the previous check was a person
/// comparing files by eye, and a person does not notice the two C++ samples
/// going quiet.
fn strip_host_language(line: &str) -> String {
    if let (Some(open), Some(close)) = (line.find('"'), line.rfind('"')) {
        if close > open {
            let literal = &line[open + 1..close];
            if literal.contains('<') {
                // Printed line endings are part of the host language, not the
                // document.
                return literal.replace("\\n", "");
            }
        }
    }
    match (line.find('<'), line.rfind('>')) {
        (Some(start), Some(end)) if end > start => line[start..=end].to_string(),
        _ => line.to_string(),
    }
}

#[test]
#[cfg(feature = "qos-loaders")]
fn every_published_governance_example_still_parses() {
    let root = repo_root();
    let mut checked = 0usize;
    let mut skipped = Vec::new();
    let mut failures = Vec::new();

    for relative in PUBLISHED_EXAMPLES {
        let path = root.join(relative);
        let Ok(text) = std::fs::read_to_string(&path) else {
            skipped.push(*relative);
            continue;
        };

        let rules = extract_domain_rules(&text);
        if rules.is_empty() {
            // The file is in the list because it publishes a governance
            // example. If it no longer contains one, either the example was
            // deleted or its shape changed enough that this extractor no
            // longer recognises it. Both are worth a red test: a list that
            // silently covers nothing is the failure mode this module exists
            // to prevent.
            failures.push(format!(
                "{}: no <domain_rule> found, but this file is listed as publishing one",
                relative
            ));
            continue;
        }

        for (index, rule) in rules.iter().enumerate() {
            let document = format!(
                "<?xml version=\"1.0\"?>\n<governance>\n{}\n</governance>",
                rule
            );
            match GovernanceConfig::parse(&document) {
                Ok(config) => {
                    assert_eq!(
                        config.domain_rules.len(),
                        1,
                        "{} rule {}: one rule in, one rule out",
                        relative,
                        index
                    );
                    checked += 1;
                }
                Err(e) => failures.push(format!(
                    "{} rule {}: {}\n--- the document this file publishes ---\n{}",
                    relative, index, e, document
                )),
            }
        }
    }

    // Say what ran, so "nothing failed" cannot be confused with "nothing ran".
    println!(
        "checked {} governance rule(s) across {} published file(s); skipped {:?}",
        checked,
        PUBLISHED_EXAMPLES.len() - skipped.len(),
        skipped
    );

    assert!(
        failures.is_empty(),
        "a governance document we publish is not one this release accepts:\n\n{}",
        failures.join("\n\n")
    );

    // A run that found nothing has proven nothing. If every file was missing,
    // this is a packaged crate without its docs, which is legitimate - but it
    // must not read as a pass.
    if skipped.len() == PUBLISHED_EXAMPLES.len() {
        println!(
            "no published example was readable from {:?}; nothing was checked",
            root
        );
        return;
    }
    assert!(
        checked > 0,
        "the published files were readable but no governance rule was extracted from any of them"
    );
}

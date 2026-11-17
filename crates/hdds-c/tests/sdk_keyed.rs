// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Run with scripts/test-sdk-keyed.sh: a generated Python writer reaches a
//! typed Rust reader over UDP. DDS 1.4 2.2.3.18 keeps KEEP_LAST per instance;
//! 2.2.2.4.2 and 2.2.2.5.1 preserve lifecycle identity. ENCRYPT recovers
//! identity from the authenticated key payload (DDS-Security 1.1 7.3.4).

use hdds::dds::{InstanceHandle, InstanceState};
use hdds::test_support::domains::{unique_domain, DomainLease};
use hdds::{DdsTrait, Participant, QoS};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, hdds::DDS)]
#[dds(final)]
struct Keyed {
    #[key]
    tag: u8,
    #[key]
    id: i64,
    value: i32,
}

struct WriterProcess(Child);
impl Drop for WriterProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn domain() -> DomainLease {
    let mut other = Vec::new();
    loop {
        let lease = unique_domain();
        if (200..=230).contains(&lease.id()) {
            return lease;
        }
        other.push(lease);
    }
}

fn run(encrypt: bool, backend: &str, mode: &str) {
    eprintln!("SDK constructor scenario: {backend}/{mode}, encrypt={encrypt}");
    let lease = domain();
    let builder = Participant::builder("rust_keyed_reader").domain_id(lease.id());
    #[cfg(feature = "security")]
    let (builder, _pki) = if encrypt {
        use rcgen::{
            BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
            KeyUsagePurpose,
        };
        let dir = std::path::PathBuf::from(
            std::env::var_os("HDDS_KEYED_WORK").expect("test work directory"),
        )
        .join(format!("pki-{}", lease.id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "DDS keyed SDK test");
        params.distinguished_name = dn;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
        std::fs::write(dir.join("ca.pem"), ca.pem()).unwrap();
        std::fs::write(dir.join("id.pem"), cert.pem()).unwrap();
        std::fs::write(dir.join("key.pem"), key.serialize_pem()).unwrap();
        let security = hdds::SecurityConfig::builder()
            .identity_certificate(dir.join("id.pem"))
            .private_key(dir.join("key.pem"))
            .ca_certificates(dir.join("ca.pem"))
            .enable_encryption(true)
            .build()
            .unwrap();
        (builder.with_security(security), Some(dir))
    } else {
        (builder, None)
    };
    let participant = builder.build().unwrap();
    let reader = participant
        .create_reader_with_type::<Keyed>(
            "sdk_key_identity",
            QoS::reliable().keep_last(1).data_representation_xcdr2(),
            if mode.starts_with("scoped") {
                "m::T"
            } else if backend == "cpp" {
                "RawBytes"
            } else {
                "Keyed"
            },
            None,
        )
        .unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut command = if backend == "python" {
        let mut command = Command::new("python3");
        command.arg(root.join("crates/hdds-c/tests/fixtures/sdk_keyed_writer.py"));
        command.env("PYTHONPATH", root.join("sdk/python"));
        command
    } else if backend == "c" {
        Command::new(std::env::var_os("HDDS_KEYED_C").expect("C SDK writer executable"))
    } else {
        Command::new(std::env::var_os("HDDS_KEYED_CPP").expect("C++ SDK writer executable"))
    };
    command
        .arg(lease.id().to_string())
        .arg(if encrypt { "encrypt" } else { "clear" })
        .arg(mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    #[cfg(feature = "security")]
    if let Some(dir) = &_pki {
        command.env("HDDS_KEYED_PKI", dir);
    }
    let mut child = WriterProcess(command.spawn().unwrap());
    let stdout = child.0.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let output = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if tx.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    assert_eq!(rx.recv_timeout(Duration::from_secs(60)).unwrap(), "WRITTEN");
    let mut seen = Vec::new();
    while let Some((sample, info)) = reader.take_with_info().unwrap() {
        let sample = sample.expect("only data before dispose");
        assert_eq!(
            info.instance_handle,
            InstanceHandle::new(sample.compute_key())
        );
        assert_eq!(sample.value, 20, "KEEP_LAST(1) is per instance");
        seen.push(sample.id);
    }
    seen.sort_unstable();
    assert_eq!(seen, [1, 2, 3]);
    let lifecycle = mode != "legacy" && mode != "oldcodec";
    for (operation, response, id) in [
        ("dispose", "DISPOSED", 2),
        ("unregister", "UNREGISTERED", 3),
    ]
    .into_iter()
    .filter(|_| lifecycle)
    {
        writeln!(child.0.stdin.as_mut().unwrap(), "{operation}").unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(30)).unwrap(), response);
        let (sample, info) = reader
            .take_with_info()
            .unwrap()
            .expect("instance transition");
        assert!(sample.is_none());
        assert_eq!(info.instance_state, InstanceState::NotAliveDisposed);
        assert_eq!(
            info.instance_handle,
            InstanceHandle::new(
                Keyed {
                    tag: 1,
                    id,
                    value: 0
                }
                .compute_key()
            )
        );
        assert!(
            reader.take_with_info().unwrap().is_none(),
            "only the selected instance changes"
        );
    }
    writeln!(child.0.stdin.as_mut().unwrap(), "quit").unwrap();
    assert!(child.0.wait().unwrap().success());
    output.join().unwrap();
}

#[test]
#[ignore = "requires generated codec and cdylib; run scripts/test-sdk-keyed.sh"]
fn generated_python_keeps_three_instances_and_their_lifecycle() {
    run(false, "python", "typed");
}

#[cfg(feature = "security")]
#[test]
#[ignore = "requires generated codec and cdylib; run scripts/test-sdk-keyed.sh"]
fn generated_python_keeps_three_instances_and_their_lifecycle_under_encrypt() {
    run(true, "python", "typed");
}

#[test]
#[ignore = "requires SDK codecs and binaries; run scripts/test-sdk-keyed.sh"]
fn sdk_constructors_preserve_legacy_typed_and_scoped_writes() {
    for mode in ["scoped", "scoped_publisher"] {
        run(false, "c", mode);
    }
    for backend in ["python", "cpp"] {
        for mode in ["legacy", "oldcodec", "bytes", "scoped"] {
            run(false, backend, mode);
        }
    }
}

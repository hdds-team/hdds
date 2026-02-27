// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Dynamic Data
//!
//! Demonstrates **runtime type manipulation** - working with data types that
//! are defined and discovered at runtime rather than compile time.
//!
//! ## Static vs Dynamic Types
//!
//! ```text
//! Static Types (compile-time):        Dynamic Types (runtime):
//! ┌────────────────────────────┐     ┌────────────────────────────┐
//! │ struct SensorData {        │     │ DynamicType::new("Sensor") │
//! │   sensor_id: u32,          │     │   .add("sensor_id", Int32) │
//! │   temperature: f64,        │     │   .add("temperature", F64) │
//! │ }                          │     │                            │
//! │                            │     │ // Type discovered from    │
//! │ // Must know type at       │     │ // data or schema          │
//! │ // compile time            │     │                            │
//! └────────────────────────────┘     └────────────────────────────┘
//! ```
//!
//! ## Dynamic Data Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                         DynamicType                                 │
//! │  ┌─────────────────────────────────────────────────────────────┐   │
//! │  │ name: "SensorReading"                                       │   │
//! │  │ members:                                                    │   │
//! │  │   [0] sensor_id: Int32 @key                                 │   │
//! │  │   [1] location: String                                      │   │
//! │  │   [2] temperature: Float64                                  │   │
//! │  │   [3] humidity: Float64                                     │   │
//! │  └─────────────────────────────────────────────────────────────┘   │
//! │                              │                                     │
//! │                              ▼                                     │
//! │                         DynamicData                                │
//! │  ┌─────────────────────────────────────────────────────────────┐   │
//! │  │ values: {                                                   │   │
//! │  │   "sensor_id" → Int32(100)                                  │   │
//! │  │   "location" → String("Room-1")                             │   │
//! │  │   "temperature" → Float64(23.5)                             │   │
//! │  │ }                                                           │   │
//! │  └─────────────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Use Cases
//!
//! - **Data recording**: Generic recorder that handles any type
//! - **Protocol bridges**: DDS ↔ REST/MQTT without type knowledge
//! - **Debugging tools**: Inspect data without compiled types
//! - **Data visualization**: Display any DDS topic dynamically
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber (discovers type at runtime)
//! cargo run --bin dynamic_data
//!
//! # Terminal 2 - Publisher (creates type dynamically)
//! cargo run --bin dynamic_data -- pub
//! ```
//!
//! **NOTE: CONCEPT DEMO** - This sample demonstrates the APPLICATION PATTERN for DynamicData/DynamicType.
//! The native DynamicData/DynamicType API is not yet exported to the SDK.
//! This sample uses standard participant/writer/reader API to show the concept.

use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Type kinds supported by dynamic data
#[derive(Debug, Clone, Copy, PartialEq)]
enum TypeKind {
    Int32,
    Int64,
    Float32,
    Float64,
    Bool,
    String,
    Struct,
}

fn type_kind_str(kind: TypeKind) -> &'static str {
    match kind {
        TypeKind::Int32 => "int32",
        TypeKind::Int64 => "int64",
        TypeKind::Float32 => "float32",
        TypeKind::Float64 => "float64",
        TypeKind::Bool => "bool",
        TypeKind::String => "string",
        TypeKind::Struct => "struct",
    }
}

/// Member descriptor for a type
#[derive(Debug, Clone)]
struct MemberDescriptor {
    name: String,
    type_kind: TypeKind,
    id: u32,
    is_key: bool,
}

/// Dynamic type definition
#[derive(Debug, Clone)]
struct DynamicType {
    name: String,
    kind: TypeKind,
    members: Vec<MemberDescriptor>,
}

impl DynamicType {
    fn new_struct(name: &str) -> Self {
        Self {
            name: name.to_string(),
            kind: TypeKind::Struct,
            members: Vec::new(),
        }
    }

    fn add_member(&mut self, name: &str, type_kind: TypeKind, is_key: bool) -> &mut Self {
        let id = self.members.len() as u32;
        self.members.push(MemberDescriptor {
            name: name.to_string(),
            type_kind,
            id,
            is_key,
        });
        self
    }
}

/// Data value variants
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum DataValue {
    Int32(i32),
    Int64(i64),
    Float32(f32),
    Float64(f64),
    Bool(bool),
    String(String),
    Unset,
}

/// Dynamic data instance
struct DynamicData {
    dtype: DynamicType,
    values: HashMap<String, DataValue>,
}

impl DynamicData {
    fn new(dtype: DynamicType) -> Self {
        let mut values = HashMap::new();
        for m in &dtype.members {
            values.insert(m.name.clone(), DataValue::Unset);
        }
        Self { dtype, values }
    }

    fn set_int32(&mut self, name: &str, value: i32) -> &mut Self {
        self.values
            .insert(name.to_string(), DataValue::Int32(value));
        self
    }

    fn set_float64(&mut self, name: &str, value: f64) -> &mut Self {
        self.values
            .insert(name.to_string(), DataValue::Float64(value));
        self
    }

    fn set_string(&mut self, name: &str, value: &str) -> &mut Self {
        self.values
            .insert(name.to_string(), DataValue::String(value.to_string()));
        self
    }

    fn set_bool(&mut self, name: &str, value: bool) -> &mut Self {
        self.values.insert(name.to_string(), DataValue::Bool(value));
        self
    }

    fn get_int32(&self, name: &str) -> Option<i32> {
        match self.values.get(name) {
            Some(DataValue::Int32(v)) => Some(*v),
            _ => None,
        }
    }

    fn get_float64(&self, name: &str) -> Option<f64> {
        match self.values.get(name) {
            Some(DataValue::Float64(v)) => Some(*v),
            _ => None,
        }
    }

    fn get_string(&self, name: &str) -> Option<String> {
        match self.values.get(name) {
            Some(DataValue::String(v)) => Some(v.clone()),
            _ => None,
        }
    }

    #[allow(dead_code)]
    fn get_bool(&self, name: &str) -> Option<bool> {
        match self.values.get(name) {
            Some(DataValue::Bool(v)) => Some(*v),
            _ => None,
        }
    }

    /// Serialize to bytes for transmission
    fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Type name
        let name_bytes = self.dtype.name.as_bytes();
        data.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(name_bytes);

        // Member count
        data.extend_from_slice(&(self.dtype.members.len() as u32).to_le_bytes());

        // Serialize each member in order
        for m in &self.dtype.members {
            // Member name
            let m_name = m.name.as_bytes();
            data.extend_from_slice(&(m_name.len() as u32).to_le_bytes());
            data.extend_from_slice(m_name);

            // Member type
            data.push(m.type_kind as u8);

            // Member value
            match self.values.get(&m.name) {
                Some(DataValue::Int32(v)) => {
                    data.push(1); // has value
                    data.extend_from_slice(&v.to_le_bytes());
                }
                Some(DataValue::Float64(v)) => {
                    data.push(1);
                    data.extend_from_slice(&v.to_le_bytes());
                }
                Some(DataValue::String(v)) => {
                    data.push(1);
                    let s_bytes = v.as_bytes();
                    data.extend_from_slice(&(s_bytes.len() as u32).to_le_bytes());
                    data.extend_from_slice(s_bytes);
                }
                Some(DataValue::Bool(v)) => {
                    data.push(1);
                    data.push(if *v { 1 } else { 0 });
                }
                _ => {
                    data.push(0); // no value
                }
            }
        }

        data
    }

    /// Deserialize from bytes
    fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 8 {
            return Err("Data too short");
        }

        let mut offset = 0;

        // Type name
        let name_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let type_name = String::from_utf8_lossy(&data[offset..offset + name_len]).to_string();
        offset += name_len;

        // Member count
        let member_count =
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        let mut dtype = DynamicType::new_struct(&type_name);
        let mut values = HashMap::new();

        for _ in 0..member_count {
            // Member name
            let m_name_len =
                u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            let m_name = String::from_utf8_lossy(&data[offset..offset + m_name_len]).to_string();
            offset += m_name_len;

            // Member type
            let type_kind = match data[offset] {
                0 => TypeKind::Int32,
                1 => TypeKind::Int64,
                2 => TypeKind::Float32,
                3 => TypeKind::Float64,
                4 => TypeKind::Bool,
                5 => TypeKind::String,
                _ => TypeKind::Int32,
            };
            offset += 1;

            dtype.add_member(&m_name, type_kind, false);

            // Has value?
            let has_value = data[offset] == 1;
            offset += 1;

            if has_value {
                let value = match type_kind {
                    TypeKind::Int32 => {
                        let v = i32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
                        offset += 4;
                        DataValue::Int32(v)
                    }
                    TypeKind::Float64 => {
                        let v = f64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
                        offset += 8;
                        DataValue::Float64(v)
                    }
                    TypeKind::String => {
                        let s_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
                            as usize;
                        offset += 4;
                        let s = String::from_utf8_lossy(&data[offset..offset + s_len]).to_string();
                        offset += s_len;
                        DataValue::String(s)
                    }
                    TypeKind::Bool => {
                        let v = data[offset] == 1;
                        offset += 1;
                        DataValue::Bool(v)
                    }
                    _ => DataValue::Unset,
                };
                values.insert(m_name, value);
            } else {
                values.insert(m_name, DataValue::Unset);
            }
        }

        Ok(Self { dtype, values })
    }
}

fn print_type(dtype: &DynamicType) {
    println!("  Type: {} ({})", dtype.name, type_kind_str(dtype.kind));
    println!("  Members ({}):", dtype.members.len());
    for m in &dtype.members {
        let key_flag = if m.is_key { " @key" } else { "" };
        println!(
            "    [{}] {}: {}{}",
            m.id,
            m.name,
            type_kind_str(m.type_kind),
            key_flag
        );
    }
}

fn print_data(data: &DynamicData) {
    println!("  Data of type '{}':", data.dtype.name);
    for m in &data.dtype.members {
        print!("    {} = ", m.name);
        match data.values.get(&m.name) {
            Some(DataValue::Int32(v)) => println!("{}", v),
            Some(DataValue::Int64(v)) => println!("{}", v),
            Some(DataValue::Float32(v)) => println!("{:.2}", v),
            Some(DataValue::Float64(v)) => println!("{:.2}", v),
            Some(DataValue::Bool(v)) => println!("{}", v),
            Some(DataValue::String(v)) => println!("\"{}\"", v),
            Some(DataValue::Unset) | None => println!("<unset>"),
        }
    }
}

fn print_dynamic_data_overview() {
    println!("--- Dynamic Data Overview ---\n");
    println!("Dynamic Data Architecture:\n");
    println!("  +-----------------+      +-----------------+");
    println!("  |  DynamicType    |----->|  DynamicData    |");
    println!("  |  - name         |      |  - type         |");
    println!("  |  - kind         |      |  - values[]     |");
    println!("  |  - members[]    |      |  - get/set()    |");
    println!("  +-----------------+      +-----------------+");
    println!();
    println!("Use Cases:");
    println!("  - Generic data recording/replay tools");
    println!("  - Protocol bridges (DDS <-> REST/MQTT)");
    println!("  - Data visualization without type knowledge");
    println!("  - Testing and debugging utilities");
    println!();
}

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("[Publisher] Creating writer...");
    let writer = participant.create_raw_writer("DynamicDataTopic", None)?;

    // Define a SensorReading type at runtime
    println!("[Publisher] Defining dynamic type 'SensorReading'...\n");

    let mut sensor_type = DynamicType::new_struct("SensorReading");
    sensor_type
        .add_member("sensor_id", TypeKind::Int32, true)
        .add_member("location", TypeKind::String, false)
        .add_member("temperature", TypeKind::Float64, false)
        .add_member("humidity", TypeKind::Float64, false)
        .add_member("is_valid", TypeKind::Bool, false);

    print_type(&sensor_type);
    println!();

    println!("[Publisher] Publishing dynamic data samples...\n");

    let locations = [
        "Building-A/Room-1",
        "Building-A/Room-2",
        "Building-B/Lab",
        "Datacenter",
    ];

    for i in 0..6 {
        let mut reading = DynamicData::new(sensor_type.clone());
        reading
            .set_int32("sensor_id", 100 + i)
            .set_string("location", locations[i as usize % locations.len()])
            .set_float64("temperature", 20.0 + (i as f64 * 2.5))
            .set_float64("humidity", 45.0 + (i as f64 * 3.0))
            .set_bool("is_valid", true);

        let data = reading.serialize();
        writer.write_raw(&data)?;

        println!(
            "  [SENT] sensor_id={}, loc='{}', temp={:.1}, hum={:.1}",
            reading.get_int32("sensor_id").unwrap_or(0),
            reading.get_string("location").unwrap_or_default(),
            reading.get_float64("temperature").unwrap_or(0.0),
            reading.get_float64("humidity").unwrap_or(0.0)
        );

        thread::sleep(Duration::from_millis(300));
    }

    println!("\n[Publisher] Done publishing dynamic data.");
    Ok(())
}

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("[Subscriber] Creating reader...");
    let reader = participant.create_raw_reader("DynamicDataTopic", None)?;

    println!("[Subscriber] Waiting for dynamic data...\n");
    println!("(Type information is discovered at runtime from the data)\n");

    let mut received = 0;
    let mut timeouts = 0;

    // Dynamic data sample uses polling since RawDataReader doesn't implement HasStatusCondition
    while timeouts < 3 {
        let samples = reader.try_take_raw()?;
        if samples.is_empty() {
            println!("  (timeout - waiting for data...)");
            timeouts += 1;
            thread::sleep(Duration::from_secs(2));
            continue;
        }

        for sample in samples {
            match DynamicData::deserialize(&sample.payload) {
                Ok(dynamic_data) => {
                    received += 1;
                    println!("[RECV #{}]", received);
                    print_data(&dynamic_data);

                    // Demonstrate runtime access
                    if let Some(temp) = dynamic_data.get_float64("temperature") {
                        if temp > 25.0 {
                            println!("    [INFO] High temperature detected!");
                        }
                    }
                    println!();
                }
                Err(e) => {
                    eprintln!("  Deserialize error: {}", e);
                }
            }
        }
        timeouts = 0;
    }

    println!("[Subscriber] Received {} dynamic data samples.", received);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let is_publisher = args.get(1).map(|s| s == "pub").unwrap_or(false);

    println!("{}", "=".repeat(60));
    println!("HDDS Dynamic Data Sample");
    println!("{}", "=".repeat(60));
    println!();
    println!("NOTE: CONCEPT DEMO - Native DynamicData/DynamicType API not yet in SDK.");
    println!("      Using standard pub/sub API to demonstrate the pattern.\n");

    print_dynamic_data_overview();

    let participant = hdds::Participant::builder("DynamicDataDemo").build()?;
    println!("[OK] Participant created\n");

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    // Type introspection example
    println!("\n--- Type Introspection Example ---\n");
    println!("  for member in &dtype.members {{");
    println!("      println!(\"Member '{{}}': type={{}}, key={{}}\",");
    println!("          member.name,");
    println!("          type_kind_str(member.type_kind),");
    println!("          member.is_key);");
    println!("  }}");

    // Best practices
    println!("\n--- Dynamic Data Best Practices ---");
    println!("1. Cache type lookups for performance-critical paths");
    println!("2. Use member IDs instead of names for faster access");
    println!("3. Validate type compatibility before operations");
    println!("4. Consider memory management for string members");
    println!("5. Use typed APIs when types are known at compile time");
    println!("6. Leverage type introspection for generic tooling");

    println!("\n=== Sample Complete ===");
    Ok(())
}

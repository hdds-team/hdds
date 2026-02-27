// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Dynamic Data Sample - Demonstrates runtime type manipulation
 *
 * Dynamic Data allows working with types at runtime without
 * compile-time type definitions. Useful for:
 * - Generic tools and data bridges
 * - Type discovery and introspection
 * - Protocol adapters and gateways
 *
 * Key concepts:
 * - DynamicType: runtime type definition
 * - DynamicData: runtime data manipulation
 * - Type introspection
 *
 * Uses the real HDDS C++ API for pub/sub transport with
 * application-level dynamic data representation.
 *
 * NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for DynamicData/DynamicType.
 * The native DynamicData/DynamicType API is not yet exported to the C/C++/Python SDK.
 * This sample uses standard participant/writer/reader API to show the concept.
 */

#include <hdds.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <variant>
#include <optional>
#include <memory>
#include <cstring>
#include <thread>
#include <chrono>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

// Type kinds
enum class TypeKind {
    Int32,
    UInt32,
    Int64,
    Float32,
    Float64,
    Bool,
    String,
    Sequence,
    Array,
    Struct,
};

std::string type_kind_str(TypeKind kind) {
    switch (kind) {
        case TypeKind::Int32: return "int32";
        case TypeKind::UInt32: return "uint32";
        case TypeKind::Int64: return "int64";
        case TypeKind::Float32: return "float32";
        case TypeKind::Float64: return "float64";
        case TypeKind::Bool: return "bool";
        case TypeKind::String: return "string";
        case TypeKind::Sequence: return "sequence";
        case TypeKind::Array: return "array";
        case TypeKind::Struct: return "struct";
        default: return "unknown";
    }
}

// Member descriptor
struct MemberDescriptor {
    std::string name;
    TypeKind type;
    uint32_t id;
    bool is_key = false;
    bool is_optional = false;
};

// Dynamic type definition
class DynamicType {
public:
    DynamicType(const std::string& name, TypeKind kind)
        : name_(name), kind_(kind) {}

    void add_member(const std::string& name, TypeKind type,
                    bool is_key = false, bool is_optional = false) {
        MemberDescriptor member;
        member.name = name;
        member.type = type;
        member.id = static_cast<uint32_t>(members_.size());
        member.is_key = is_key;
        member.is_optional = is_optional;
        members_.push_back(member);
    }

    const std::string& name() const { return name_; }
    TypeKind kind() const { return kind_; }
    const std::vector<MemberDescriptor>& members() const { return members_; }

    std::optional<MemberDescriptor> get_member(const std::string& name) const {
        for (const auto& m : members_) {
            if (m.name == name) return m;
        }
        return std::nullopt;
    }

private:
    std::string name_;
    TypeKind kind_;
    std::vector<MemberDescriptor> members_;
};

// Dynamic data value type
using DataValue = std::variant<
    int32_t, uint32_t, int64_t,
    float, double, bool, std::string,
    std::monostate  // for unset values
>;

// Dynamic data implementation
class DynamicData {
public:
    explicit DynamicData(std::shared_ptr<DynamicType> type)
        : type_(type) {
        for (const auto& m : type_->members()) {
            values_[m.name] = std::monostate{};
            is_set_[m.name] = false;
        }
    }

    // Setters
    void set_int32(const std::string& name, int32_t value) {
        if (values_.count(name)) { values_[name] = value; is_set_[name] = true; }
    }

    void set_float64(const std::string& name, double value) {
        if (values_.count(name)) { values_[name] = value; is_set_[name] = true; }
    }

    void set_string(const std::string& name, const std::string& value) {
        if (values_.count(name)) { values_[name] = value; is_set_[name] = true; }
    }

    void set_bool(const std::string& name, bool value) {
        if (values_.count(name)) { values_[name] = value; is_set_[name] = true; }
    }

    // Getters
    int32_t get_int32(const std::string& name) const {
        if (auto it = values_.find(name); it != values_.end()) {
            if (auto* v = std::get_if<int32_t>(&it->second)) return *v;
        }
        return 0;
    }

    double get_float64(const std::string& name) const {
        if (auto it = values_.find(name); it != values_.end()) {
            if (auto* v = std::get_if<double>(&it->second)) return *v;
        }
        return 0.0;
    }

    std::string get_string(const std::string& name) const {
        if (auto it = values_.find(name); it != values_.end()) {
            if (auto* v = std::get_if<std::string>(&it->second)) return *v;
        }
        return "";
    }

    bool get_bool(const std::string& name) const {
        if (auto it = values_.find(name); it != values_.end()) {
            if (auto* v = std::get_if<bool>(&it->second)) return *v;
        }
        return false;
    }

    bool is_set(const std::string& name) const {
        auto it = is_set_.find(name);
        return it != is_set_.end() && it->second;
    }

    // Serialize to bytes for transmission
    std::vector<uint8_t> serialize() const {
        // Simple serialization format: [member_count][member_data...]
        std::vector<uint8_t> data;
        uint32_t count = static_cast<uint32_t>(type_->members().size());
        data.resize(4);
        std::memcpy(data.data(), &count, 4);

        for (const auto& m : type_->members()) {
            auto it = values_.find(m.name);
            if (it == values_.end()) continue;

            std::visit([&data, &m](auto&& val) {
                using T = std::decay_t<decltype(val)>;
                if constexpr (std::is_same_v<T, int32_t>) {
                    size_t pos = data.size();
                    data.resize(pos + 4);
                    std::memcpy(data.data() + pos, &val, 4);
                } else if constexpr (std::is_same_v<T, double>) {
                    size_t pos = data.size();
                    data.resize(pos + 8);
                    std::memcpy(data.data() + pos, &val, 8);
                } else if constexpr (std::is_same_v<T, std::string>) {
                    uint32_t len = static_cast<uint32_t>(val.size());
                    size_t pos = data.size();
                    data.resize(pos + 4 + len);
                    std::memcpy(data.data() + pos, &len, 4);
                    std::memcpy(data.data() + pos + 4, val.c_str(), len);
                } else if constexpr (std::is_same_v<T, bool>) {
                    data.push_back(val ? 1 : 0);
                }
            }, it->second);
        }
        return data;
    }

    // Clone
    std::unique_ptr<DynamicData> clone() const {
        auto copy = std::make_unique<DynamicData>(type_);
        copy->values_ = values_;
        copy->is_set_ = is_set_;
        return copy;
    }

    std::shared_ptr<DynamicType> type() const { return type_; }
    const std::map<std::string, DataValue>& values() const { return values_; }

private:
    std::shared_ptr<DynamicType> type_;
    std::map<std::string, DataValue> values_;
    std::map<std::string, bool> is_set_;
};

// Type factory
class TypeFactory {
public:
    std::shared_ptr<DynamicType> create_struct(const std::string& name) {
        auto type = std::make_shared<DynamicType>(name, TypeKind::Struct);
        types_[name] = type;
        return type;
    }

    std::shared_ptr<DynamicType> get_type(const std::string& name) const {
        if (auto it = types_.find(name); it != types_.end()) {
            return it->second;
        }
        return nullptr;
    }

private:
    std::map<std::string, std::shared_ptr<DynamicType>> types_;
};

void print_type(const DynamicType& type) {
    std::cout << "  Type: " << type.name() << " (" << type_kind_str(type.kind()) << ")\n";
    std::cout << "  Members (" << type.members().size() << "):\n";
    for (const auto& m : type.members()) {
        std::cout << "    [" << m.id << "] " << m.name << ": " << type_kind_str(m.type);
        if (m.is_key) std::cout << " @key";
        if (m.is_optional) std::cout << " @optional";
        std::cout << "\n";
    }
}

void print_data(const DynamicData& data) {
    std::cout << "  Data of type '" << data.type()->name() << "':\n";
    for (const auto& m : data.type()->members()) {
        std::cout << "    " << m.name << " = ";
        if (!data.is_set(m.name)) {
            std::cout << "<unset>\n";
            continue;
        }

        auto it = data.values().find(m.name);
        if (it == data.values().end()) {
            std::cout << "<not found>\n";
            continue;
        }

        std::visit([](auto&& val) {
            using T = std::decay_t<decltype(val)>;
            if constexpr (std::is_same_v<T, std::monostate>) {
                std::cout << "<unset>";
            } else if constexpr (std::is_same_v<T, std::string>) {
                std::cout << "\"" << val << "\"";
            } else if constexpr (std::is_same_v<T, bool>) {
                std::cout << (val ? "true" : "false");
            } else {
                std::cout << val;
            }
        }, it->second);
        std::cout << "\n";
    }
}

void print_dynamic_data_overview() {
    std::cout << "--- Dynamic Data Overview ---\n\n";
    std::cout << "Dynamic Data Architecture:\n\n";
    std::cout << "  +------------------+      +------------------+\n";
    std::cout << "  |  TypeFactory     |----->|  DynamicType     |\n";
    std::cout << "  |                  |      |  - name          |\n";
    std::cout << "  | create_struct()  |      |  - kind          |\n";
    std::cout << "  +------------------+      |  - members[]     |\n";
    std::cout << "                           +--------+---------+\n";
    std::cout << "                                    |\n";
    std::cout << "                                    v\n";
    std::cout << "                           +------------------+\n";
    std::cout << "                           |  DynamicData     |\n";
    std::cout << "                           |  - type          |\n";
    std::cout << "                           |  - values[]      |\n";
    std::cout << "                           |  - get/set()     |\n";
    std::cout << "                           +------------------+\n";
    std::cout << "\n";
    std::cout << "Use Cases:\n";
    std::cout << "  - Generic data recording/replay tools\n";
    std::cout << "  - Protocol bridges (DDS <-> REST/MQTT)\n";
    std::cout << "  - Data visualization without type knowledge\n";
    std::cout << "  - Testing and debugging utilities\n";
    std::cout << "\n";
}

void run_publisher(hdds::Participant& participant, std::shared_ptr<DynamicType> sensor_type) {
    std::cout << "--- Publisher Mode ---\n\n";

    auto writer = participant.create_writer_raw("DynamicDataTopic", hdds::QoS::reliable());
    std::cout << "[OK] Writer created for DynamicDataTopic\n\n";

    // Publish dynamic data samples
    for (int i = 0; i < 5; i++) {
        DynamicData reading(sensor_type);
        reading.set_int32("sensor_id", 100 + i);
        reading.set_string("location", "Building-A/Room-" + std::to_string(i + 1));
        reading.set_float64("temperature", 20.0 + i * 1.5);
        reading.set_float64("humidity", 45.0 + i * 2.0);
        reading.set_bool("is_valid", true);

        std::cout << "Publishing:\n";
        print_data(reading);
        std::cout << "\n";

        auto bytes = reading.serialize();
        writer->write_raw(bytes);

        std::this_thread::sleep_for(500ms);
    }

    std::cout << "Done publishing.\n";
}

void run_subscriber(hdds::Participant& participant) {
    std::cout << "--- Subscriber Mode ---\n\n";

    auto reader = participant.create_reader_raw("DynamicDataTopic", hdds::QoS::reliable());
    std::cout << "[OK] Reader created for DynamicDataTopic\n";

    hdds::WaitSet waitset;
    waitset.attach(reader->get_status_condition());
    std::cout << "[OK] WaitSet attached\n\n";

    std::cout << "Waiting for dynamic data samples...\n\n";

    int received = 0;
    int timeout_count = 0;

    while (received < 5 && timeout_count < 5) {
        if (waitset.wait(2s)) {
            while (auto sample = reader->take_raw()) {
                std::cout << "[Received] Raw bytes: " << sample->size() << " bytes\n";
                received++;
            }
            timeout_count = 0;
        } else {
            timeout_count++;
            std::cout << "(waiting...)\n";
        }
    }

    std::cout << "\nReceived " << received << " samples.\n";
}

int main(int argc, char* argv[]) {
    std::cout << "=== HDDS Dynamic Data Sample ===\n\n";
    std::cout << "NOTE: CONCEPT DEMO - Native DynamicData/DynamicType API not yet in SDK.\n"
              << "      Using standard pub/sub API to demonstrate the pattern.\n\n";

    bool is_publisher = (argc > 1) &&
        (std::strcmp(argv[1], "pub") == 0 ||
         std::strcmp(argv[1], "publisher") == 0 ||
         std::strcmp(argv[1], "-p") == 0);

    print_dynamic_data_overview();

    try {
        // Initialize logging
        hdds::logging::init(hdds::LogLevel::Warn);

        // Create type factory
        TypeFactory factory;
        std::cout << "[OK] TypeFactory created\n\n";

        // Define a SensorReading type at runtime
        std::cout << "--- Creating Dynamic Type ---\n\n";

        auto sensor_type = factory.create_struct("SensorReading");
        sensor_type->add_member("sensor_id", TypeKind::Int32, true, false);
        sensor_type->add_member("location", TypeKind::String, false, false);
        sensor_type->add_member("temperature", TypeKind::Float64, false, false);
        sensor_type->add_member("humidity", TypeKind::Float64, false, false);
        sensor_type->add_member("is_valid", TypeKind::Bool, false, false);

        std::cout << "[OK] Type 'SensorReading' created dynamically\n\n";
        print_type(*sensor_type);
        std::cout << "\n";

        // Create and populate dynamic data
        std::cout << "--- Creating Dynamic Data ---\n\n";

        DynamicData reading1(sensor_type);
        reading1.set_int32("sensor_id", 101);
        reading1.set_string("location", "Building-A/Room-1");
        reading1.set_float64("temperature", 23.5);
        reading1.set_float64("humidity", 45.2);
        reading1.set_bool("is_valid", true);

        std::cout << "[OK] DynamicData instance created\n\n";
        print_data(reading1);
        std::cout << "\n";

        // Read values back
        std::cout << "--- Reading Dynamic Data ---\n\n";

        auto id = reading1.get_int32("sensor_id");
        auto loc = reading1.get_string("location");
        auto temp = reading1.get_float64("temperature");
        auto hum = reading1.get_float64("humidity");
        auto valid = reading1.get_bool("is_valid");

        std::cout << "Read values:\n";
        std::cout << "  sensor_id: " << id << "\n";
        std::cout << "  location: " << loc << "\n";
        std::cout << "  temperature: " << temp << "\n";
        std::cout << "  humidity: " << hum << "\n";
        std::cout << "  is_valid: " << (valid ? "true" : "false") << "\n\n";

        // Clone data
        std::cout << "--- Cloning Dynamic Data ---\n\n";

        auto reading2 = reading1.clone();
        reading2->set_int32("sensor_id", 102);
        reading2->set_string("location", "Building-B/Room-3");
        reading2->set_float64("temperature", 25.0);

        std::cout << "[OK] Cloned and modified:\n\n";
        print_data(*reading2);
        std::cout << "\n";

        // Type introspection
        std::cout << "--- Type Introspection ---\n\n";

        std::cout << "Iterating over type members:\n";
        for (const auto& m : sensor_type->members()) {
            std::cout << "  Member '" << m.name << "':\n";
            std::cout << "    - Type: " << type_kind_str(m.type) << "\n";
            std::cout << "    - ID: " << m.id << "\n";
            std::cout << "    - Is key: " << (m.is_key ? "yes" : "no") << "\n";
            std::cout << "    - Optional: " << (m.is_optional ? "yes" : "no") << "\n";
        }
        std::cout << "\n";

        // Create participant and demonstrate pub/sub with dynamic data
        std::cout << "--- HDDS Pub/Sub with Dynamic Data ---\n\n";

        hdds::Participant participant("DynamicDataDemo");
        std::cout << "[OK] Participant created\n\n";

        if (is_publisher) {
            run_publisher(participant, sensor_type);
        } else {
            run_subscriber(participant);
        }

        // Best practices
        std::cout << "\n--- Dynamic Data Best Practices ---\n\n";
        std::cout << "1. Cache type lookups for performance-critical paths\n";
        std::cout << "2. Use member IDs instead of names for faster access\n";
        std::cout << "3. Validate type compatibility before operations\n";
        std::cout << "4. Consider memory management for string members\n";
        std::cout << "5. Use typed APIs when types are known at compile time\n";
        std::cout << "6. Leverage type introspection for generic tooling\n";

        std::cout << "\n=== Sample Complete ===\n";

    } catch (const hdds::Error& e) {
        std::cerr << "HDDS Error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

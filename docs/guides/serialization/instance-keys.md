# Instance keys in serialized SDKs

Regenerate keyed IDL types with the current `hddsgen` before using keyed instance
operations in C, C++, Python or TypeScript. The generated codec supplies
the normal RTPS KeyHash, the protected key digest and the key-only payload.
The writer chooses the wire hash from its security policy. Instance handles
and local history continue to use the normal KeyHash under ENCRYPT.

For `Sensor { @key long id; float value; }`, the typed operations are:

```c
#include <hdds.h>
#include "Sensor.h"

HddsDataWriter *writer = sensor_create_keyed_writer(participant, "sensors", qos);
Sensor sample = {42, 1.5f};
sensor_write(writer, &sample);
sensor_dispose(writer, &sample);
sensor_unregister_instance(writer, &sample);
```

Include `hdds.h` before the generated C header to expose its typed operations.
The generated `sensor_create_keyed_writer` selects a keyed endpoint. The
older `sensor_create_writer` keeps its legacy raw-byte path. The new C
helper announces the scoped IDL type name (`m::Sensor`, not `m_Sensor`). The C++ SDK retains its `RawBytes` naming
convention; its new `create_keyed_writer_raw` overload accepts an explicit
type name. Python accepts `type_name` on Participant and Publisher. Custom
codecs supply the name to either keyed C constructor; NULL means `RawBytes`.

```cpp
auto writer = participant.create_writer<Sensor>("sensors");
writer.write(Sensor{42, 1.5f});
writer.dispose(Sensor{42, 0.0f});
```

```python
writer = participant.create_writer("sensors", Sensor, type_name="Sensor")
writer.write_typed(Sensor(id=42, value=1.5))
handle = writer.register_instance(Sensor(id=42))
writer.dispose(Sensor(id=42))
writer.unregister_instance(Sensor(id=42))
```

```typescript
import * as Types from "./Sensor";
const writer = participant.createWriter<Types.Sensor>(
  "sensors", qos, "Sensor", Types);
writer.writeTyped({ id: 42, value: 1.5 });
writer.disposeInstance({ id: 42, value: 0 });
writer.unregisterInstance({ id: 42, value: 0 });
```

`disposeInstance` changes a DDS instance's state; the existing TypeScript
`dispose()` releases the writer. Typed registration and lifecycle operations
serialize only the key, so non-key data is irrelevant. Python and C++ also
support their existing explicit-timestamp variants with typed keyed values.

Old SDK writer constructors and older codecs retain the legacy byte path.
A typed keyed writer also accepts pre-encoded bytes through Python `write`,
C++ `raw()->write_raw`, or TypeScript `write`: it decodes the supplied CDR2
body with the constructor's codec and passes its key metadata to the C ABI.
Regeneration enables keyed lifecycle semantics; it is not required to keep
an older codec publishing through its previous constructor. Custom codecs
with key encoders remain keyed even without a decoder; pre-encoded byte
operations require a decoder (and a default-constructible value in C++).

## C ABI contract

`hdds_writer_create_keyed` and `hdds_publisher_create_writer_keyed` announce a
WITH_KEY writer. Each write, register, dispose or unregister operation uses
the corresponding additive `_keyed` entry point and an `HddsSerializedKey`:

| Field | Meaning |
| --- | --- |
| `HASH` | Normal RTPS KeyHash, including its maximum-key-size padding/MD5 rule. |
| `PROTECTED_HASH` | MD5 of CDR big-endian key fields with natural alignment, even when the key fits in 16 bytes. |
| `PAYLOAD`, `PAYLOAD_LEN` | Little-endian key-only body, without the encapsulation header, preserving the type's extensibility and member ids. |
| `REPRESENTATION` | `0` for XCDR1 or `2` for XCDR2; must match the writer's selected representation. |

Both hashes and the payload must describe the same instance as the sample.
All bytes are copied during the call; no application pointer is retained.
Registration and lifecycle operations accept `data = NULL, len = 0` because
they need only the key metadata. Registration returns the normal instance
handle and emits no DATA. A zero-valued KeyHash is a valid keyed instance.

The generated SDK codecs write XCDR2. A custom C ABI codec can supply XCDR1
when its data and key payload both use the writer's selected representation.
Keyed calls reject a legacy keyless handle or a mismatched representation;
legacy byte operations on a keyed writer reject missing key metadata.
Existing constructors and byte operations remain source compatible for
keyless topics. Bytes alone do not identify which fields form an IDL key.

The wire rules are RTPS 2.5 9.4.5.3 and 9.6.4.8, DDS-XTypes 1.3 7.2.2.4.7
and 7.6.8, and DDS-Security 1.1 7.3.4. Instance lifecycle follows DDS 1.4
2.2.2.4.2 and 2.2.2.5.1. Run `scripts/test-sdk-keyed.sh` with `HDDSGEN` set to
the generator binary to exercise the generated Python and C++ constructors
against a Rust reader, including scoped names and pre-encoded bytes. The
Python lifecycle scenarios also run under ENCRYPT.

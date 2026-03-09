// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Hello World (Java 22+ / Panama FFI)
 *
 * Demonstrates basic pub/sub using HDDS native library via
 * java.lang.foreign (Foreign Function & Memory API).
 *
 * No JNI. No jextract. No dependencies. Pure Java 22+.
 *
 * Prerequisites:
 *     - Java 22+ (Panama FFI is standard since JDK 22)
 *     - HDDS native library: cargo build --release
 *
 * Usage:
 *     javac HelloWorld.java
 *
 *     # Terminal 1 - Subscriber
 *     java -Djava.library.path=../../../../target/release HelloWorld
 *
 *     # Terminal 2 - Publisher
 *     java -Djava.library.path=../../../../target/release HelloWorld pub
 *
 * Cross-language interop:
 *     This example uses the same topic ("HelloWorldTopic") and CDR wire format
 *     as the C, C++, Python and Rust hello_world samples. You can mix and match:
 *         java HelloWorld pub       +   python hello_world.py
 *         ./hello_world pub  (C)    +   java HelloWorld
 *
 * For production use, consider running jextract on hdds.h to auto-generate
 * all bindings instead of the manual approach shown here.
 */

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

public class HelloWorld {

    // ---- HDDS Native Bindings (Panama FFI) --------------------------------

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup HDDS;

    static {
        System.loadLibrary("hdds_c");
        HDDS = SymbolLookup.loaderLookup();
    }

    // Logging
    private static final MethodHandle hdds_logging_init = downcall(
        "hdds_logging_init",
        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));

    // Participant lifecycle
    private static final MethodHandle hdds_participant_create = downcall(
        "hdds_participant_create",
        FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    private static final MethodHandle hdds_participant_destroy = downcall(
        "hdds_participant_destroy",
        FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

    // Writer
    private static final MethodHandle hdds_writer_create = downcall(
        "hdds_writer_create",
        FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    private static final MethodHandle hdds_writer_write = downcall(
        "hdds_writer_write",
        FunctionDescriptor.of(ValueLayout.JAVA_INT,
            ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    private static final MethodHandle hdds_writer_destroy = downcall(
        "hdds_writer_destroy",
        FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

    // Reader
    private static final MethodHandle hdds_reader_create = downcall(
        "hdds_reader_create",
        FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    private static final MethodHandle hdds_reader_take = downcall(
        "hdds_reader_take",
        FunctionDescriptor.of(ValueLayout.JAVA_INT,
            ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

    private static final MethodHandle hdds_reader_destroy = downcall(
        "hdds_reader_destroy",
        FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

    private static final MethodHandle hdds_reader_get_status_condition = downcall(
        "hdds_reader_get_status_condition",
        FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    // WaitSet
    private static final MethodHandle hdds_waitset_create = downcall(
        "hdds_waitset_create",
        FunctionDescriptor.of(ValueLayout.ADDRESS));

    private static final MethodHandle hdds_waitset_destroy = downcall(
        "hdds_waitset_destroy",
        FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

    private static final MethodHandle hdds_waitset_attach_status_condition = downcall(
        "hdds_waitset_attach_status_condition",
        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    private static final MethodHandle hdds_waitset_wait = downcall(
        "hdds_waitset_wait",
        FunctionDescriptor.of(ValueLayout.JAVA_INT,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

    private static MethodHandle downcall(String name, FunctionDescriptor desc) {
        MemorySegment addr = HDDS.find(name)
            .orElseThrow(() -> new UnsatisfiedLinkError("HDDS symbol not found: " + name));
        return LINKER.downcallHandle(addr, desc);
    }

    // ---- CDR Serialization for HelloWorld { int32 id; string message } ----

    /**
     * Serialize a HelloWorld message to CDR (little-endian).
     * Wire format: [id:i32] [str_len:u32] [str_bytes + NUL] [padding to 4-align]
     */
    static byte[] serialize(int id, String message) {
        byte[] strBytes = message.getBytes(StandardCharsets.UTF_8);
        int strLen = strBytes.length + 1;  // include NUL terminator
        int rawLen = 4 + 4 + strLen;
        int padding = (4 - (rawLen % 4)) % 4;

        ByteBuffer buf = ByteBuffer.allocate(rawLen + padding)
            .order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(id);
        buf.putInt(strLen);
        buf.put(strBytes);
        buf.put((byte) 0);  // NUL
        return buf.array();
    }

    /** Deserialized HelloWorld message. */
    record HelloWorldMsg(int id, String message) {}

    /** Deserialize a HelloWorld message from CDR (little-endian). */
    static HelloWorldMsg deserialize(byte[] data, int length) {
        ByteBuffer buf = ByteBuffer.wrap(data, 0, length)
            .order(ByteOrder.LITTLE_ENDIAN);
        int id = buf.getInt();
        int strLen = buf.getInt();
        byte[] strBytes = new byte[strLen - 1];  // exclude NUL
        buf.get(strBytes);
        return new HelloWorldMsg(id, new String(strBytes, StandardCharsets.UTF_8));
    }

    // ---- Publisher --------------------------------------------------------

    static void runPublisher(MemorySegment participant) throws Throwable {
        System.out.println("Creating writer...");

        try (var arena = Arena.ofConfined()) {
            MemorySegment topicName = arena.allocateFrom("HelloWorldTopic");
            MemorySegment writer = (MemorySegment) hdds_writer_create.invokeExact(
                participant, topicName);

            if (writer.equals(MemorySegment.NULL)) {
                System.err.println("Failed to create writer");
                return;
            }

            System.out.println("Publishing messages...");

            for (int i = 0; i < 10; i++) {
                byte[] payload = serialize(i, "Hello from HDDS Java!");
                MemorySegment data = arena.allocateFrom(ValueLayout.JAVA_BYTE, payload);

                int rc = (int) hdds_writer_write.invokeExact(
                    writer, data, (long) payload.length);

                if (rc == 0) {  // HDDS_OK
                    System.out.printf("  Published: Hello from HDDS Java! (id=%d)%n", i);
                } else {
                    System.err.printf("  Failed to publish message %d (rc=%d)%n", i, rc);
                }

                Thread.sleep(500);
            }

            System.out.println("Done publishing.");
            hdds_writer_destroy.invokeExact(writer);
        }
    }

    // ---- Subscriber -------------------------------------------------------

    static void runSubscriber(MemorySegment participant) throws Throwable {
        System.out.println("Creating reader...");

        try (var arena = Arena.ofConfined()) {
            MemorySegment topicName = arena.allocateFrom("HelloWorldTopic");
            MemorySegment reader = (MemorySegment) hdds_reader_create.invokeExact(
                participant, topicName);

            if (reader.equals(MemorySegment.NULL)) {
                System.err.println("Failed to create reader");
                return;
            }

            // Create waitset and attach reader condition
            MemorySegment waitset = (MemorySegment) hdds_waitset_create.invokeExact();
            MemorySegment cond = (MemorySegment) hdds_reader_get_status_condition
                .invokeExact(reader);
            int arc = (int) hdds_waitset_attach_status_condition
                .invokeExact(waitset, cond);

            System.out.println("Waiting for messages (Ctrl+C to exit)...");
            int received = 0;

            // Pre-allocate buffers
            MemorySegment triggered = arena.allocate(ValueLayout.ADDRESS, 1);
            MemorySegment outLen    = arena.allocate(ValueLayout.JAVA_LONG);
            MemorySegment buffer    = arena.allocate(1024);
            MemorySegment readLen   = arena.allocate(ValueLayout.JAVA_LONG);

            while (received < 10) {
                // Wait up to 5 seconds
                int wrc = (int) hdds_waitset_wait.invokeExact(
                    waitset, 5_000_000_000L, triggered, 1L, outLen);
                long count = outLen.get(ValueLayout.JAVA_LONG, 0);

                if (wrc == 0 && count > 0) {  // HDDS_OK + conditions triggered
                    // Take all available samples
                    while (true) {
                        int trc = (int) hdds_reader_take.invokeExact(
                            reader, buffer, 1024L, readLen);
                        if (trc != 0) break;  // no more data

                        long len = readLen.get(ValueLayout.JAVA_LONG, 0);
                        byte[] raw = buffer.asSlice(0, len)
                            .toArray(ValueLayout.JAVA_BYTE);
                        HelloWorldMsg msg = deserialize(raw, (int) len);
                        System.out.printf("  Received: %s (id=%d)%n",
                            msg.message(), msg.id());
                        received++;
                    }
                } else {
                    System.out.println("  (timeout - no messages)");
                }
            }

            System.out.println("Done receiving.");
            hdds_waitset_destroy.invokeExact(waitset);
            hdds_reader_destroy.invokeExact(reader);
        }
    }

    // ---- Main -------------------------------------------------------------

    public static void main(String[] args) throws Throwable {
        boolean isPublisher = args.length > 0
            && (args[0].equals("pub")
                || args[0].equals("publisher")
                || args[0].equals("-p"));

        // Initialize logging (INFO = 3)
        int logRc = (int) hdds_logging_init.invokeExact(3);

        System.out.println("Creating participant...");

        try (var arena = Arena.ofConfined()) {
            MemorySegment name = arena.allocateFrom("HelloWorld");
            MemorySegment participant = (MemorySegment) hdds_participant_create
                .invokeExact(name);

            if (participant.equals(MemorySegment.NULL)) {
                System.err.println("Failed to create participant");
                System.exit(1);
            }

            if (isPublisher) {
                runPublisher(participant);
            } else {
                runSubscriber(participant);
            }

            hdds_participant_destroy.invokeExact(participant);
            System.out.println("Cleanup complete.");
        }
    }
}

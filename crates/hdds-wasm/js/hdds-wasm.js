// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
//
// Hand-written ES-module glue for the HDDS WASM SDK.
//
// There is no wasm-bindgen here: the module exports plain C functions and its
// linear memory, and this file marshals between JavaScript values and that
// memory. It runs unchanged in a browser and in node (the gate uses node).
//
// Usage in a browser:
//
//   import { HddsWasm, HddsClient } from './hdds-wasm.js';
//   const wasm = await HddsWasm.load('./hdds_wasm.wasm');
//   const client = new HddsClient(wasm, 0);
//   await client.connect('ws://localhost:9000');
//   const topicId = await client.createTopic('Chatter', 'std_msgs::String');
//   client.subscribe(topicId, (payload) => console.log(payload));
//   client.publish(topicId, cdrBytes);

const ERR = {
  '-1': 'null argument',
  '-2': 'buffer too small',
  '-3': 'protocol error',
  '-4': 'invalid utf-8',
};

export const EVENT = {
  CONNECT_ACK: 1,
  TOPIC_ACK: 2,
  DATA: 3,
  PONG: 4,
  ERROR: 5,
  DISCONNECTED: 6,
  OTHER: 7,
};

function check(n) {
  if (n < 0) {
    throw new Error(`hdds-wasm: ${ERR[String(n)] || `error ${n}`}`);
  }
  return n;
}

/** A loaded HDDS WASM module. */
export class HddsWasm {
  constructor(instance) {
    this.exports = instance.exports;
    this.memory = instance.exports.memory;
  }

  /** Instantiate from a URL (browser) or a file path (node). */
  static async load(source) {
    let bytes;
    if (typeof source === 'string' && typeof fetch === 'function' && /^https?:/.test(source)) {
      const response = await fetch(source);
      bytes = new Uint8Array(await response.arrayBuffer());
    } else if (source instanceof Uint8Array) {
      bytes = source;
    } else {
      // node: read the file without importing anything at module scope, so a
      // browser never sees a node builtin.
      const { readFile } = await import('node:fs/promises');
      bytes = new Uint8Array(await readFile(source));
    }
    const { instance } = await WebAssembly.instantiate(bytes, {});
    return new HddsWasm(instance);
  }

  /** A Uint8Array view over the module's memory. Re-read after any growth. */
  view() {
    return new Uint8Array(this.memory.buffer);
  }

  alloc(len) {
    const ptr = this.exports.hdds_wasm_alloc(len);
    if (ptr === 0) {
      throw new Error('hdds-wasm: allocation failed');
    }
    return ptr;
  }

  free(ptr, len) {
    this.exports.hdds_wasm_free(ptr, len);
  }

  /** Copy a JS byte array into module memory; returns [ptr, len]. */
  writeBytes(bytes) {
    const len = bytes.length;
    if (len === 0) {
      return [this.alloc(1), 0];
    }
    const ptr = this.alloc(len);
    this.view().set(bytes, ptr);
    return [ptr, len];
  }

  writeString(text) {
    return this.writeBytes(new TextEncoder().encode(text));
  }

  readBytes(ptr, len) {
    return this.view().slice(ptr, ptr + len);
  }
}

/** Scratch output buffer, grown on demand. */
class Scratch {
  constructor(wasm, capacity = 4096) {
    this.wasm = wasm;
    this.capacity = capacity;
    this.ptr = wasm.alloc(capacity);
  }

  grow(capacity) {
    this.wasm.free(this.ptr, this.capacity);
    this.capacity = capacity;
    this.ptr = this.wasm.alloc(capacity);
  }

  /** Make sure the buffer holds at least `capacity` bytes. */
  reserve(capacity) {
    if (capacity > this.capacity) {
      this.grow(capacity);
    }
  }

  /**
   * Run `fn(ptr, cap)`, growing the buffer until the call fits.
   *
   * Every C entry point that can answer -2 (buffer too small) is required to
   * leave its inputs untouched on that path, so a retry is a retry and not a
   * second execution.
   */
  call(fn) {
    let n = fn(this.ptr, this.capacity);
    while (n === -2) {
      this.grow(this.capacity * 4);
      n = fn(this.ptr, this.capacity);
    }
    return check(n);
  }
}

/** CDR encoder bound to the module's encoder object. */
export class CdrWriter {
  constructor(wasm) {
    this.wasm = wasm;
    this.handle = wasm.exports.hdds_wasm_cdr_encoder_new();
  }

  u32(v) { check(this.wasm.exports.hdds_wasm_cdr_encode_u32(this.handle, v)); return this; }
  i32(v) { check(this.wasm.exports.hdds_wasm_cdr_encode_i32(this.handle, v)); return this; }
  u64(v) { check(this.wasm.exports.hdds_wasm_cdr_encode_u64(this.handle, v)); return this; }
  f32(v) { check(this.wasm.exports.hdds_wasm_cdr_encode_f32(this.handle, v)); return this; }
  f64(v) { check(this.wasm.exports.hdds_wasm_cdr_encode_f64(this.handle, v)); return this; }

  string(text) {
    const [ptr, len] = this.wasm.writeString(text);
    try {
      check(this.wasm.exports.hdds_wasm_cdr_encode_string(this.handle, ptr, len));
    } finally {
      this.wasm.free(ptr, len || 1);
    }
    return this;
  }

  /** Consume the encoder and return the CDR bytes. */
  finish() {
    const scratch = new Scratch(this.wasm);
    try {
      // Size the buffer from the encoder itself, so the common case is one
      // call. hdds_wasm_cdr_encoder_finish also keeps the encoder alive on
      // -2, so Scratch.call's retry is safe whatever the size.
      const needed = check(this.wasm.exports.hdds_wasm_cdr_encoder_len(this.handle));
      scratch.reserve(needed);
      const n = scratch.call((ptr, cap) =>
        this.wasm.exports.hdds_wasm_cdr_encoder_finish(this.handle, ptr, cap));
      this.handle = 0;
      return this.wasm.readBytes(scratch.ptr, n);
    } finally {
      this.wasm.free(scratch.ptr, scratch.capacity);
    }
  }
}

/**
 * A browser-side DDS participant.
 *
 * The transport is a WebSocket carrying binary frames of the relay protocol;
 * the wasm module owns the protocol state.
 */
export class HddsClient {
  constructor(wasm, domainId = 0) {
    this.wasm = wasm;
    this.participant = wasm.exports.hdds_wasm_participant_new(domainId);
    this.scratch = new Scratch(wasm);
    this.socket = null;
    this.subscribers = new Map();
    this.pending = [];
    this.topicIdsByName = new Map();
  }

  /** Free the participant. The socket, if any, is closed first. */
  close() {
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    this.wasm.exports.hdds_wasm_participant_free(this.participant);
    this.participant = 0;
  }

  get connected() {
    return this.wasm.exports.hdds_wasm_is_connected(this.participant) === 1;
  }

  /** Open the WebSocket and complete CONNECT / CONNECT_ACK. */
  connect(url, WebSocketImpl) {
    const Impl = WebSocketImpl || globalThis.WebSocket;
    if (!Impl) {
      throw new Error('hdds-wasm: no WebSocket implementation available');
    }
    return new Promise((resolve, reject) => {
      const socket = new Impl(url);
      socket.binaryType = 'arraybuffer';
      this.socket = socket;
      socket.onerror = (e) => reject(e);
      socket.onmessage = (event) => this.handleFrame(new Uint8Array(event.data));
      socket.onopen = () => {
        this.pending.push({ event: EVENT.CONNECT_ACK, resolve });
        socket.send(this.buildConnect());
      };
    });
  }

  buildConnect() {
    const n = this.scratch.call((ptr, cap) =>
      this.wasm.exports.hdds_wasm_build_connect(this.participant, ptr, cap));
    return this.wasm.readBytes(this.scratch.ptr, n);
  }

  buildCreateTopic(name, typeName) {
    const [namePtr, nameLen] = this.wasm.writeString(name);
    const [typePtr, typeLen] = this.wasm.writeString(typeName);
    try {
      const n = this.scratch.call((ptr, cap) =>
        this.wasm.exports.hdds_wasm_build_create_topic(
          this.participant, namePtr, nameLen, typePtr, typeLen, ptr, cap));
      return this.wasm.readBytes(this.scratch.ptr, n);
    } finally {
      this.wasm.free(namePtr, nameLen || 1);
      this.wasm.free(typePtr, typeLen || 1);
    }
  }

  buildSubscribe(topicId) {
    const n = this.scratch.call((ptr, cap) =>
      this.wasm.exports.hdds_wasm_build_subscribe(this.participant, topicId, ptr, cap));
    return this.wasm.readBytes(this.scratch.ptr, n);
  }

  buildPublish(topicId, payload) {
    const [dataPtr, dataLen] = this.wasm.writeBytes(payload);
    try {
      const n = this.scratch.call((ptr, cap) =>
        this.wasm.exports.hdds_wasm_build_publish(
          this.participant, topicId, dataPtr, dataLen, ptr, cap));
      return this.wasm.readBytes(this.scratch.ptr, n);
    } finally {
      this.wasm.free(dataPtr, dataLen || 1);
    }
  }

  /** Feed one relay frame to the wasm module and dispatch the event. */
  handleFrame(frame) {
    const [msgPtr, msgLen] = this.wasm.writeBytes(frame);
    const lenPtr = this.wasm.alloc(4);
    try {
      const code = this.scratch.call((ptr, cap) =>
        this.wasm.exports.hdds_wasm_process(
          this.participant, msgPtr, msgLen, ptr, cap, lenPtr));
      const outLen = new DataView(this.wasm.memory.buffer).getUint32(lenPtr, true);
      const out = this.wasm.readBytes(this.scratch.ptr, outLen);
      this.dispatch(code, out);
      return { code, out };
    } finally {
      this.wasm.free(msgPtr, msgLen || 1);
      this.wasm.free(lenPtr, 4);
    }
  }

  dispatch(code, out) {
    if (code === EVENT.DATA) {
      const topicId = out[0] | (out[1] << 8);
      const payload = out.slice(2);
      const handler = this.subscribers.get(topicId);
      if (handler) {
        handler(payload, topicId);
      }
      return;
    }
    if (code === EVENT.TOPIC_ACK) {
      const topicId = out[0] | (out[1] << 8);
      const waiter = this.takePending(EVENT.TOPIC_ACK);
      if (waiter) {
        waiter.resolve(topicId);
      }
      return;
    }
    if (code === EVENT.CONNECT_ACK) {
      const waiter = this.takePending(EVENT.CONNECT_ACK);
      if (waiter) {
        waiter.resolve(this);
      }
    }
  }

  takePending(event) {
    const index = this.pending.findIndex((p) => p.event === event);
    if (index < 0) {
      return null;
    }
    return this.pending.splice(index, 1)[0];
  }

  /** Ask the relay for a topic id and wait for TOPIC_ACK. */
  createTopic(name, typeName) {
    const frame = this.buildCreateTopic(name, typeName);
    return new Promise((resolve, reject) => {
      this.pending.push({
        event: EVENT.TOPIC_ACK,
        resolve: (topicId) => {
          this.topicIdsByName.set(name, topicId);
          resolve(topicId);
        },
        reject,
      });
      this.socket.send(frame);
    });
  }

  subscribe(topicId, handler) {
    this.subscribers.set(topicId, handler);
    this.socket.send(this.buildSubscribe(topicId));
  }

  publish(topicId, payload) {
    this.socket.send(this.buildPublish(topicId, payload));
  }

  /** A CDR writer bound to this client's module. */
  cdr() {
    return new CdrWriter(this.wasm);
  }
}

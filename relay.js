'use strict';
// Signaling relay shared by the host app (Node/Electron) and the viewer page (browser).
//
// Messages travel through free public MQTT brokers over wss://. Every message is encrypted
// (AES-256-GCM) with a key derived from a secret that only the host and the invited person
// know, so the brokers see random bytes and nothing else. Several brokers are used at once
// (first copy wins), so one broker being down does not matter.
//
// Dependency free: a tiny MQTT 3.1.1 client (CONNECT / SUBSCRIBE / PUBLISH at QoS 0) is included.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.WTRelay = factory();
})(typeof self !== 'undefined' ? self : globalThis, function () {
  // Free, no account, TLS WebSocket. Edit this list to add or swap brokers.
  // (The viewer page must be re-uploaded after changing it.)
  const BROKERS = [
    'wss://broker.hivemq.com:8884/mqtt',
    'wss://broker.emqx.io:8084/mqtt',
    'wss://test.mosquitto.org:8081/mqtt',
  ];
  const ICE_SERVERS = [{ urls: 'stun:stun.l.google.com:19302' }];

  const te = new TextEncoder();
  const td = new TextDecoder();

  let wc = globalThis.crypto;
  if (!wc && typeof require === 'function') { try { wc = require('crypto').webcrypto; } catch { /* none */ } }

  // ------------------------------------------------------------ small helpers
  const b64u = {
    enc(bytes) {
      let s = '';
      for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    },
    dec(str) {
      const s = str.replace(/-/g, '+').replace(/_/g, '/');
      const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    },
  };
  const hex = (bytes) => Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, '0')).join('');
  const randHex = (n) => hex(wc.getRandomValues(new Uint8Array(n)));
  const concat = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  };

  // ------------------------------------------------------------ secrets + encryption
  const newSecret = () => b64u.enc(wc.getRandomValues(new Uint8Array(16))); // 128 bits, 22 chars
  const validSecret = (s) => typeof s === 'string' && /^[A-Za-z0-9_-]{22,86}$/.test(s);

  // secret -> { topic, key }. The topic (mailbox name) and the key are independent HKDF outputs.
  async function deriveRoom(secret) {
    if (!validSecret(secret)) throw new Error('bad secret');
    const base = await wc.subtle.importKey('raw', b64u.dec(secret), 'HKDF', false, ['deriveBits', 'deriveKey']);
    const salt = te.encode('watch-together/v1');
    const params = (info) => ({ name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(info) });
    const topicBits = await wc.subtle.deriveBits(params('topic'), base, 128);
    const key = await wc.subtle.deriveKey(params('key'), base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    return { topic: `wt1/${hex(topicBits)}`, key };
  }

  async function encrypt(key, topic, text) {
    const iv = wc.getRandomValues(new Uint8Array(12));
    const ct = await wc.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode(topic) }, key, te.encode(text));
    return concat(iv, new Uint8Array(ct));
  }

  async function decrypt(key, topic, bytes) {
    if (bytes.length < 29) throw new Error('short');
    const pt = await wc.subtle.decrypt(
      { name: 'AES-GCM', iv: bytes.subarray(0, 12), additionalData: te.encode(topic) }, key, bytes.subarray(12));
    return td.decode(pt);
  }

  // ------------------------------------------------------------ MQTT 3.1.1 packets
  const mqttStr = (s) => { const b = te.encode(s); return concat(Uint8Array.of(b.length >> 8, b.length & 255), b); };
  function varint(n) {
    const out = [];
    do { let d = n % 128; n = Math.floor(n / 128); if (n > 0) d |= 128; out.push(d); } while (n > 0);
    return Uint8Array.from(out);
  }
  const packet = (first, body) => concat(Uint8Array.of(first), varint(body.length), body);

  const connectPacket = (clientId, keepalive) => packet(0x10, concat(
    mqttStr('MQTT'), Uint8Array.of(4, 0x02, keepalive >> 8, keepalive & 255), mqttStr(clientId)));
  const subscribePacket = (id, topics) => packet(0x82, concat(
    Uint8Array.of(id >> 8, id & 255), ...topics.map((t) => concat(mqttStr(t), Uint8Array.of(0)))));
  const unsubscribePacket = (id, topics) => packet(0xa2, concat(
    Uint8Array.of(id >> 8, id & 255), ...topics.map(mqttStr)));
  const publishPacket = (topic, payload) => packet(0x30, concat(mqttStr(topic), payload));
  const PINGREQ = Uint8Array.of(0xc0, 0);
  const DISCONNECT = Uint8Array.of(0xe0, 0);

  const toBytes = (d) => {
    if (d instanceof ArrayBuffer) return new Uint8Array(d);
    if (ArrayBuffer.isView(d)) return new Uint8Array(d.buffer, d.byteOffset, d.byteLength);
    return null; // text frames are not MQTT
  };

  // One connection to one broker. Reconnects forever with backoff until stop().
  class MqttConn {
    constructor(url, WS, hooks) {
      this.url = url;
      this.WS = WS;
      this.hooks = hooks;
      this.name = url.replace(/^wss?:\/\//, '').replace(/[/?].*$/, '');
      this.topics = new Set();
      this.up = false;
      this.stopped = false;
      this.ws = null;
      this.backoff = 1000;
      this.pid = 1;
      this.connect();
    }

    log(m) { if (this.hooks.log) this.hooks.log(`${this.name}: ${m}`); }

    connect() {
      if (this.stopped) return;
      let ws;
      try { ws = new this.WS(this.url, 'mqtt'); } catch (e) { this.log(`cannot open (${e.message})`); return this.retry(); }
      ws.binaryType = 'arraybuffer';
      this.ws = ws;
      this.buf = new Uint8Array(0);
      this.lastRx = Date.now();
      this.connTimer = setTimeout(() => { if (this.ws === ws && !this.up) this.drop(); }, 12000);
      ws.onopen = () => { if (this.ws === ws) this.write(connectPacket(`wt-${randHex(8)}`, 45)); };
      ws.onmessage = (ev) => {
        if (this.ws !== ws) return;
        const b = toBytes(ev.data);
        if (!b) return;
        this.lastRx = Date.now();
        this.feed(b);
      };
      ws.onerror = () => {};
      ws.onclose = () => { if (this.ws === ws) this.down(); };
    }

    write(bytes) {
      const ws = this.ws;
      if (ws && ws.readyState === 1) { try { ws.send(bytes); } catch { /* socket closing */ } }
    }

    drop() { try { if (this.ws) this.ws.close(); } catch { /* ignore */ } }

    down() {
      const was = this.up;
      this.up = false;
      this.ws = null;
      clearTimeout(this.connTimer);
      clearInterval(this.kaTimer);
      if (was) this.log('disconnected');
      this.hooks.onChange();
      this.retry();
    }

    retry() {
      if (this.stopped) return;
      const delay = this.backoff * (0.75 + Math.random() * 0.5);
      this.backoff = Math.min(this.backoff * 2, 30000);
      this.retryTimer = setTimeout(() => this.connect(), delay);
    }

    feed(chunk) {
      this.buf = this.buf.length ? concat(this.buf, chunk) : chunk;
      for (;;) {
        const b = this.buf;
        if (b.length < 2) return;
        let len = 0, mul = 1, pos = 1, ok = false;
        while (pos < b.length && pos <= 4) {
          const d = b[pos++];
          len += (d & 127) * mul;
          mul *= 128;
          if (!(d & 128)) { ok = true; break; }
        }
        if (!ok) { if (pos >= 5) this.drop(); return; } // malformed, or not complete yet
        if (b.length < pos + len) return;
        const first = b[0];
        const body = b.subarray(pos, pos + len);
        this.buf = b.subarray(pos + len);
        this.handle(first >> 4, first & 15, body);
      }
    }

    handle(type, flags, body) {
      if (type === 2) { // CONNACK
        if (body[1] !== 0) { this.log(`refused (code ${body[1]})`); return this.drop(); }
        this.up = true;
        this.backoff = 1000;
        clearTimeout(this.connTimer);
        this.kaTimer = setInterval(() => {
          if (!this.up) return;
          if (Date.now() - this.lastRx > 50000) return this.drop(); // silent for too long
          this.write(PINGREQ);
        }, 15000);
        if (this.topics.size) this.write(subscribePacket(this.pid++ & 0xffff || 1, [...this.topics]));
        this.log('connected');
        this.hooks.onChange();
      } else if (type === 3) { // PUBLISH
        const tl = (body[0] << 8) | body[1];
        const topic = td.decode(body.subarray(2, 2 + tl));
        let p = 2 + tl;
        const qos = (flags >> 1) & 3;
        if (qos > 0) {
          const id = (body[p] << 8) | body[p + 1];
          p += 2;
          if (qos === 1) this.write(Uint8Array.of(0x40, 2, id >> 8, id & 255));
        }
        this.hooks.onPublish(topic, body.slice(p));
      }
      // SUBACK / PINGRESP / others: nothing to do
    }

    addTopic(topic) {
      if (this.topics.has(topic)) return;
      this.topics.add(topic);
      if (this.up) this.write(subscribePacket(this.pid++ & 0xffff || 1, [topic]));
    }

    removeTopic(topic) {
      if (!this.topics.delete(topic)) return;
      if (this.up) this.write(unsubscribePacket(this.pid++ & 0xffff || 1, [topic]));
    }

    publish(topic, payload) {
      if (!this.up) return false;
      this.write(publishPacket(topic, payload));
      return true;
    }

    stop() {
      this.stopped = true;
      clearTimeout(this.retryTimer);
      clearTimeout(this.connTimer);
      clearInterval(this.kaTimer);
      if (this.up) this.write(DISCONNECT);
      this.up = false;
      this.drop();
    }
  }

  // An encrypted mailbox. send() publishes to every broker; incoming copies are de-duplicated.
  class Channel {
    constructor(net, topic, key, onMessage) {
      this.net = net;
      this.topic = topic;
      this.key = key;
      this.onMessage = onMessage;
      this.seen = new Set();
      this.rx = Promise.resolve(); // keeps decrypt + delivery in arrival order
      this.tx = Promise.resolve();
    }

    send(obj) {
      const msg = Object.assign({}, obj, { i: randHex(8) });
      const p = this.tx.then(async () => {
        this.net.publish(this.topic, await encrypt(this.key, this.topic, JSON.stringify(msg)));
      });
      this.tx = p.catch(() => {});
      return p;
    }

    // Encrypt now, publish later in one synchronous call (for page-unload "goodbye" messages).
    async prepare(obj) {
      const bytes = await encrypt(this.key, this.topic, JSON.stringify(Object.assign({}, obj, { i: randHex(8) })));
      return () => this.net.publish(this.topic, bytes);
    }

    receive(bytes) {
      this.rx = this.rx.then(async () => {
        let msg;
        try { msg = JSON.parse(await decrypt(this.key, this.topic, bytes)); } catch { return; } // not ours / tampered
        if (!msg || typeof msg !== 'object' || typeof msg.i !== 'string') return;
        if (this.seen.has(msg.i)) return;
        this.seen.add(msg.i);
        if (this.seen.size > 4000) this.seen.delete(this.seen.values().next().value);
        try { this.onMessage(msg); } catch (e) { this.net.log(`handler error: ${e && e.message}`); }
      }).catch(() => {});
    }

    close() {
      this.tx.then(() => this.net.drop(this));
    }
  }

  class RelayNet {
    constructor({ brokers = BROKERS, WebSocket: WS, onStatus, log } = {}) {
      WS = WS || globalThis.WebSocket;
      this.onStatus = onStatus || (() => {});
      this.log = (m) => { if (log) log(m); };
      this.channels = new Map();
      this.conns = brokers.map((url) => new MqttConn(url, WS, {
        onChange: () => this.onStatus(this),
        onPublish: (topic, payload) => { const ch = this.channels.get(topic); if (ch) ch.receive(payload); },
        log: (m) => this.log(m),
      }));
    }

    channel({ topic, key, onMessage }) {
      const ch = new Channel(this, topic, key, onMessage);
      this.channels.set(topic, ch);
      for (const c of this.conns) c.addTopic(topic);
      return ch;
    }

    drop(ch) {
      if (this.channels.get(ch.topic) !== ch) return;
      this.channels.delete(ch.topic);
      for (const c of this.conns) c.removeTopic(ch.topic);
    }

    publish(topic, bytes) {
      let n = 0;
      for (const c of this.conns) if (c.publish(topic, bytes)) n++;
      return n;
    }

    upCount() { return this.conns.filter((c) => c.up).length; }
    info() { return this.conns.map((c) => ({ name: c.name, up: c.up })); }
    close() { this.conns.forEach((c) => c.stop()); this.channels.clear(); }
  }

  return { BROKERS, ICE_SERVERS, RelayNet, newSecret, validSecret, deriveRoom, b64u };
});

'use strict';
// Viewer side of the signaling protocol, with no DOM or WebRTC in it (so it can be tested in Node).
//
// Wire messages (all encrypted by relay.js). f = from ('h' host / 'v' viewer), c = device id, p = page id.
//   viewer -> host: hello {w}   announce / heartbeat (w=1 while no host reply has been heard yet)
//                   signal {d}  WebRTC answer / candidate
//                   resync      "my media link failed, please offer again"
//                   leave       page is closing
//   host -> viewer: hb          presence ping for the whole invite
//                   status {state, code?}   waiting | denied | kicked | locked | full | busy | expired | replaced | revoked
//                   accepted {ice}
//                   signal {d}  WebRTC offer / candidate / bye
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.WTClientLib = factory();
})(typeof self !== 'undefined' ? self : globalThis, function () {
  const FINAL = new Set(['denied', 'kicked', 'locked', 'full', 'busy', 'expired', 'replaced', 'revoked']);
  const HELLO_FAST_MS = 3000;   // until the host has answered
  const HELLO_SLOW_MS = 10000;  // heartbeat afterwards
  const HOST_SILENT_MS = 45000;

  class WTClient {
    // opts: { net, room: { topic, key }, cid, pid, isMediaUp(): bool,
    //         onState({ kind, code?, state? }), onAccepted(iceServers), onSignal(data) }
    // kinds: connecting | relay-down | looking | waiting | accepted | final
    constructor(opts) {
      this.o = opts;
      this.heard = false;
      this.status = null;     // last host verdict: 'waiting' | 'accepted'
      this.code = '';
      this.final = null;
      this.lastHost = 0;
      this.lastHello = 0;
      this.startedAt = Date.now();
      this.relaySeenUp = false;
      this.view = '';
      this.leaveFn = null;
      this.ch = opts.net.channel({ topic: opts.room.topic, key: opts.room.key, onMessage: (m) => this.onHost(m) });
    }

    async start() {
      try { this.leaveFn = await this.ch.prepare({ f: 'v', t: 'leave', c: this.o.cid, p: this.o.pid }); } catch { /* optional */ }
      this.timer = setInterval(() => this.tick(), 1000);
      this.tick();
    }

    stop() {
      clearInterval(this.timer);
      this.ch.close();
    }

    send(obj) { return this.ch.send(Object.assign({ f: 'v', c: this.o.cid, p: this.o.pid }, obj)).catch(() => {}); }
    signal(d) { return this.send({ t: 'signal', d }); }
    resync() { return this.send({ t: 'resync' }); }
    leaveNow() { if (this.leaveFn) { try { this.leaveFn(); } catch { /* ignore */ } } }

    hello() {
      this.lastHello = Date.now();
      this.send({ t: 'hello', w: this.heard ? 0 : 1 });
    }

    tick() {
      if (this.final) return;
      const now = Date.now();
      if (this.o.net.upCount() > 0) this.relaySeenUp = true;
      if (now - this.lastHello >= (this.heard ? HELLO_SLOW_MS : HELLO_FAST_MS)) this.hello();
      // Host went quiet. Only matters while there is no working media link.
      if (this.heard && now - this.lastHost > HOST_SILENT_MS && !this.o.isMediaUp()) this.heard = false;
      this.report();
    }

    report() {
      let s;
      if (this.final) s = { kind: 'final', state: this.final };
      else if (this.o.net.upCount() === 0) {
        s = { kind: Date.now() - this.startedAt > 8000 || this.relaySeenUp ? 'relay-down' : 'connecting' };
      } else if (!this.heard) s = { kind: Date.now() - this.startedAt > 5000 ? 'looking' : 'connecting' };
      else if (this.status === 'waiting') s = { kind: 'waiting', code: this.code };
      else if (this.status === 'accepted') s = { kind: 'accepted' };
      else s = { kind: 'connecting' };
      const sig = s.kind + (s.code || '') + (s.state || '');
      if (sig === this.view) return;
      this.view = sig;
      this.o.onState(s);
    }

    onHost(m) {
      if (m.f !== 'h' || typeof m.t !== 'string') return;
      if (m.t === 'hb') { this.lastHost = Date.now(); return; }
      if (m.c !== this.o.cid || m.p !== this.o.pid) return; // addressed to another device/page
      this.heard = true;
      this.lastHost = Date.now();
      if (this.final) return;
      if (m.t === 'status') {
        if (m.state === 'waiting') {
          this.status = 'waiting';
          this.code = typeof m.code === 'string' ? m.code.slice(0, 40) : '';
        } else if (FINAL.has(m.state)) {
          this.final = m.state;
          clearInterval(this.timer);
        }
      } else if (m.t === 'accepted') {
        this.status = 'accepted';
        this.o.onAccepted(Array.isArray(m.ice) ? m.ice : null);
      } else if (m.t === 'signal' && m.d && typeof m.d === 'object') {
        this.o.onSignal(m.d);
      }
      this.report();
    }
  }

  return { WTClient };
});

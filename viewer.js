(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const v = $('v');
  const dbg = (...a) => console.log('[wt]', ...a);

  const FINAL = {
    denied: 'The host declined your request.',
    kicked: 'You were removed by the host.',
    locked: 'This room is locked.',
    busy: 'Another request is pending. Refresh in a moment.',
    replaced: 'This link was opened in another tab.',
    full: 'The room is full.',
    expired: 'The request timed out. Refresh to ask again.',
    revoked: 'This link is no longer valid. Ask the host for a new one.',
  };

  const hex = (n) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => b.toString(16).padStart(2, '0')).join('');
  const secret = decodeURIComponent(location.hash.slice(1)).trim(); // the part after # never leaves this browser

  let pc = null;
  let client = null;
  let net = null;
  let media = new MediaStream();
  let started = false;      // user clicked "Click to start" (unlocks audio)
  let finalState = false;   // no reconnect after denied/kicked/etc.
  let hostStopped = false;  // host pressed "Stop stream"; viewers stay connected
  let jitterMs = null;
  let iceCfg = null;
  let chain = Promise.resolve();
  let early = [];           // ICE candidates that arrived before the offer (relays can reorder messages)
  let resyncs = 0;
  let watchdog = null;

  // ------------------------------------------------------------ overlay
  function overlay(text, showStart = false, code = '') {
    $('msg').textContent = text;
    $('startBtn').hidden = !showStart;
    $('code').textContent = code;
    $('codeBox').hidden = !code;
    $('overlay').hidden = false;
  }
  const hideOverlay = () => { $('overlay').hidden = true; };
  const mediaUp = () => !!pc && pc.connectionState === 'connected';

  // ------------------------------------------------------------ signaling (via client.js)
  function onState(s) {
    dbg('state', s.kind, s.state || '');
    if (s.kind === 'final') { finalState = true; closePeer(); v.srcObject = null; return overlay(FINAL[s.state] || 'Disconnected.'); }
    if (s.kind === 'waiting') return overlay('Waiting for the host to let you in…', false, s.code);
    if (mediaUp()) return; // a working stream is never covered by relay trouble
    if (s.kind === 'connecting') overlay('Connecting…');
    else if (s.kind === 'relay-down') overlay("Can't reach the relay servers. Check your internet connection. Retrying…");
    else if (s.kind === 'looking') overlay('Looking for the host… Is the host app running, and is this the newest link?');
    else if (s.kind === 'accepted' && !hostStopped) overlay('Connected. Waiting for video…');
  }

  function onAccepted(ice) {
    iceCfg = ice || WTRelay.ICE_SERVERS;
    if (pc || hostStopped) return; // already connecting, or the host paused the stream
    createPeer(iceCfg);
    armWatchdog();
  }

  function onSignal(d) { chain = chain.then(() => handleSignal(d)).catch((err) => console.error(err)); }

  const fingerprint = (sdp) => ((/^a=fingerprint:(\S+ \S+)/m.exec(sdp || '')) || [])[1] || '';

  async function handleSignal(d) {
    if (d.type === 'bye') {
      hostStopped = true;
      early = [];
      closePeer();
      v.srcObject = null;
      overlay('The host stopped the stream. It will resume when they start it again.');
    } else if (d.type === 'offer' && typeof d.sdp === 'string') {
      hostStopped = false;
      // The host rebuilt its side (new DTLS identity): start from a fresh peer connection.
      if (pc && pc.remoteDescription && fingerprint(pc.remoteDescription.sdp) !== fingerprint(d.sdp)) closePeer();
      if (!pc) createPeer(iceCfg || WTRelay.ICE_SERVERS);
      await pc.setRemoteDescription({ type: 'offer', sdp: d.sdp });
      for (const c of early.splice(0)) await pc.addIceCandidate(c).catch(() => {});
      await pc.setLocalDescription(await pc.createAnswer());
      client.signal({ type: 'answer', sdp: pc.localDescription.sdp });
      dbg('tx answer');
      armWatchdog();
    } else if (d.type === 'candidate' && d.candidate) {
      if (pc && pc.remoteDescription) await pc.addIceCandidate(d.candidate).catch(() => {});
      else early.push(d.candidate);
    }
  }

  // If the media link does not come up (a lost message, a blocked path), ask the host to offer again.
  function armWatchdog(ms = 30000) {
    clearTimeout(watchdog);
    watchdog = setTimeout(() => {
      if (finalState || hostStopped || mediaUp()) return;
      if (resyncs >= 3) return overlay('Could not connect. Ask the host to check the network, then refresh.');
      resyncs++;
      dbg('resync', resyncs);
      closePeer();
      client.resync();
      armWatchdog();
    }, ms);
  }

  // ------------------------------------------------------------ WebRTC
  function closePeer() {
    if (pc) { pc.onconnectionstatechange = pc.ontrack = pc.onicecandidate = null; pc.close(); pc = null; }
  }

  function createPeer(iceServers) {
    closePeer();
    media = new MediaStream();
    v.srcObject = media;
    const me = new RTCPeerConnection({ iceServers });
    pc = me;
    me.oniceconnectionstatechange = () => dbg('ICE', me.iceConnectionState);

    me.onicecandidate = (e) => { if (e.candidate && pc === me) client.signal({ type: 'candidate', candidate: e.candidate.toJSON() }); };
    me.ontrack = (e) => {
      media.addTrack(e.track); // host adds no stream ids, so build the stream ourselves
      applyJitter();
      v.muted = !started;
      v.play().catch(() => {});
      if (!started) overlay('Ready.', true);
      else hideOverlay();
    };
    me.ondatachannel = (e) => {
      e.channel.onmessage = (ev) => { try { onCtl(JSON.parse(ev.data), e.channel); } catch { /* ignore */ } };
    };
    me.onconnectionstatechange = () => {
      if (pc !== me) return;
      dbg('peer', me.connectionState);
      if (me.connectionState === 'connected') { clearTimeout(watchdog); resyncs = 0; }
      else if (me.connectionState === 'failed') {
        overlay('Connection failed. Trying again…');
        armWatchdog(2000);
      } else if (me.connectionState === 'disconnected') overlay('Connection interrupted…');
    };
  }

  // Host-driven jitter buffer. Unit: milliseconds, allowed range 0-4000 (Chrome/Edge 124+).
  function applyJitter(channel) {
    if (jitterMs == null || !pc) return;
    let supported = false;
    for (const r of pc.getReceivers()) {
      try {
        if ('jitterBufferTarget' in r) { r.jitterBufferTarget = jitterMs; supported = true; }
        else if ('playoutDelayHint' in r) { r.playoutDelayHint = jitterMs / 1000; supported = true; } // legacy, seconds
      } catch (e) { console.warn('jitter buffer:', e); }
    }
    if (channel && channel.readyState === 'open') channel.send(JSON.stringify({ type: 'jitter-ack', ms: jitterMs, supported }));
  }

  function onCtl(m, channel) {
    switch (m.type) {
      case 'jitter':
        jitterMs = Math.max(0, Math.min(4000, Number(m.ms) || 0));
        applyJitter(channel);
        break;
      case 'sub': // step 5: { type: 'sub', text: '...' }
        $('subs').textContent = m.text || '';
        $('subs').hidden = !m.text;
        break;
    }
  }

  // ------------------------------------------------------------ UI
  $('startBtn').onclick = () => {
    started = true;
    v.muted = false;
    v.play().catch(() => {});
    hideOverlay();
  };
  v.addEventListener('playing', () => { if (started) hideOverlay(); });

  // ---- fullscreen
  // Desktop and Android: fullscreen the whole page, so the controls and messages stay on screen.
  // iPhone Safari has no page fullscreen at all: only the <video> itself can go fullscreen (native player).
  const root = document.documentElement;
  const isFs = () => !!(document.fullscreenElement || document.webkitFullscreenElement || v.webkitDisplayingFullscreen);
  const coarse = matchMedia('(hover: none) and (pointer: coarse)').matches;

  async function enterFs() {
    try {
      if (root.requestFullscreen) await root.requestFullscreen({ navigationUI: 'hide' });
      else if (root.webkitRequestFullscreen) root.webkitRequestFullscreen();
      else if (v.webkitEnterFullscreen) v.webkitEnterFullscreen();
      else return;
      // Landscape suits video; only possible once fullscreen (Android Chrome). Failure is harmless.
      if (coarse && screen.orientation && screen.orientation.lock) screen.orientation.lock('landscape').catch(() => {});
    } catch {
      try { if (v.webkitEnterFullscreen) v.webkitEnterFullscreen(); } catch { /* not possible here */ }
    }
  }
  function exitFs() {
    if (screen.orientation && screen.orientation.unlock) { try { screen.orientation.unlock(); } catch { /* ignore */ } }
    if (document.exitFullscreen) document.exitFullscreen().catch(() => {});
    else if (document.webkitExitFullscreen) document.webkitExitFullscreen();
    else if (v.webkitExitFullscreen) v.webkitExitFullscreen();
  }
  const toggleFs = () => (isFs() ? exitFs() : enterFs());
  const syncFs = () => {
    const on = isFs();
    $('fsIcon').setAttribute('href', on ? '#i-fs-exit' : '#i-fs-enter');
    $('fsBtn').setAttribute('aria-label', on ? 'Exit fullscreen' : 'Fullscreen');
    $('fsBtn').title = on ? 'Exit fullscreen (F)' : 'Fullscreen (F)';
  };
  ['fullscreenchange', 'webkitfullscreenchange'].forEach((ev) => document.addEventListener(ev, syncFs));
  ['webkitbeginfullscreen', 'webkitendfullscreen'].forEach((ev) => v.addEventListener(ev, syncFs));
  $('fsBtn').onclick = toggleFs;

  // ---- sound
  const syncSound = () => {
    const off = v.muted || v.volume === 0;
    $('muteIcon').setAttribute('href', off ? '#i-muted' : '#i-volume');
    $('muteBtn').setAttribute('aria-label', off ? 'Unmute' : 'Mute');
    $('muteBtn').title = off ? 'Unmute (M)' : 'Mute (M)';
    const pct = v.muted ? 0 : v.volume * 100;
    $('vol').value = v.muted ? 0 : v.volume;
    $('vol').style.setProperty('--pct', `${pct}%`);
  };
  v.addEventListener('volumechange', syncSound);
  $('muteBtn').onclick = () => {
    if (v.muted || v.volume === 0) { v.muted = false; if (v.volume === 0) v.volume = 1; } else v.muted = true;
    syncSound();
  };
  $('vol').oninput = (e) => { const x = Number(e.target.value); v.volume = x; v.muted = x === 0; syncSound(); };
  syncSound();

  // ---- showing / hiding the controls
  let idleTimer;
  const wake = () => {
    document.body.classList.remove('idle');
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => document.body.classList.add('idle'), 3000);
  };
  ['mousemove', 'keydown'].forEach((ev) => document.addEventListener(ev, wake));
  $('controls').addEventListener('pointerdown', wake);

  // Touch: tap the picture to show/hide the controls, double-tap for fullscreen.
  let tapTimer = null;
  $('stage').addEventListener('click', (e) => {
    if (!(e.pointerType === 'touch' || (e.pointerType === undefined && coarse))) return; // mouse users have hover + double-click
    if (tapTimer) { clearTimeout(tapTimer); tapTimer = null; toggleFs(); return; }
    tapTimer = setTimeout(() => {
      tapTimer = null;
      if (document.body.classList.contains('idle')) wake();
      else { clearTimeout(idleTimer); document.body.classList.add('idle'); }
    }, 260);
  });
  v.ondblclick = toggleFs; // mouse
  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.key === 'f' || e.key === 'F') toggleFs();
    else if (e.key === 'm' || e.key === 'M') $('muteBtn').click();
  });
  wake();

  // ------------------------------------------------------------ start
  function brokerList() { // `?relay=` is for local testing only
    const local = location.hostname === '127.0.0.1' || location.hostname === 'localhost';
    const q = new URLSearchParams(location.search).get('relay');
    return local && q ? q.split(',').map((x) => x.trim()).filter(Boolean) : WTRelay.BROKERS;
  }

  window.addEventListener('error', (e) => dbg('error', e.message));
  window.wt = { get pc() { return pc; }, get client() { return client; }, get net() { return net; } }; // console debugging

  (async function main() {
    if (!WTRelay.validSecret(secret)) return overlay('This link is incomplete. Ask the host for the full link.');
    if (!(window.isSecureContext && window.crypto && crypto.subtle && window.RTCPeerConnection)) {
      return overlay('This browser or page cannot run the viewer. Use a recent Chrome, Edge or Firefox over https.');
    }
    overlay('Connecting…');
    const room = await WTRelay.deriveRoom(secret);
    // One id per browser and invite: lets an approved viewer rejoin after a refresh without a new prompt.
    const cidKey = `wt-cid-${room.topic}`;
    const cid = (() => {
      try {
        let c = localStorage.getItem(cidKey);
        if (!/^[0-9a-f]{32}$/.test(c || '')) { c = hex(16); localStorage.setItem(cidKey, c); }
        return c;
      } catch { return hex(16); }
    })();
    net = new WTRelay.RelayNet({ brokers: brokerList(), WebSocket: window.WebSocket, log: dbg });
    client = new WTClientLib.WTClient({ net, room, cid, pid: hex(8), isMediaUp: mediaUp, onState, onAccepted, onSignal });
    window.addEventListener('pagehide', () => client.leaveNow());
    await client.start();
  })().catch((e) => { console.error(e); overlay('Something went wrong starting the viewer. Try refreshing.'); });
})();

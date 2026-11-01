// yNotes: tiny Algorand wallet + encrypted self-notes stored on-chain.
import algosdk from 'algosdk';
import QRCode from 'qrcode';
import jsQR from 'jsqr';

const NETS = {
  testnet: { algod: 'https://testnet-api.algonode.cloud', idx: 'https://testnet-idx.algonode.cloud', explorer: 'https://lora.algokit.io/testnet' },
  mainnet: { algod: 'https://mainnet-api.algonode.cloud', idx: 'https://mainnet-idx.algonode.cloud', explorer: 'https://lora.algokit.io/mainnet' },
};
const NOTE_PREFIX = 'yn1:';   // encrypted note:  "yn1:" + iv(12) + AES-GCM ciphertext
const READ_PREFIX = 'ynr1:';  // read marker:     "ynr1:" + txid of the note
const MAX_NOTE = 1024;
const enc = new TextEncoder();
const dec = new TextDecoder();

const $ = (id) => document.getElementById(id);
const state = { net: localStorage.getItem('yn_net') || 'testnet', acct: null, key: null, notes: [], read: new Set(), pending: [] };

// ---------- helpers ----------
const b64 = (u8) => btoa(String.fromCharCode(...u8));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const concat = (...arrs) => {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
};
const startsWith = (u8, prefix) => {
  const p = enc.encode(prefix);
  return u8.length >= p.length && p.every((b, i) => u8[i] === b);
};
const net = () => NETS[state.net];
const algod = () => new algosdk.Algodv2('', net().algod, '');
const addr = () => state.acct.addr.toString();
const fmtAlgo = (micro) => (Number(micro) / 1e6).toLocaleString(undefined, { maximumFractionDigits: 6 });

function toast(msg, isErr = false) {
  const t = $('toast');
  t.textContent = msg;
  t.className = 'show' + (isErr ? ' err' : '');
  clearTimeout(toast.t);
  toast.t = setTimeout(() => (t.className = ''), isErr ? 6000 : 3000);
}
function busy(btn, on, label) {
  if (on) { btn.dataset.label = btn.textContent; btn.textContent = label || 'Working…'; btn.disabled = true; }
  else { btn.textContent = btn.dataset.label; btn.disabled = false; }
}

// ---------- crypto ----------
async function deriveKey(sk) {
  const hash = await crypto.subtle.digest('SHA-256', concat(enc.encode('ynotes-v1'), sk.slice(0, 32)));
  return crypto.subtle.importKey('raw', hash, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function encryptNote(text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, state.key, enc.encode(text)));
  return concat(enc.encode(NOTE_PREFIX), iv, ct);
}
async function decryptNote(u8) {
  const body = u8.slice(enc.encode(NOTE_PREFIX).length);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: body.slice(0, 12) }, state.key, body.slice(12));
  return dec.decode(pt);
}
const noteBytesFor = (text) => enc.encode(NOTE_PREFIX).length + 12 + 16 + enc.encode(text).length;

// ---------- chain ----------
async function sendPayment(to, microAmount, noteBytes) {
  const sp = await algod().getTransactionParams().do();
  const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: addr(), receiver: to, amount: microAmount, note: noteBytes, suggestedParams: sp,
  });
  const signed = txn.signTxn(state.acct.sk);
  const { txid } = await algod().sendRawTransaction(signed).do();
  await algosdk.waitForConfirmation(algod(), txid, 6);
  return txid;
}

async function fetchByPrefix(prefix) {
  const out = [];
  let next = '';
  do {
    const q = new URLSearchParams({ 'note-prefix': b64(enc.encode(prefix)), limit: '1000' });
    if (next) q.set('next', next);
    const r = await fetch(`${net().idx}/v2/accounts/${addr()}/transactions?${q}`);
    if (!r.ok) throw new Error(`Indexer error ${r.status}`);
    const j = await r.json();
    out.push(...(j.transactions || []));
    next = j['next-token'] || '';
  } while (next);
  // Only trust transactions I signed myself (anyone can send me a tx with a matching prefix).
  return out.filter((t) => t.sender === addr());
}

async function refreshBalance() {
  try {
    const r = await fetch(`${net().algod}/v2/accounts/${addr()}`);
    const j = await r.json();
    $('balance').textContent = fmtAlgo(j.amount ?? 0) + ' ALGO';
    $('fundHint').hidden = !(state.net === 'testnet' && Number(j.amount ?? 0) < 200000);
  } catch (e) {
    $('balance').textContent = '?';
  }
}

async function refreshNotes() {
  $('notesStatus').textContent = 'Loading…';
  try {
    const [noteTxs, readTxs] = await Promise.all([fetchByPrefix(NOTE_PREFIX), fetchByPrefix(READ_PREFIX)]);
    for (const t of readTxs) state.read.add(dec.decode(unb64(t.note)).slice(READ_PREFIX.length));
    const notes = [];
    for (const t of noteTxs) {
      try {
        notes.push({ id: t.id, time: t['round-time'] * 1000, text: await decryptNote(unb64(t.note)) });
      } catch { /* not decryptable with this key: ignore */ }
    }
    const known = new Set(notes.map((n) => n.id));
    state.pending = state.pending.filter((p) => !known.has(p.id)); // indexer caught up
    state.notes = notes;
    $('notesStatus').textContent = '';
  } catch (e) {
    $('notesStatus').textContent = 'Could not load notes: ' + e.message;
  }
  renderNotes();
}

// ---------- UI: notes ----------
function renderNotes() {
  const showRead = $('showRead').checked;
  const all = [...state.pending, ...state.notes].sort((a, b) => b.time - a.time);
  const list = all.filter((n) => showRead || !state.read.has(n.id));
  const ul = $('notes');
  ul.innerHTML = '';
  for (const n of list) {
    const li = document.createElement('li');
    const isRead = state.read.has(n.id);
    if (isRead) li.className = 'read';
    const text = document.createElement('div');
    text.className = 'text';
    text.textContent = n.text;
    const meta = document.createElement('div');
    meta.className = 'meta';
    const time = document.createElement('span');
    time.textContent = new Date(n.time).toLocaleString();
    meta.append(time);
    const copy = document.createElement('button');
    copy.textContent = 'Copy';
    copy.className = 'small ghost';
    copy.onclick = () => navigator.clipboard.writeText(n.text).then(() => toast('Copied'));
    meta.append(copy);
    if (!isRead) {
      const btn = document.createElement('button');
      btn.textContent = '✓ Mark read';
      btn.className = 'small';
      btn.onclick = () => markRead(n.id, btn);
      meta.append(btn);
    }
    li.append(text, meta);
    ul.append(li);
  }
  const unread = all.filter((n) => !state.read.has(n.id)).length;
  $('noteCount').textContent = `${unread} unread / ${all.length} total`;
  if (!list.length && !$('notesStatus').textContent) $('notesStatus').textContent = 'No notes yet.';
}

async function saveNote() {
  const text = $('noteText').value.trim();
  if (!text) return;
  if (noteBytesFor(text) > MAX_NOTE) return toast('Note too long', true);
  const btn = $('saveNote');
  busy(btn, true, 'Saving…');
  try {
    const id = await sendPayment(addr(), 0, await encryptNote(text));
    state.pending.push({ id, time: Date.now(), text });
    $('noteText').value = '';
    updateCounter();
    renderNotes();
    refreshBalance();
    toast('Note saved on-chain');
  } catch (e) {
    toast('Save failed: ' + e.message, true);
  } finally {
    busy(btn, false);
  }
}

async function markRead(id, btn) {
  busy(btn, true, '…');
  try {
    await sendPayment(addr(), 0, enc.encode(READ_PREFIX + id));
    state.read.add(id);
    renderNotes();
    refreshBalance();
  } catch (e) {
    toast('Failed: ' + e.message, true);
    busy(btn, false);
  }
}

function updateCounter() {
  const n = noteBytesFor($('noteText').value.trim());
  $('counter').textContent = `${n} / ${MAX_NOTE} bytes`;
  $('counter').classList.toggle('over', n > MAX_NOTE);
}

// ---------- UI: send ----------
async function sendCoins() {
  const to = $('sendTo').value.trim();
  const amt = parseFloat($('sendAmt').value);
  if (!algosdk.isValidAddress(to)) return toast('Invalid address', true);
  if (!(amt > 0)) return toast('Invalid amount', true);
  if (!confirm(`Send ${amt} ALGO to\n${to}\non ${state.net}?`)) return;
  const btn = $('sendBtn');
  busy(btn, true, 'Sending…');
  try {
    const memo = $('sendMemo').value.trim();
    const txid = await sendPayment(to, Math.round(amt * 1e6), memo ? enc.encode(memo) : undefined);
    toast('Sent! ' + txid.slice(0, 10) + '…');
    $('sendTo').value = $('sendAmt').value = $('sendMemo').value = '';
    refreshBalance();
  } catch (e) {
    toast('Send failed: ' + e.message, true);
  } finally {
    busy(btn, false);
  }
}

// ---------- QR ----------
async function showQR(text, title, warn) {
  $('qrTitle').textContent = title;
  $('qrWarn').textContent = warn || '';
  $('qrText').textContent = text;
  await QRCode.toCanvas($('qrCanvas'), text, { width: 280, margin: 2, errorCorrectionLevel: 'M' });
  $('qrModal').hidden = false;
}

let scanStream = null;
async function scanQR(onResult) {
  $('scanModal').hidden = false;
  const video = $('scanVideo');
  try {
    scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
  } catch (e) {
    closeScan();
    return toast('Camera unavailable here (' + e.name + '). Use your phone camera app and paste the text instead.', true);
  }
  video.srcObject = scanStream;
  await video.play();
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  const tick = () => {
    if (!scanStream) return;
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      ctx.drawImage(video, 0, 0);
      const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(img.data, img.width, img.height);
      if (code && code.data) { closeScan(); onResult(code.data); return; }
    }
    requestAnimationFrame(tick);
  };
  tick();
}
function closeScan() {
  if (scanStream) scanStream.getTracks().forEach((t) => t.stop());
  scanStream = null;
  $('scanModal').hidden = true;
}

// Seed QR: when served over http(s) it's a link (phone camera opens app directly);
// the seed lives in the #fragment, which browsers never send to the server.
function seedQRText(m) {
  return location.protocol.startsWith('http') ? `${location.origin}${location.pathname}#m=${m.replace(/ /g, '-')}` : m;
}
function extractMnemonic(s) {
  s = s.trim();
  const i = s.indexOf('#m=');
  if (i >= 0) s = decodeURIComponent(s.slice(i + 3));
  return s.toLowerCase().replace(/[-,\s]+/g, ' ').trim();
}

// ---------- account ----------
async function login(mnemonic) {
  const acct = algosdk.mnemonicToSecretKey(mnemonic); // throws if invalid
  state.acct = acct;
  state.key = await deriveKey(acct.sk);
  state.notes = []; state.pending = []; state.read = new Set();
  localStorage.setItem('yn_m', mnemonic);
  $('setup').hidden = true;
  $('main').hidden = false;
  $('address').textContent = addr();
  $('explorer').href = `${net().explorer}/account/${addr()}`;
  refreshBalance();
  refreshNotes();
}
function tryLogin(raw) {
  login(extractMnemonic(raw)).catch((e) => toast('Invalid 25-word phrase: ' + e.message, true));
}
function logout() {
  if (!confirm('Forget wallet on THIS device? (Notes stay on-chain. You need your QR / 25 words to log in again.)')) return;
  localStorage.removeItem('yn_m');
  location.reload();
}

// ---------- wire up ----------
function init() {
  $('netSel').value = state.net;
  $('netSel').onchange = () => {
    state.net = $('netSel').value;
    localStorage.setItem('yn_net', state.net);
    document.body.dataset.net = state.net;
    if (state.acct) login(localStorage.getItem('yn_m'));
  };
  document.body.dataset.net = state.net;

  $('createBtn').onclick = () => {
    const { sk } = algosdk.generateAccount();
    const m = algosdk.secretKeyToMnemonic(sk);
    login(m).then(() => showQR(seedQRText(m), 'Your secret key QR', 'Save/print this QR now. Anyone with it can read your notes and spend your coins.'));
  };
  $('importBtn').onclick = () => tryLogin($('importText').value);
  $('scanImportBtn').onclick = () => scanQR(tryLogin);

  $('saveNote').onclick = saveNote;
  $('noteText').oninput = updateCounter;
  $('noteText').onkeydown = (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) saveNote(); };
  $('refreshBtn').onclick = () => { refreshBalance(); refreshNotes(); };
  $('showRead').onchange = renderNotes;

  $('sendBtn').onclick = sendCoins;
  $('scanAddrBtn').onclick = () => scanQR((s) => ($('sendTo').value = s.replace(/^algorand:\/\//i, '').split('?')[0]));
  $('receiveBtn').onclick = () => showQR(addr(), 'Receive ALGO', 'Share this address to receive coins.');
  $('copyAddr').onclick = () => navigator.clipboard.writeText(addr()).then(() => toast('Address copied'));
  $('backupBtn').onclick = () => {
    if (!confirm('Show your SECRET key QR? Make sure nobody is watching your screen.')) return;
    const m = localStorage.getItem('yn_m');
    showQR(seedQRText(m), 'Your secret key QR', 'Scan this on another device to open your notes. Keep it private!');
  };
  $('logoutBtn').onclick = logout;
  $('qrClose').onclick = () => { $('qrModal').hidden = true; $('qrText').hidden = true; };
  $('qrShowText').onclick = () => ($('qrText').hidden = !$('qrText').hidden);
  $('scanClose').onclick = closeScan;

  // Login from a scanned seed link (#m=...), then wipe it from the address bar/history.
  if (location.hash.startsWith('#m=')) {
    const m = extractMnemonic(location.hash);
    history.replaceState(null, '', location.pathname + location.search);
    return tryLogin(m);
  }
  const saved = localStorage.getItem('yn_m');
  if (saved) tryLogin(saved);
}
init();

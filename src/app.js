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
const PHOTO_PREFIX = 'ynp1:'; // photo header:    "ynp1:" + iv(12) + AES-GCM of JSON {p: photo id, n: chunks, b: bytes, c: caption}
const CHUNK_PREFIX = 'ync1:'; // photo chunk:     "ync1:" + photo id(16 hex) + index(2) + slice of the encrypted JPEG
const MAX_NOTE = 1024;
const CHUNK_DATA = MAX_NOTE - CHUNK_PREFIX.length - 16 - 2;
const PHOTO_SIDE = 800;       // photos are shrunk to 800px, grayscale, JPEG quality 0.4 to keep fees low
const PHOTO_QUALITY = 0.4;
const MAX_PHOTO = 1024 * 1024;
const FEE = 1000;             // microAlgos per transaction
const enc = new TextEncoder();
const dec = new TextDecoder();

const $ = (id) => document.getElementById(id);
const state = { net: localStorage.getItem('yn_net') || 'testnet', acct: null, key: null, notes: [], read: new Set(), pending: [], photo: null };
const photoUrls = new Map(); // photo id -> Promise<object URL>

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
async function encryptBytes(u8) { // iv(12) + ciphertext
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return concat(iv, new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, state.key, u8)));
}
const decryptBytes = async (u8) => new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u8.slice(0, 12) }, state.key, u8.slice(12)));
const encryptNote = async (text, prefix = NOTE_PREFIX) => concat(enc.encode(prefix), await encryptBytes(enc.encode(text)));
const decryptNote = async (u8, prefix = NOTE_PREFIX) => dec.decode(await decryptBytes(u8.slice(prefix.length)));
const photoHeader = (photo, caption) => JSON.stringify({ p: photo.id, n: photo.chunks.length, b: photo.bytes, c: caption });
const noteBytesFor = (text) => state.photo
  ? PHOTO_PREFIX.length + 12 + 16 + enc.encode(photoHeader(state.photo, text)).length
  : NOTE_PREFIX.length + 12 + 16 + enc.encode(text).length;

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

// Sends many 0-ALGO self-payments carrying `notes`, in atomic groups of 16.
async function sendNotes(notes, onProgress) {
  const sp = await algod().getTransactionParams().do();
  const firstIds = [];
  for (let i = 0; i < notes.length; i += 16) {
    const txns = notes.slice(i, i + 16).map((note) => algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: addr(), receiver: addr(), amount: 0, note, suggestedParams: sp,
    }));
    if (txns.length > 1) algosdk.assignGroupID(txns);
    await algod().sendRawTransaction(txns.map((t) => t.signTxn(state.acct.sk))).do();
    firstIds.push(txns[0].txID());
    onProgress(Math.min(i + 16, notes.length), notes.length);
  }
  for (const id of firstIds) await algosdk.waitForConfirmation(algod(), id, 10);
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
    const [noteTxs, readTxs, photoTxs] = await Promise.all([fetchByPrefix(NOTE_PREFIX), fetchByPrefix(READ_PREFIX), fetchByPrefix(PHOTO_PREFIX)]);
    for (const t of readTxs) state.read.add(dec.decode(unb64(t.note)).slice(READ_PREFIX.length));
    const notes = [];
    for (const t of noteTxs) {
      try {
        notes.push({ id: t.id, time: t['round-time'] * 1000, text: await decryptNote(unb64(t.note)) });
      } catch { /* not decryptable with this key: ignore */ }
    }
    for (const t of photoTxs) {
      try {
        const h = JSON.parse(await decryptNote(unb64(t.note), PHOTO_PREFIX));
        notes.push({ id: t.id, time: t['round-time'] * 1000, text: h.c || '', photo: { id: h.p, n: h.n, bytes: h.b } });
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

// ---------- photos ----------
// Shrink to PHOTO_SIDE px, grayscale, low-quality JPEG.
async function compressPhoto(file) {
  const url = URL.createObjectURL(file);
  try {
    const img = new Image();
    img.src = url;
    await img.decode();
    const s = Math.min(1, PHOTO_SIDE / Math.max(img.naturalWidth, img.naturalHeight));
    const c = document.createElement('canvas');
    c.width = Math.max(1, Math.round(img.naturalWidth * s));
    c.height = Math.max(1, Math.round(img.naturalHeight * s));
    const ctx = c.getContext('2d');
    ctx.fillStyle = '#fff'; // transparent PNGs would otherwise turn black
    ctx.fillRect(0, 0, c.width, c.height);
    ctx.drawImage(img, 0, 0, c.width, c.height);
    const d = ctx.getImageData(0, 0, c.width, c.height);
    const px = d.data;
    for (let i = 0; i < px.length; i += 4) px[i] = px[i + 1] = px[i + 2] = 0.299 * px[i] + 0.587 * px[i + 1] + 0.114 * px[i + 2];
    ctx.putImageData(d, 0, 0);
    const blob = await new Promise((r) => c.toBlob(r, 'image/jpeg', PHOTO_QUALITY));
    return new Uint8Array(await blob.arrayBuffer());
  } finally {
    URL.revokeObjectURL(url);
  }
}

async function pickPhoto(file) {
  if (!file) return;
  try {
    const jpeg = await compressPhoto(file);
    if (jpeg.length > MAX_PHOTO) return toast('Photo too large even after shrinking', true);
    const id = [...crypto.getRandomValues(new Uint8Array(8))].map((b) => b.toString(16).padStart(2, '0')).join('');
    const blob = await encryptBytes(jpeg);
    const chunks = [];
    for (let i = 0, k = 0; i < blob.length; i += CHUNK_DATA, k++) {
      chunks.push(concat(enc.encode(CHUNK_PREFIX + id), new Uint8Array([k >> 8, k & 255]), blob.slice(i, i + CHUNK_DATA)));
    }
    const url = URL.createObjectURL(new Blob([jpeg], { type: 'image/jpeg' }));
    state.photo = { id, chunks, bytes: jpeg.length, url };
    $('photoPreview').src = url;
    $('photoInfo').textContent = `${(jpeg.length / 1024).toFixed(0)} KB · ${chunks.length + 1} txns ≈ ${fmtAlgo((chunks.length + 1) * FEE)} ALGO`;
    $('photoBox').hidden = false;
  } catch (e) {
    toast('Could not read photo: ' + e.message, true);
  }
  updateCounter();
}
function clearPhoto(keepUrl) {
  if (state.photo && !keepUrl) URL.revokeObjectURL(state.photo.url);
  state.photo = null;
  $('photoFile').value = '';
  $('photoBox').hidden = true;
  updateCounter();
}

function loadPhoto(p) {
  if (!photoUrls.has(p.id)) {
    photoUrls.set(p.id, (async () => {
      const txs = await fetchByPrefix(CHUNK_PREFIX + p.id);
      const parts = [];
      for (const t of txs) {
        const u8 = unb64(t.note);
        const at = CHUNK_PREFIX.length + 16;
        parts[(u8[at] << 8) | u8[at + 1]] = u8.slice(at + 2);
      }
      if (parts.length !== p.n || parts.includes(undefined)) throw new Error('photo not fully on-chain yet');
      const jpeg = await decryptBytes(concat(...parts));
      return URL.createObjectURL(new Blob([jpeg], { type: 'image/jpeg' }));
    })().catch((e) => { photoUrls.delete(p.id); throw e; }));
  }
  return photoUrls.get(p.id);
}

// Phones: share sheet ("Save Image" / "Save to Photos"). Elsewhere: plain download.
async function savePhoto(n) {
  try {
    const blob = await (await fetch(await loadPhoto(n.photo))).blob();
    const name = `ynotes-${new Date(n.time).toISOString().slice(0, 19).replace(/[T:]/g, '-')}.jpg`;
    const file = new File([blob], name, { type: 'image/jpeg' });
    if (navigator.canShare?.({ files: [file] })) return await navigator.share({ files: [file] });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(file);
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 10000);
  } catch (e) {
    if (e.name !== 'AbortError') toast('Could not save photo: ' + e.message, true);
  }
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
    if (n.photo) {
      const img = document.createElement('img');
      img.className = 'photo';
      img.alt = `📷 Loading photo (${(n.photo.bytes / 1024).toFixed(0)} KB)…`;
      img.onclick = () => img.src && window.open(img.src);
      loadPhoto(n.photo).then((u) => (img.src = u), (e) => (img.alt = '📷 Could not load photo: ' + e.message));
      li.append(img);
    }
    const meta = document.createElement('div');
    meta.className = 'meta';
    const time = document.createElement('span');
    time.textContent = new Date(n.time).toLocaleString();
    meta.append(time);
    const copy = document.createElement('button');
    copy.textContent = 'Copy';
    copy.className = 'small ghost';
    copy.onclick = () => navigator.clipboard.writeText(n.text).then(() => toast('Copied'));
    if (n.photo) {
      copy.textContent = 'Save photo';
      copy.onclick = () => savePhoto(n);
    }
    if (n.text || n.photo) meta.append(copy);
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
  const photo = state.photo;
  if (!text && !photo) return;
  if (noteBytesFor(text) > MAX_NOTE) return toast('Note too long', true);
  if (photo && !confirm(`Save photo on-chain?\n${photo.chunks.length + 1} transactions ≈ ${fmtAlgo((photo.chunks.length + 1) * FEE)} ALGO in fees.`)) return;
  const btn = $('saveNote');
  busy(btn, true, 'Saving…');
  try {
    let id;
    if (photo) {
      // Chunks first; the header (which makes the photo show up) only once they are all confirmed.
      await sendNotes(photo.chunks, (done, total) => (btn.textContent = `Uploading ${done}/${total}…`));
      btn.textContent = 'Saving…';
      id = await sendPayment(addr(), 0, await encryptNote(photoHeader(photo, text), PHOTO_PREFIX));
      photoUrls.set(photo.id, Promise.resolve(photo.url));
      state.pending.push({ id, time: Date.now(), text, photo: { id: photo.id, n: photo.chunks.length, bytes: photo.bytes } });
      clearPhoto(true);
    } else {
      id = await sendPayment(addr(), 0, await encryptNote(text));
      state.pending.push({ id, time: Date.now(), text });
    }
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

// The key QR holds just the 25 words (never a link, so it can't end up in browser/scanner history).
function extractMnemonic(s) {
  return s.toLowerCase().replace(/[-,\s]+/g, ' ').trim();
}

// ---------- PIN vault: the 25 words are stored encrypted with a PIN-derived key ----------
const VAULT = 'yn_v';
const PBKDF2_ITER = 600000;
async function pinKey(pin, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function saveVault(mnemonic, pin) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await pinKey(pin, salt), enc.encode(mnemonic)));
  const addr = algosdk.mnemonicToSecretKey(mnemonic).addr.toString(); // public, lets us match a scanned QR without the PIN
  localStorage.setItem(VAULT, JSON.stringify({ v: 1, addr, salt: b64(salt), iv: b64(iv), ct: b64(ct) }));
  localStorage.removeItem('yn_m'); // drop any old unencrypted copy
}
async function openVault(pin) { // throws on wrong PIN
  const v = JSON.parse(localStorage.getItem(VAULT));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(v.iv) }, await pinKey(pin, unb64(v.salt)), unb64(v.ct));
  return dec.decode(pt);
}

// PIN dialog. Resolves to the PIN, or null if cancelled. `check` may throw to reject the PIN.
function askPin({ title, confirmPin = false, check }) {
  return new Promise((resolve) => {
    const [p1, p2, msg] = [$('pinInput'), $('pinInput2'), $('pinMsg')];
    $('pinTitle').textContent = title;
    p1.value = p2.value = msg.textContent = '';
    p2.hidden = !confirmPin;
    $('pinModal').hidden = false;
    p1.focus();
    const done = (val) => { $('pinModal').hidden = true; $('pinOk').onclick = $('pinCancel').onclick = p1.onkeydown = p2.onkeydown = null; resolve(val); };
    const ok = async () => {
      const pin = p1.value;
      if (confirmPin && pin.length < 4) return (msg.textContent = 'Use at least 4 characters (6+ is safer).');
      if (confirmPin && pin !== p2.value) return (msg.textContent = 'PINs do not match.');
      if (check) {
        $('pinOk').disabled = true;
        msg.textContent = 'Checking…';
        try { await check(pin); } catch { msg.textContent = 'Wrong PIN.'; p1.value = ''; p1.focus(); return; }
        finally { $('pinOk').disabled = false; }
      }
      done(pin);
    };
    $('pinOk').onclick = ok;
    $('pinCancel').onclick = () => done(null);
    p1.onkeydown = p2.onkeydown = (e) => { if (e.key === 'Enter') ok(); };
  });
}

// ---------- account ----------
async function login(mnemonic) {
  const acct = algosdk.mnemonicToSecretKey(mnemonic); // throws if invalid
  state.acct = acct;
  state.mnemonic = mnemonic;
  state.key = await deriveKey(acct.sk);
  state.notes = []; state.pending = []; state.read = new Set();
  $('setup').hidden = $('lock').hidden = true;
  $('main').hidden = false;
  $('address').textContent = addr();
  QRCode.toCanvas($('addrQR'), addr(), { width: 160, margin: 2 });
  $('explorer').href = `${net().explorer}/account/${addr()}`;
  refreshBalance();
  refreshNotes();
}

// New wallet on this device (create / paste / scan): validate, set a PIN, store encrypted.
async function setupWallet(raw) {
  const m = extractMnemonic(raw);
  try { algosdk.mnemonicToSecretKey(m); } catch (e) { toast('Invalid 25-word phrase: ' + e.message, true); return false; }
  const pin = await askPin({ title: 'Set a PIN for this device', confirmPin: true });
  if (pin === null) return false;
  await saveVault(m, pin);
  await login(m);
  return true;
}

async function unlock() {
  const btn = $('unlockBtn');
  busy(btn, true, 'Unlocking…');
  try {
    await login(await openVault($('unlockPin').value));
    $('unlockPin').value = '';
  } catch {
    toast('Wrong PIN', true);
    $('unlockPin').select();
  } finally {
    busy(btn, false);
  }
}

function logout() {
  if (!confirm('Forget wallet on THIS device? (Notes stay on-chain. You need your QR / 25 words to log in again.)')) return;
  localStorage.removeItem(VAULT);
  localStorage.removeItem('yn_m');
  location.reload();
}

// ---------- wire up ----------
async function init() {
  $('netSel').value = state.net;
  $('netSel').onchange = () => {
    state.net = $('netSel').value;
    localStorage.setItem('yn_net', state.net);
    document.body.dataset.net = state.net;
    if (state.acct) login(state.mnemonic);
  };
  document.body.dataset.net = state.net;

  $('createBtn').onclick = async () => {
    const { sk } = algosdk.generateAccount();
    const m = algosdk.secretKeyToMnemonic(sk);
    if (await setupWallet(m)) showQR(m, 'Your secret key QR', 'Save/print this QR now. Anyone with it can read your notes and spend your coins.');
  };
  $('importBtn').onclick = () => setupWallet($('importText').value).then((ok) => ok && ($('importText').value = ''));
  $('scanImportBtn').onclick = () => scanQR(setupWallet);
  $('unlockBtn').onclick = unlock;
  $('unlockPin').onkeydown = (e) => { if (e.key === 'Enter') unlock(); };
  $('forgetBtn').onclick = logout;

  $('saveNote').onclick = saveNote;
  $('noteText').oninput = updateCounter;
  $('noteText').onkeydown = (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) saveNote(); };
  $('photoBtn').onclick = () => $('photoFile').click();
  $('photoFile').onchange = () => pickPhoto($('photoFile').files[0]);
  $('photoClear').onclick = () => clearPhoto();
  $('refreshBtn').onclick = () => { refreshBalance(); refreshNotes(); };
  $('showRead').onchange = renderNotes;

  $('sendBtn').onclick = sendCoins;
  $('scanAddrBtn').onclick = () => scanQR((s) => ($('sendTo').value = s.replace(/^algorand:\/\//i, '').split('?')[0]));
  $('addrQR').onclick = () => showQR(addr(), 'Receive ALGO', 'Share this address to receive coins.');
  $('copyAddr').onclick = () => navigator.clipboard.writeText(addr()).then(() => toast('Address copied'));
  $('backupBtn').onclick = async () => {
    const pin = await askPin({ title: 'Enter PIN to show your key QR', check: openVault });
    if (pin === null) return;
    showQR(state.mnemonic, 'Your secret key QR', 'Scan this on another device to open your notes. Keep it private!');
  };
  $('changePinBtn').onclick = async () => {
    if (await askPin({ title: 'Current PIN', check: openVault }) === null) return;
    const pin = await askPin({ title: 'New PIN', confirmPin: true });
    if (pin === null) return;
    await saveVault(state.mnemonic, pin);
    toast('PIN changed');
  };
  $('lockBtn').onclick = () => location.reload();
  $('logoutBtn').onclick = logout;
  $('qrClose').onclick = () => { $('qrModal').hidden = true; $('qrText').hidden = true; };
  $('qrShowText').onclick = () => ($('qrText').hidden = !$('qrText').hidden);
  $('scanClose').onclick = closeScan;

  if (localStorage.getItem(VAULT)) return showLock();
  const legacy = localStorage.getItem('yn_m'); // saved by an older version without PIN
  if (legacy) {
    await login(legacy);
    const pin = await askPin({ title: 'Set a PIN to protect your saved key', confirmPin: true });
    if (pin !== null) { await saveVault(legacy, pin); toast('Key is now PIN-protected'); }
  }
}
function showLock() {
  $('setup').hidden = true;
  $('lock').hidden = false;
  $('unlockPin').focus();
}
init();

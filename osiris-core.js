/* ============================================================
   osiris-core.js
   Shared library core for the Osiris multi-theme bookshelf.

   Step 3 of the workplan ("Shared schema + storage key"): one
   storage key, one array of book records, read/written by every
   shelf (CLASSIQUE, Codex Collection, Lit Circle). Dark Shelf is
   intentionally NOT migrated yet — see workplan §2/§9 step 4.

   Each shelf already contains its own one-time migration logic
   (MIGRATION_FLAG + legacy key fold-in) that calls into the
   loadLibrary/saveLibrary/makeBookId functions below — this file
   only needs to provide the shared storage primitives, it does not
   need to know about any shelf's legacy key format.
   ============================================================ */
(function (global) {
  "use strict";

  var LIB_KEY = "osiris_library_books_v2";

  /* ---------------- id helper ---------------- */
  // Short, collision-safe-enough id: time-based prefix + random suffix.
  // Matches the "b_..." shape already used in the shared schema (§2).
  function makeBookId() {
    return "b_" + Date.now().toString(36) + "_" + Math.random().toString(36).slice(2, 9);
  }

  /* ---------------- load / save ---------------- */
  // Only ever touches the one shared key. Corrupt/missing data
  // resolves to an empty array rather than throwing, so a shelf
  // can always render something instead of crashing on read.
  function loadLibrary() {
    try {
      var raw = global.localStorage.getItem(LIB_KEY);
      var parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      return [];
    }
  }

  // Returns true on success, false on failure (quota exceeded,
  // storage disabled, etc.) — callers are expected to check this
  // and surface their own message (see §3's actionable-toast fix),
  // not to assume the write went through.
  function saveLibrary(books) {
    try {
      global.localStorage.setItem(LIB_KEY, JSON.stringify(books || []));
      return true;
    } catch (e) {
      return false;
    }
  }

  /* ---------------- hub api dependencies ---------------- */
  // Resolves Workplan 4.2: Hub API dropdown throws due to missing core.* calls
  var MSG = {
    SHELF_READY: "OSIRIS_SHELF_READY",
    SET_SORT: "OSIRIS_SET_SORT",
    LIBRARY_UPDATED: "OSIRIS_LIBRARY_UPDATED",
    // Sent once by the Hub after mounting a shelf, only when the Hub itself
    // was opened with a ?book=<id> URL param (e.g. from DASHBOARD.html's
    // per-book deep link). Payload: { id }. Each shelf scrolls/highlights
    // that book rather than trying to launch the file directly — a
    // programmatic window.open() this far removed from any direct user
    // click is unreliable across browsers' popup blockers, so every
    // shelf's handler surfaces the book's own existing "Open" affordance
    // (detail modal / expand-row / inline button) for the person to click
    // themselves instead of attempting to auto-launch it.
    OPEN_BOOK: "OSIRIS_OPEN_BOOK",
    // Hub -> shelf, pushed on SET_SORT/SET_LANG's SHELF_READY cadence (see
    // pushOpenMode() in MEIN_BIBLIOTHEK_HUB.html) and re-pushed live on
    // toggle. Payload: { mode: "reader" | "popup" | "newtab" }. Governs how
    // a shelf's "Open" action behaves — "reader" requests the Hub's native
    // in-app PDF reader (see REQUEST_READER_OPEN below; falls back to
    // "popup" behavior for non-PDF books or if resolution fails), "popup"
    // reuses one named window (one book at a time), "newtab" opens a fresh
    // tab per click (many books at once). A deliberate, Hub-level,
    // manually-set choice rather than per-shelf, since it's a behavioral
    // preference (like language/sort), not a per-skin cosmetic one.
    SET_OPEN_MODE: "OSIRIS_SET_OPEN_MODE",
    // Shelf -> Hub, sent instead of resolving/opening the file locally
    // when the current SET_OPEN_MODE is "reader". Payload: { id, title,
    // author }. The Hub — not the shelf — resolves the actual file
    // (OsirisCore.getFileHandle/resolveFileHandle/getFileBlob, the same
    // primitives every shelf already uses) since it has the same access
    // via the book id alone; this avoids piping large file buffers
    // through an extra postMessage hop. If resolution fails or the file
    // isn't a PDF (the native reader is PDF-only — no EPUB support), the
    // Hub falls back to opening it exactly as "popup" mode would, using
    // whatever bytes it already resolved. The reader itself talks to the
    // Hub over its own separate, raw postMessage channel — not through
    // core.listen()/core.send() at all, same reasoning as the Vault-keys
    // and Portfolio-navigation channels: a second embedded frame existing
    // alongside the shelf would otherwise fight over the listen()
    // singleton's one active target.
    REQUEST_READER_OPEN: "OSIRIS_REQUEST_READER_OPEN",
    // NOT "OSIRIS_SET_LANG" — deliberately unprefixed, unlike every other
    // MSG entry above. The Hub sends this via core.MSG.SET_LANG (see
    // MEIN_BIBLIOTHEK_HUB.html's pushLang()), and Classique listens for it
    // the same indirect way (handlers[OsirisCore.MSG.SET_LANG]). But three
    // shelves — the_codex_collection.html, the_dark_shelf.html, and
    // the_lit_circle.html — all listen on the *raw literal* 'SET_LANG'
    // string (matching each other, and matching the comments in their own
    // source calling it "the hub's own literal"). A prior value of
    // "OSIRIS_SET_LANG" here silently broke the language toggle on all
    // three of those shelves: the Hub would broadcast "OSIRIS_SET_LANG"
    // but their handlers were keyed on "SET_LANG" and never fired. Setting
    // the value to match the raw literal fixes the wire contract for every
    // shelf without touching any shelf file — Classique and the Hub both
    // reference the constant rather than a hardcoded value, so they pick
    // this up automatically.
    SET_LANG: "SET_LANG"
  };

  // Opt-in message-contract tracer. Off by default, zero cost when off (one
  // localStorage read per message — checked live rather than cached, so
  // toggling it in DevTools takes effect on the very next message without a
  // reload). Turn on from either the Hub or a shelf's console:
  //   localStorage.setItem('osirisDebug', '1')
  // then reload and watch messages cross the boundary in real time,
  // including the one thing static analysis can never fully rule out: a
  // message arriving with no handler registered for its type (contract
  // mismatch) — logged as a warning, not silently dropped like it is in
  // production. Turn back off with:
  //   localStorage.removeItem('osirisDebug')
  function _debugOn() {
    try { return global.localStorage && global.localStorage.getItem("osirisDebug") === "1"; }
    catch (e) { return false; } // localStorage can throw in some sandboxed/private-mode contexts
  }
  function _debugLog() {
    if (!_debugOn()) return;
    var args = ["[osiris-core]"].concat(Array.prototype.slice.call(arguments));
    (global.console && global.console.log || function () {}).apply(global.console, args);
  }

  function send(targetWindow, type, payload) {
    if (targetWindow && targetWindow.postMessage) {
      if (_debugOn()) {
        var label = targetWindow === global.parent ? "parent" : (targetWindow === global ? "self" : "iframe");
        _debugLog("SEND ->", label, type, payload);
      }
      targetWindow.postMessage({ type: type, payload: payload }, "*");
    }
  }

  // Registers at most one real `message` listener on `global`, no matter
  // how many times listen() is called. The Hub calls listen() again every
  // time it switches shelves (new iframe src -> new handlers to attach),
  // and same-origin iframe navigation does NOT create a new WindowProxy —
  // so calling addEventListener fresh each time (the old behavior) stacked
  // one listener per switch, each still holding the previous shelf's stale
  // handler closure. Fixed the same way PORTFOLIO_SEITE.html's own message
  // listener does it: register once, and resolve the *current* target/
  // handlers through a closure variable that later listen() calls update,
  // rather than re-registering.
  var _listenTarget = null;
  var _listenHandlers = null;
  var _listenerRegistered = false;

  function listen(win, handlers) {
    _listenTarget = win;
    _listenHandlers = handlers;
    if (_listenerRegistered) return;
    _listenerRegistered = true;
    global.addEventListener("message", function (e) {
      if (!_listenTarget || e.source !== _listenTarget) return;
      if (e.data && e.data.type && _listenHandlers && _listenHandlers[e.data.type]) {
        _debugLog("RECV <-", e.data.type, e.data.payload, "(handled)");
        _listenHandlers[e.data.type](e.data.payload);
      } else if (e.data && e.data.type && _debugOn()) {
        // Arrived from the expected source, has a type, but nothing in the
        // *current* handlers object matches it — this is exactly the shape
        // of bug the SET_LANG-prefix mismatch (see MSG.SET_LANG comment
        // above) was: a real message, silently going nowhere.
        _debugLog("RECV <-", e.data.type, e.data.payload, "(NO HANDLER REGISTERED — contract mismatch?)");
      }
    });
  }

  /* ---------------- Vault Bridge (real Portfolio contract) ----------------
     Ported from the actual PORTFOLIO_SEITE.html message contract. The vault
     itself (PBKDF2 -> AES-GCM, 4-digit passphrase, ki_safe_vault_store) lives
     entirely inside Portfolio — it is never present in this file or the Hub.
     Portfolio does NOT broadcast a vault "state" and does NOT answer a
     "request state" query; the previous OSIRIS_VAULT_STATE / OSIRIS_REQUEST_
     VAULT message types here were speculative and matched nothing Portfolio
     actually sends, which is why the Hub's vault status always fell back to
     "locked/unavailable" even against a genuinely unlocked vault.

     What Portfolio really does: when the user clicks "Apply Keys" on its
     side, it posts already-decrypted keys, unprompted, straight to the
     current .page-frame's contentWindow:
       { type: 'osirisVaultKeys', keys: [{ provider, key, email }] }
     — provider is a free-text display name (e.g. "Google Gemini", "GitHub
     Models"), not one of this file's provider ids — and expects an ack
     back so it can update its own status line:
       { type: 'osirisVaultKeysApplied', count }
     There is no "locked vs unlocked" signal available to the embedded page
     at all; the only observable event is "keys arrived" or "they didn't". */

  // Best-effort match from Portfolio's free-text provider name to this
  // file's provider id (e.g. "Google Gemini" -> "google", "GitHub Models"
  // -> "github"). Substring match after normalizing covers Portfolio's
  // VAULT_DEFAULT_PROVIDERS out of the box; anything the user typed into
  // Portfolio's "+ New provider" field that doesn't resemble one of our 9
  // ids is left unmatched rather than guessed.
  function matchProviderId(displayName) {
    var norm = String(displayName || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    if (!norm) return null;
    for (var i = 0; i < PROVIDERS.length; i++) {
      var id = PROVIDERS[i].id;
      if (norm.indexOf(id) !== -1) return id;
    }
    return null;
  }

  // cb(appliedKeysById, count) fires whenever Portfolio pushes keys. This
  // file automatically acks back to Portfolio (e.source) with the applied
  // count — callers don't need to manage that half of the handshake.
  function onVaultKeysReceived(cb) {
    global.addEventListener("message", function (e) {
      if (!e.data || e.data.type !== "osirisVaultKeys" || !Array.isArray(e.data.keys)) return;
      var applied = {};
      var count = 0;
      e.data.keys.forEach(function (k) {
        var id = matchProviderId(k && k.provider);
        if (id && k.key) {
          applied[id] = k.key;
          count++;
        }
      });
      _debugLog("RECV <- (vault)", "osirisVaultKeys", { rawCount: e.data.keys.length, matchedCount: count, matchedIds: Object.keys(applied) });
      cb(applied, count);
      if (e.source && e.source.postMessage) {
        _debugLog("SEND -> (vault)", "osirisVaultKeysApplied", { count: count });
        e.source.postMessage({ type: "osirisVaultKeysApplied", count: count }, "*");
      }
    });
  }

  /* ---------------- Manual API Keys Store ---------------- */
  // Ported from KI_WÖRTERBUCH_sample.html — the "code sample" referenced by
  // workplan §4.2 ("add all 9 API from code sample"). That file is the
  // source of truth for the real 9-provider fail-over system (models, key
  // links, key-format validation); this was previously a 2-provider stub.
  // See PROVIDER_FAILOVER_ORDER in the sample for the priority order used
  // by its background auto-switching — kept here as a comment for context,
  // not implemented in this file (no auto-switch caller exists yet).
  var PROVIDERS = [
    { id: "pollinations", label: "Pollinations AI" },
    { id: "cerebras", label: "Cerebras" },
    { id: "groq", label: "Groq" },
    { id: "google", label: "Google AI Studio" },
    { id: "nvidia", label: "NVIDIA NIM" },
    { id: "github", label: "GitHub Models" },
    { id: "cloudflare", label: "Cloudflare Workers AI" },
    { id: "openrouter", label: "OpenRouter" },
    { id: "huggingface", label: "Hugging Face" }
  ];

  var FREE_MODELS = {
    cerebras: [
      { id: "llama-3.3-70b", label: "Llama 3.3 70B (Cerebras, ultra-fast)" },
      { id: "llama3.1-8b", label: "Llama 3.1 8B (Cerebras)" }
    ],
    groq: [
      { id: "openai/gpt-oss-120b", label: "GPT-OSS 120B" },
      { id: "openai/gpt-oss-20b", label: "GPT-OSS 20B (fast)" },
      { id: "qwen/qwen3.6-27b", label: "Qwen 3.6 27B" }
    ],
    google: [
      { id: "gemini-flash-latest", label: "Gemini Flash (latest)" },
      { id: "gemini-3.5-flash", label: "Gemini 3.5 Flash" },
      { id: "gemini-3.1-flash-lite", label: "Gemini 3.1 Flash-Lite (cheap)" }
    ],
    nvidia: [
      { id: "deepseek-ai/deepseek-r1", label: "DeepSeek R1 (NIM)" },
      { id: "nvidia/nemotron-4-340b-instruct", label: "Nemotron 4 340B" },
      { id: "meta/llama3-70b-instruct", label: "Llama 3 70B (NIM)" }
    ],
    github: [
      { id: "gpt-4o-mini", label: "GPT-4o mini (GitHub Models)" },
      { id: "Meta-Llama-3.1-70B-Instruct", label: "Llama 3.1 70B (GitHub Models)" }
    ],
    cloudflare: [
      { id: "@cf/meta/llama-3.1-8b-instruct", label: "Llama 3.1 8B (Workers AI, 10k/day)" },
      { id: "@cf/mistral/mistral-7b-instruct-v0.1", label: "Mistral 7B (Workers AI)" }
    ],
    openrouter: [
      { id: "openai/gpt-oss-120b:free", label: "GPT-OSS 120B (:free)" },
      { id: "openai/gpt-oss-20b:free", label: "GPT-OSS 20B (:free, fast)" },
      { id: "meta-llama/llama-3.3-70b-instruct:free", label: "Llama 3.3 70B (:free)" }
    ],
    huggingface: [
      { id: "meta-llama/Llama-3.1-8B-Instruct", label: "Llama 3.1 8B (HF Router)" },
      { id: "mistralai/Mistral-7B-Instruct-v0.3", label: "Mistral 7B (HF Router)" }
    ],
    pollinations: [
      { id: "openai", label: "OpenAI (Pollinations)" },
      { id: "mistral", label: "Mistral (Pollinations)" },
      { id: "llama", label: "Llama (Pollinations)" }
    ]
  };

  var FREE_KEY_LINKS = {
    cerebras: "https://cloud.cerebras.ai/platform/api-keys",
    groq: "https://console.groq.com/keys",
    google: "https://aistudio.google.com/apikey",
    nvidia: "https://build.nvidia.com/explore/discover",
    github: "https://github.com/settings/tokens",
    cloudflare: "https://dash.cloudflare.com/profile/api-tokens",
    openrouter: "https://openrouter.ai/keys",
    huggingface: "https://huggingface.co/settings/tokens",
    pollinations: "https://enter.pollinations.ai"
  };

  // No provider is fully keyless — Pollinations now requires a key too
  // (see sample's comment on this). Kept as an array (not hardcoded true)
  // so a future keyless provider can be added without touching the
  // validateApiKey branch below.
  var KEYLESS_PROVIDERS = [];

  // Key-shape patterns, ported verbatim from the sample. These check
  // *shape* only, not whether the key actually works with the provider.
  var API_KEY_PATTERNS = {
    cerebras: { re: /^csk-[a-zA-Z0-9]{20,}$/, hint: 'starts with "csk-"' },
    openrouter: { re: /^sk-or-[a-zA-Z0-9-]{16,}$/, hint: 'starts with "sk-or-"' },
    groq: { re: /^gsk_[a-zA-Z0-9]{20,}$/, hint: 'starts with "gsk_"' },
    // Google accepts both the legacy "AIza..." (39 char) format and the
    // newer "AQ." key format — both are in circulation, see sample.
    google: { re: /^(AIza[a-zA-Z0-9_-]{35}|AQ\.[a-zA-Z0-9_.-]{20,})$/, hint: 'starts with "AIza" (39 chars) or "AQ." (new Google key format)' },
    nvidia: { re: /^nvapi-[a-zA-Z0-9_-]{20,}$/, hint: 'starts with "nvapi-"' },
    github: { re: /^(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{20,})$/, hint: 'starts with "ghp_" or "github_pat_"' },
    // Cloudflare needs both an Account ID and an API token, entered
    // together as "accountId:apiToken".
    cloudflare: { re: /^[a-f0-9]{32}:[a-zA-Z0-9_-]{20,}$/, hint: 'format "AccountID:APIToken" (Account ID = 32 hex chars)' },
    huggingface: { re: /^hf_[a-zA-Z0-9]{20,}$/, hint: 'starts with "hf_"' },
    // Pollinations issues pk_ (publishable) and sk_ (secret) keys; both
    // are accepted since this is a client-side app.
    pollinations: { re: /^(sk|pk)_[a-zA-Z0-9]{16,}$/, hint: 'starts with "sk_" or "pk_"' }
  };

  function validateApiKey(provider, rawKey) {
    var key = (rawKey || "").trim();
    var keyed = KEYLESS_PROVIDERS.indexOf(provider) === -1;
    if (!keyed) return { status: "empty", message: "" };
    if (!key) return { status: "warning", message: "A key is required for " + provider + "." };
    var pattern = API_KEY_PATTERNS[provider];
    if (pattern && !pattern.re.test(key)) {
      return { status: "invalid", message: "Invalid format: a " + provider + " key " + pattern.hint + "." };
    }
    if (/\s/.test(rawKey)) {
      return { status: "invalid", message: "The key contains whitespace — please check it." };
    }
    return { status: "valid", message: "Key format looks valid." };
  }

  // Promise wrapped for local storage fallback implementation
  function loadManualKeys() {
    return Promise.resolve(JSON.parse(global.localStorage.getItem("osiris_manual_keys") || "{}"));
  }

  function saveManualKeys(keys) {
    global.localStorage.setItem("osiris_manual_keys", JSON.stringify(keys));
  }

  function clearManualKeys() {
    global.localStorage.removeItem("osiris_manual_keys");
  }

  function loadManualModels() {
    return JSON.parse(global.localStorage.getItem("osiris_manual_models") || "{}");
  }

  function saveManualModels(models) {
    global.localStorage.setItem("osiris_manual_models", JSON.stringify(models));
  }

  /* ---------------- File handle store (§5 / §9.6) ----------------
     IndexedDB store for FileSystemFileHandle objects, keyed by book id.
     Handles are opaque objects that can't be JSON.stringify'd into
     localStorage (that's why the schema's book.fileHandle field is just
     a boolean flag, not the handle itself — the real handle lives here).
     Chromium only: callers must feature-detect `showOpenFilePicker`
     before offering this path and fall back to book.link otherwise. */
  var FH_DB_NAME = "osiris_file_handles_db";
  var FH_STORE = "handles";
  // Reboot-proof fallback store (§9.6b): raw File/Blob bytes, for when
  // there's no FileSystemFileHandle at all — unsupported browser, or a
  // shelf loaded inside the Hub's cross-origin iframe where
  // showOpenFilePicker() is blocked. sessionFiles (in-memory, per shelf)
  // covers the current tab only and is gone on reload; this store
  // persists the actual bytes in IndexedDB so "click to open" survives
  // a reload or full browser/computer restart. Same DB as the handle
  // store, bumped to v2 to add the second object store.
  var BLOB_STORE = "blobs";
  var _fhDbPromise = null;

  function _openHandleDb() {
    if (_fhDbPromise) return _fhDbPromise;
    _fhDbPromise = new Promise(function (resolve, reject) {
      if (!global.indexedDB) { reject(new Error("indexedDB unavailable")); return; }
      var req = global.indexedDB.open(FH_DB_NAME, 2);
      req.onupgradeneeded = function () {
        if (!req.result.objectStoreNames.contains(FH_STORE)) {
          req.result.createObjectStore(FH_STORE);
        }
        if (!req.result.objectStoreNames.contains(BLOB_STORE)) {
          req.result.createObjectStore(BLOB_STORE);
        }
      };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error); };
    });
    return _fhDbPromise;
  }

  // Persists the raw File/Blob itself (IndexedDB stores these natively,
  // no base64/serialization needed). Safe to call even if a real handle
  // was also saved elsewhere — callers only reach for this path when
  // pickFileHandle() wasn't available or was blocked, so it never
  // duplicates a handle-backed save.
  function saveFileBlob(bookId, blob) {
    return _openHandleDb().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(BLOB_STORE, "readwrite");
        tx.objectStore(BLOB_STORE).put(blob, bookId);
        tx.oncomplete = function () { resolve(true); };
        tx.onerror = function () { reject(tx.error); };
      });
    }).catch(function () { return false; });
  }

  function getFileBlob(bookId) {
    return _openHandleDb().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(BLOB_STORE, "readonly");
        var req = tx.objectStore(BLOB_STORE).get(bookId);
        req.onsuccess = function () { resolve(req.result || null); };
        req.onerror = function () { reject(req.error); };
      });
    }).catch(function () { return null; });
  }

  function deleteFileBlob(bookId) {
    return _openHandleDb().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(BLOB_STORE, "readwrite");
        tx.objectStore(BLOB_STORE).delete(bookId);
        tx.oncomplete = function () { resolve(true); };
        tx.onerror = function () { reject(tx.error); };
      });
    }).catch(function () { return false; });
  }

  // Convenience mirror of openFileHandle: resolves the stored blob
  // straight to an opened tab. Returns the same "opened" | "unavailable"
  // status string so callers can chain it as a fallback step after
  // openFileHandle without any extra branching.
  // Shared by openFileHandle/openFileBlob below and mirrored inline by
  // each shelf's session-cached-file fast path. "popup" reuses one named
  // window (one book at a time); anything else opens a fresh tab. Not
  // used for book.link opens (external, user-provided URLs) — those
  // always get a plain new tab regardless of mode, deliberately: reusing
  // a "reader" window for an arbitrary external site doesn't fit the same
  // mental model as reusing it for the person's own uploaded files.
  var READER_WINDOW_NAME = "osirisReader";
  function _openUrl(url, mode) {
    if (mode === "popup") {
      global.open(url, READER_WINDOW_NAME, "width=820,height=1040");
    } else {
      global.open(url, "_blank");
    }
  }

  function openFileBlob(bookId, mode) {
    return getFileBlob(bookId).then(function (blob) {
      if (!blob) return "unavailable";
      var url = URL.createObjectURL(blob);
      _openUrl(url, mode);
      setTimeout(function () { URL.revokeObjectURL(url); }, 60000);
      return "opened";
    });
  }

  // Feature detect only — does not touch the DB. Callers use this to
  // decide whether to show the "Choose File" primary path at all.
  function fileHandlesSupported() {
    return typeof global.showOpenFilePicker === "function";
  }

  function saveFileHandle(bookId, handle) {
    return _openHandleDb().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(FH_STORE, "readwrite");
        tx.objectStore(FH_STORE).put(handle, bookId);
        tx.oncomplete = function () { resolve(true); };
        tx.onerror = function () { reject(tx.error); };
      });
    }).catch(function () { return false; });
  }

  function getFileHandle(bookId) {
    return _openHandleDb().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(FH_STORE, "readonly");
        var req = tx.objectStore(FH_STORE).get(bookId);
        req.onsuccess = function () { resolve(req.result || null); };
        req.onerror = function () { reject(req.error); };
      });
    }).catch(function () { return null; });
  }

  function deleteFileHandle(bookId) {
    return _openHandleDb().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(FH_STORE, "readwrite");
        tx.objectStore(FH_STORE).delete(bookId);
        tx.oncomplete = function () { resolve(true); };
        tx.onerror = function () { reject(tx.error); };
      });
    }).catch(function () { return false; });
  }

  // Opens the file picker and returns the chosen handle (or null if the
  // user cancelled / the browser doesn't support the API). Does NOT
  // persist it — callers save it via saveFileHandle once they have a
  // book id to key it by (e.g. after the book record itself is created).
  function pickFileHandle(options) {
    if (!fileHandlesSupported()) return Promise.resolve(null);
    return global.showOpenFilePicker(options || {}).then(function (handles) {
      return handles && handles[0] ? handles[0] : null;
    }).catch(function (err) {
      if (err && err.name === "AbortError") return null; // user cancelled — not an error
      // Anything else (most commonly SecurityError: "Cross origin sub frames
      // aren't allowed to show a file picker", thrown when a shelf is loaded
      // inside the Hub's <iframe>) is a real failure, not a cancel. Rethrow
      // so callers can fall back to the plain <input type="file"> picker,
      // which isn't subject to this restriction, instead of silently doing
      // nothing.
      throw err;
    });
  }

  // Re-requests permission (required after reload — grants aren't
  // persisted across sessions unless the PWA "Persistent Permissions"
  // feature applies, see workplan §5 PWA note) and returns the live File,
  // or null if permission was denied / the handle no longer resolves
  // (e.g. the file was moved/deleted on disk).
  function resolveFileHandle(handle) {
    if (!handle || typeof handle.queryPermission !== "function") return Promise.resolve(null);
    return handle.queryPermission({ mode: "read" }).then(function (state) {
      if (state === "granted") return true;
      return handle.requestPermission({ mode: "read" }).then(function (s) { return s === "granted"; });
    }).then(function (granted) {
      if (!granted) return null;
      return handle.getFile();
    }).catch(function () {
      return null;
    });
  }

  // Convenience: resolve a handle straight to a File and open it in a
  // new tab via a throwaway object URL. Returns a status string so
  // callers can fall back to book.link on anything other than "opened".
  function openFileHandle(handle, mode) {
    return resolveFileHandle(handle).then(function (file) {
      if (!file) return "unavailable";
      var url = URL.createObjectURL(file);
      _openUrl(url, mode);
      setTimeout(function () { URL.revokeObjectURL(url); }, 60000);
      return "opened";
    });
  }

  /* ---------------- AI Classifier (§7 AI Sorting) ----------------
     Batch classification of books into {theme, cecr} using whatever
     provider(s) have a key present, in FREE_MODELS declaration order,
     with automatic failover to the next provider on any error.

     Uses a real text excerpt when the caller's entry has one (workplan
     §9's text extractor — shipped in all 4 shelves as of this pass,
     `book.excerpt`, capped ~700 chars, PDF/EPUB) and falls back to
     metadata-only (title/author/category/comment) otherwise, e.g. a
     link-only entry with no locally readable file. confidence is
     "excerpt" for the former, "estimated" for the latter, per entry —
     a single batch can be a mix of both. */

  var CHAT_ENDPOINTS = {
    cerebras: "https://api.cerebras.ai/v1/chat/completions",
    groq: "https://api.groq.com/openai/v1/chat/completions",
    nvidia: "https://integrate.api.nvidia.com/v1/chat/completions",
    github: "https://models.github.ai/inference/chat/completions",
    openrouter: "https://openrouter.ai/api/v1/chat/completions",
    huggingface: "https://router.huggingface.co/v1/chat/completions",
    pollinations: "https://text.pollinations.ai/openai"
  };

  // Providers tried in this order (fastest/most-reliable free tiers first);
  // google and cloudflare use different request shapes, handled separately
  // in callProvider below, but still take their turn in this order.
  var PROVIDER_FAILOVER_ORDER = [
    "cerebras", "groq", "google", "nvidia", "github",
    "cloudflare", "openrouter", "huggingface", "pollinations"
  ];

  function _extractJson(text) {
    var cleaned = String(text || "").replace(/```json/gi, "").replace(/```/g, "").trim();
    var start = cleaned.indexOf("[");
    var end = cleaned.lastIndexOf("]");
    if (start === -1 || end === -1 || end < start) throw new Error("no JSON array in response");
    return JSON.parse(cleaned.slice(start, end + 1));
  }

  function _callOpenAiCompatible(provider, key, model, systemPrompt, userPrompt) {
    return fetch(CHAT_ENDPOINTS[provider], {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + key },
      body: JSON.stringify({
        model: model,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt }
        ],
        temperature: 0.2
      })
    }).then(function (res) {
      if (!res.ok) throw new Error(provider + " HTTP " + res.status);
      return res.json();
    }).then(function (data) {
      var text = data && data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
      if (!text) throw new Error(provider + " returned an empty response");
      return text;
    });
  }

  function _callGoogle(key, model, systemPrompt, userPrompt) {
    var url = "https://generativelanguage.googleapis.com/v1beta/models/" + model + ":generateContent?key=" + encodeURIComponent(key);
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: systemPrompt + "\n\n" + userPrompt }] }] })
    }).then(function (res) {
      if (!res.ok) throw new Error("google HTTP " + res.status);
      return res.json();
    }).then(function (data) {
      var c = data && data.candidates && data.candidates[0];
      var text = c && c.content && c.content.parts && c.content.parts[0] && c.content.parts[0].text;
      if (!text) throw new Error("google returned an empty response");
      return text;
    });
  }

  // Cloudflare's key is stored as "accountId:apiToken" (see API_KEY_PATTERNS).
  function _callCloudflare(key, model, systemPrompt, userPrompt) {
    var parts = String(key || "").split(":");
    var accountId = parts[0], token = parts[1];
    var url = "https://api.cloudflare.com/client/v4/accounts/" + accountId + "/ai/run/" + model;
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
      body: JSON.stringify({ messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userPrompt }] })
    }).then(function (res) {
      if (!res.ok) throw new Error("cloudflare HTTP " + res.status);
      return res.json();
    }).then(function (data) {
      var text = data && data.result && data.result.response;
      if (!text) throw new Error("cloudflare returned an empty response");
      return text;
    });
  }

  function _callProvider(provider, key, model, systemPrompt, userPrompt) {
    if (provider === "google") return _callGoogle(key, model, systemPrompt, userPrompt);
    if (provider === "cloudflare") return _callCloudflare(key, model, systemPrompt, userPrompt);
    return _callOpenAiCompatible(provider, key, model, systemPrompt, userPrompt);
  }

  var CLASSIFY_SYSTEM_PROMPT =
    "You are a librarian tagging books for a personal library app. Given a JSON array of " +
    "books, reply with ONLY a JSON array of the same length, in the same order, of objects: " +
    "{\"theme\": string, \"cecr\": one of \"A1\",\"A2\",\"B1\",\"B2\",\"C1\",\"C2\", or null if " +
    "not applicable (e.g. non-fiction reference, or the language level can't reasonably be " +
    "guessed)}. theme is a short 1-3 word genre/subject label. Some entries include an " +
    "`excerpt` field with real text pulled from the book itself — when present, weight it " +
    "over title/author/category/comment, since it's a far more reliable signal for both genre " +
    "and reading-level than metadata alone; when absent, judge from title/author/category/" +
    "comment as before. No prose, no markdown fences, just the JSON array.";

  // entries: [{title, author, category, comment, excerpt?}]. Entries with a
  // non-empty `excerpt` (workplan §9's text extractor — see the classifier
  // comment above) get confidence:"excerpt"; entries without one (e.g.
  // link-only, or extraction failed/unsupported format) fall back to
  // metadata-only and confidence:"estimated" — mirrored per-entry in a
  // single mixed batch. Tries each provider that has a key present, in
  // PROVIDER_FAILOVER_ORDER, first model listed for that provider in
  // FREE_MODELS; moves to the next provider on any failure (bad key, rate
  // limit, malformed response). Rejects only if every provider with a key
  // fails.
  function aiClassifyBatch(entries) {
    return loadManualKeys().then(function (keys) {
      keys = keys || {};
      var candidates = PROVIDER_FAILOVER_ORDER.filter(function (p) { return !!keys[p]; });
      if (!candidates.length) return Promise.reject(new Error("no API key available"));

      var hasExcerpt = entries.map(function (e) { return !!(e.excerpt && String(e.excerpt).trim()); });

      var userPrompt = JSON.stringify(entries.map(function (e, i) {
        var payload = { title: e.title || "", author: e.author || "", category: e.category || "", comment: e.comment || "" };
        if (hasExcerpt[i]) payload.excerpt = String(e.excerpt).trim();
        return payload;
      }));

      function tryNext(i) {
        if (i >= candidates.length) return Promise.reject(new Error("all providers failed"));
        var provider = candidates[i];
        var models = FREE_MODELS[provider];
        var model = models && models[0] && models[0].id;
        if (!model) return tryNext(i + 1);
        return _callProvider(provider, keys[provider], model, CLASSIFY_SYSTEM_PROMPT, userPrompt)
          .then(function (text) {
            var parsed = _extractJson(text);
            if (!Array.isArray(parsed) || parsed.length !== entries.length) {
              throw new Error(provider + " returned a malformed/mismatched array");
            }
            return parsed.map(function (tag, i) {
              return {
                theme: (tag && tag.theme) || null,
                cecr: (tag && tag.cecr) || null,
                confidence: hasExcerpt[i] ? "excerpt" : "estimated",
                provider: provider,
                taggedAt: Date.now()
              };
            });
          })
          .catch(function () { return tryNext(i + 1); });
      }
      return tryNext(0);
    });
  }

  /* ---------------- Core Utilities ---------------- */
  function escapeHtml(str) {
    if (!str) return "";
    return String(str).replace(/[&<>"'`=\/]/g, function (s) {
      return {
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "/": "&#x2F;", "`": "&#x60;", "=": "&#x3D;"
      }[s];
    });
  }

  // UI-facing sort keys (as used by the Hub's sort row) mapped to the
  // actual §2 schema field they correspond to. Bug found in this pass:
  // the Hub calls sortBooks(library, 'name'|'date'|'opens'|'theme'|'cecr', dir)
  // directly, but the schema doesn't have top-level name/date/opens/theme/cecr
  // fields — it has title/addedAt/openCount/fileMeta.size/aiTags.theme/aiTags.cecr.
  // a[key] was silently undefined for every book on 5 of 7 sort options
  // (only 'category' ever matched a real field), so those buttons reordered
  // nothing. Fixed by mapping UI keys to real (possibly dotted) field paths
  // and resolving dotted paths via getField() below.
  var SORT_KEY_PATHS = {
    name: "title",
    date: "addedAt",
    size: "fileMeta.size",
    opens: "openCount",
    category: "category",
    theme: "aiTags.theme",
    cecr: "aiTags.cecr"
  };

  function getField(obj, path) {
    var parts = path.split(".");
    var val = obj;
    for (var i = 0; i < parts.length; i++) {
      if (val === null || val === undefined) return undefined;
      val = val[parts[i]];
    }
    return val;
  }

  function sortBooks(books, key, dir) {
    if (!books || !Array.isArray(books)) return [];
    var path = SORT_KEY_PATHS[key] || key; // fall back to key itself if an unmapped/flat key is passed
    var sorted = books.slice().sort(function(a, b) {
       var valA = getField(a, path);
       var valB = getField(b, path);
       var aMissing = valA === undefined || valA === null || valA === "";
       var bMissing = valB === undefined || valB === null || valB === "";
       if (aMissing && bMissing) return 0;
       if (aMissing) return 1;  // missing values sort last regardless of asc/desc
       if (bMissing) return -1;
       if (typeof valA === "string" && typeof valB === "string") {
         return valA.localeCompare(valB);
       }
       if (valA < valB) return -1;
       if (valA > valB) return 1;
       return 0;
    });
    if (dir === 'desc') sorted.reverse();
    return sorted.map(function(b) { return b.id; });
  }

  global.OsirisCore = {
    LIB_KEY: LIB_KEY,
    makeBookId: makeBookId,
    loadLibrary: loadLibrary,
    saveLibrary: saveLibrary,
    MSG: MSG,
    send: send,
    listen: listen,
    onVaultKeysReceived: onVaultKeysReceived,
    matchProviderId: matchProviderId,
    PROVIDERS: PROVIDERS,
    FREE_MODELS: FREE_MODELS,
    FREE_KEY_LINKS: FREE_KEY_LINKS,
    KEYLESS_PROVIDERS: KEYLESS_PROVIDERS,
    API_KEY_PATTERNS: API_KEY_PATTERNS,
    validateApiKey: validateApiKey,
    loadManualKeys: loadManualKeys,
    saveManualKeys: saveManualKeys,
    clearManualKeys: clearManualKeys,
    loadManualModels: loadManualModels,
    saveManualModels: saveManualModels,
    escapeHtml: escapeHtml,
    sortBooks: sortBooks,
    fileHandlesSupported: fileHandlesSupported,
    pickFileHandle: pickFileHandle,
    saveFileHandle: saveFileHandle,
    getFileHandle: getFileHandle,
    deleteFileHandle: deleteFileHandle,
    resolveFileHandle: resolveFileHandle,
    openFileHandle: openFileHandle,
    saveFileBlob: saveFileBlob,
    getFileBlob: getFileBlob,
    deleteFileBlob: deleteFileBlob,
    openFileBlob: openFileBlob,
    aiClassifyBatch: aiClassifyBatch
  };
})(typeof window !== "undefined" ? window : this);
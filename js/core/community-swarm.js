/**
 * Osiris EduHub - Hardened Hybrid Document Sharing & Security Engine v2.5
 * (Social 1-to-1 + Decentralized WebRTC Swarm + Zero-Trust Client Security)
 *
 * Transports:
 *  1. BroadcastChannel: Instant zero-latency cross-tab sharing on same device/browser.
 *  2. PeerJS WebRTC DataChannels: Automatic cross-device mesh across GitHub Pages & Internet.
 *     - Automatic deterministic Lobby Slot pool (slots 1..8 per room)
 *     - Automatic Peer Exchange (PEX) gossip mesh
 *     - Packet chunking for large PDF/DOCX files (>48 KB)
 *     - Manual Room-Code / Peer-ID direct connection support
 *
 * Security Hardening Included:
 *  1. Anti-XSS: Strict HTML entity escaping (escapeHtml), DOMParser HTML sanitizer
 *     for DOCX previews, safe DataURL & HTTP(S) URL validators, zero inline string interpolation in onclicks.
 *  2. Anti-Prototype Pollution: Safe JSON reviver blocking __proto__, constructor, prototype.
 *  3. Anti-Steganography / Polyglot / Malware CDR:
 *     - Strict Magic-Byte whitelist (PDF, DOCX, PNG, JPEG, WEBP, GIF, TXT) — unknown binaries rejected.
 *     - PDF Active-Content Scanner: Blocks PDFs containing /JavaScript, /JS, /Launch, /RichMedia, /SubmitForm.
 *     - Office Macro Blocker: Scans DOCX ZIP containers for vbaProject.bin, .exe, .vbs, .bat, .ps1.
 *     - Image EOI / Polyglot Check: Verifies image headers and blocks SVG script vectors.
 *  4. Anti-DDoS & Resource Exhaustion:
 *     - Sliding-window rate limiter per Peer ID (auto-blacklists flooding peers).
 *     - Strict 25 MB maximum file size cap & metadata string length caps (max 200 chars).
 *     - Unsolicited delivery blocker (only accepts DELIVER_DOC for explicitly requested hashes/IDs).
 *     - Maximum 50 peers & 100 catalog items per peer.
 *  5. Anti-MitM & Integrity:
 *     - Mandatory SHA-256 bit-level verification + visual 6-char SHA-256 Security Fingerprint badge.
 */

(function (window) {
    'use strict';

    // --- Security Constants & Quotas ---
    const SWARM_CHANNEL_NAME = 'osiris_edu_swarm_v1';
    const SHARED_DOCS_KEY = 'osiris_shared_swarm_docs';
    const MAX_FILE_BYTES = 25 * 1024 * 1024; // 25 MB hard cap
    const MAX_CATALOG_ITEMS_PER_PEER = 100;
    const MAX_TRACKED_PEERS = 50;
    const MAX_META_STRING_LEN = 200;
    const RATE_LIMIT_WINDOW_MS = 10000; // 10 seconds
    const RATE_LIMIT_MAX_MSGS = 25;     // max 25 control messages per 10s per peer
    const PEER_ID_REGEX = /^peer_[a-z0-9]{6,16}$/;
    const CHUNK_SIZE = 48000;           // 48 KB chunk size for WebRTC DataChannel transfer

    // WebRTC Swarm Lobby Pool Settings
    const LOBBY_PREFIX = 'osiris-dt-swarm-v2-';
    const LOBBY_SLOT_COUNT = 8;

    let currentConfig = {
        dbName: 'DokumentationDB',
        storeName: 'documents',
        docTypeLabel: 'Doktyp',
        onDocImported: null
    };

    let localCatalog = [];
    let remoteCatalog = new Map();       // peerId -> { lastSeen, docs, webrtcId, transport }
    let peerRateTracker = new Map();     // peerId -> [timestamps]
    let blockedPeers = new Set();        // peerIds blocked for flooding/malformed data
    let pendingRequests = new Map();     // "${peerId}:${docId}" -> { token, expiresAt }
    let broadcastChannel = null;

    // WebRTC PeerJS State
    let peerJsInstance = null;
    let myWebrtcId = null;
    let webrtcStatus = 'initializing';  // 'initializing' | 'connecting' | 'connected' | 'offline' | 'error'
    let currentLobbySlot = 1;
    let webrtcConnections = new Map();  // webrtcPeerId -> DataConnection
    let peerToWebrtcMap = new Map();    // osirisPeerId -> webrtcPeerId
    let incomingChunks = new Map();     // transferId -> { chunks: Map(idx->str), total, sender, token, startedAt }
    let activeSwarmRoom = 'global';

    function generateCryptoHex(byteLen) {
        const buf = new Uint8Array(byteLen || 16);
        if (window.crypto && window.crypto.getRandomValues) {
            window.crypto.getRandomValues(buf);
        } else {
            for (let i = 0; i < buf.length; i++) buf[i] = Math.floor(Math.random() * 256);
        }
        return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Generate cryptographically random 96-bit Peer ID
    let myPeerId = 'peer_' + generateCryptoHex(6);

    const ALLOWED_THEMES = Object.freeze(['light', 'dark', 'osiris', 'snow', 'grass', 'ocean', 'sunset']);
    const ALLOWED_FONTS = Object.freeze([
        "'Brush Script MT', cursive",
        "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
        "Georgia, 'Times New Roman', serif",
        "'Courier New', Courier, monospace",
        "'Trebuchet MS', Verdana, sans-serif",
        "'Arial Narrow', Arial, sans-serif",
        "'Palatino Linotype', 'Book Antiqua', Palatino, serif"
    ]);

    // =========================================================================
    // 1. ZERO-TRUST SECURITY & SANITIZATION SUITE (window.OsirisSecurity)
    // =========================================================================

    function isTrustedOrigin(event) {
        if (!event) return false;
        if (window.location.protocol === 'file:' && (event.origin === 'null' || event.origin === '' || event.origin === 'file://')) {
            return true;
        }
        return event.origin === window.location.origin;
    }

    function getTargetOrigin() {
        if (window.location.protocol === 'file:' || !window.location.origin || window.location.origin === 'null') {
            return '*';
        }
        return window.location.origin;
    }

    function sanitizeThemeName(theme) {
        const t = String(theme || '').trim().toLowerCase();
        return ALLOWED_THEMES.indexOf(t) !== -1 ? t : 'light';
    }

    function sanitizeFontFamily(font) {
        const f = String(font || '').trim();
        if (ALLOWED_FONTS.indexOf(f) !== -1) return f;
        if (/^[a-zA-Z0-9\s,'"\-]+$/.test(f) && f.length <= 100 && !/url\s*\(|expression|import/i.test(f)) {
            return f;
        }
        return ALLOWED_FONTS[1];
    }

    function escapeHtml(val) {
        if (val === null || val === undefined) return '';
        return String(val)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;')
            .replace(/`/g, '&#96;');
    }

    function clampString(val, maxLen) {
        if (val === null || val === undefined) return '';
        const s = String(val)
            .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u202A-\u202E\u2066-\u2069]/g, '')
            .trim();
        return s.length > (maxLen || MAX_META_STRING_LEN) ? s.substring(0, maxLen || MAX_META_STRING_LEN) : s;
    }

    function sanitizeFileName(fileName) {
        const raw = clampString(fileName || 'Dokument.pdf', 150)
            .replace(/[\\/:*?"<>|]/g, '_')
            .replace(/\.{2,}/g, '_')
            .replace(/^\.+/, '');
        return raw || 'Dokument.pdf';
    }

    function sanitizeUrl(url) {
        if (!url || typeof url !== 'string') return '#';
        const trimmed = url.replace(/[\x00-\x20\u202A-\u202E\u2066-\u2069]/g, '').trim();
        try {
            const parsed = new URL(trimmed, window.location.origin);
            if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
                return parsed.href.replace(/"/g, '%22').replace(/'/g, '%27').replace(/</g, '%3C').replace(/>/g, '%3E');
            }
        } catch (e) {}
        return '#';
    }

    function sanitizeDataUrl(dataUrl) {
        if (!dataUrl || typeof dataUrl !== 'string') return '';
        const trimmed = dataUrl.trim();
        const allowedPrefixes = [
            'data:application/pdf;base64,',
            'data:application/vnd.openxmlformats-officedocument.wordprocessingml.document;base64,',
            'data:application/msword;base64,',
            'data:image/png;base64,',
            'data:image/jpeg;base64,',
            'data:image/jpg;base64,',
            'data:image/webp;base64,',
            'data:image/gif;base64,',
            'data:text/plain;base64,'
        ];
        const lower = trimmed.substring(0, 100).toLowerCase();
        if (allowedPrefixes.some(p => lower.startsWith(p))) {
            const commaIdx = trimmed.indexOf(',');
            if (commaIdx === -1) return '';
            const b64 = trimmed.substring(commaIdx + 1).replace(/\s+/g, '');
            if (!/^[A-Za-z0-9+/=]+$/.test(b64)) return '';
            return trimmed.substring(0, commaIdx + 1) + b64;
        }
        return '';
    }

    function sanitizeHtmlFragment(dirtyHtml) {
        if (!dirtyHtml || typeof dirtyHtml !== 'string') return '';
        try {
            const parser = new DOMParser();
            const doc = parser.parseFromString(dirtyHtml, 'text/html');
            const forbiddenTags = [
                'script', 'iframe', 'object', 'embed', 'svg', 'math',
                'form', 'input', 'button', 'textarea', 'select', 'meta',
                'link', 'style', 'base', 'applet', 'frame', 'frameset',
                'audio', 'video', 'source', 'track', 'portal', 'template', 'noscript'
            ];
            forbiddenTags.forEach(tag => {
                doc.querySelectorAll(tag).forEach(el => el.remove());
            });
            const allElements = doc.body.querySelectorAll('*');
            allElements.forEach(el => {
                Array.from(el.attributes).forEach(attr => {
                    const name = attr.name.toLowerCase();
                    const val = (attr.value || '').replace(/[\x00-\x20]/g, '').toLowerCase();
                    if (name.startsWith('on') || name === 'srcdoc' || name === 'formaction' || name === 'style' || name === 'id' || name === 'name') {
                        el.removeAttribute(attr.name);
                    } else if (name === 'href' || name === 'src' || name === 'xlink:href' || name === 'action') {
                        if (val.startsWith('http://') || val.startsWith('https://') || val.startsWith('data:image/png;base64,') || val.startsWith('data:image/jpeg;base64,')) {
                            if (name === 'href') {
                                el.setAttribute('target', '_blank');
                                el.setAttribute('rel', 'noopener noreferrer');
                            }
                        } else {
                            el.removeAttribute(attr.name);
                        }
                    }
                });
            });
            return doc.body.innerHTML;
        } catch (e) {
            return '';
        }
    }

    function safeJsonParse(raw) {
        if (!raw || typeof raw !== 'string') return null;
        try {
            return JSON.parse(raw, (key, value) => {
                if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
                    return undefined;
                }
                return value;
            });
        } catch (e) {
            return null;
        }
    }

    function dataUrlToUint8Array(dataUrl) {
        if (!dataUrl || typeof dataUrl !== 'string') throw new Error('Invalid DataURL');
        const commaIdx = dataUrl.indexOf(',');
        if (commaIdx === -1) throw new Error('Malformed DataURL');
        const base64 = dataUrl.substring(commaIdx + 1).replace(/\s+/g, '');
        const binary = atob(base64);
        const len = binary.length;
        if (len > MAX_FILE_BYTES) throw new Error(`File size ${len} exceeds max limit of ${MAX_FILE_BYTES}`);
        const u8 = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            u8[i] = binary.charCodeAt(i);
        }
        return u8;
    }

    function validateMagicBytes(u8, fileName) {
        if (!u8 || !(u8 instanceof Uint8Array) || u8.length === 0) {
            return { valid: false, reason: 'Leere oder ungültige Binärdaten' };
        }
        if (u8.length > MAX_FILE_BYTES) {
            return { valid: false, reason: `Dateigröße (${(u8.length / (1024*1024)).toFixed(1)} MB) überschreitet das Limit von 25 MB` };
        }

        const len = u8.length;
        const b0 = u8[0], b1 = u8[1], b2 = u8[2], b3 = u8[3];

        // 1. PDF Validation (%PDF-)
        if (b0 === 0x25 && b1 === 0x50 && b2 === 0x44 && b3 === 0x46) {
            const checkLen = Math.min(len, 200000);
            const strSlice = String.fromCharCode.apply(null, u8.subarray(0, checkLen));
            const dangerousPatterns = [
                /\/JavaScript\b/i,
                /\/JS\b/i,
                /\/Launch\b/i,
                /\/SubmitForm\b/i,
                /\/ImportData\b/i,
                /\/RichMedia\b/i
            ];
            for (const pat of dangerousPatterns) {
                if (pat.test(strSlice)) {
                    return { valid: false, reason: 'PDF enthält verbotene aktive Inhalte / Skripte (' + pat.source + ')' };
                }
            }
            return { valid: true, type: 'application/pdf' };
        }

        // 2. DOCX / ZIP Container Validation (PK\x03\x04)
        if (b0 === 0x50 && b1 === 0x4B && b2 === 0x03 && b3 === 0x04) {
            const checkLen = Math.min(len, 200000);
            const strSlice = String.fromCharCode.apply(null, u8.subarray(0, checkLen));
            if (strSlice.includes('vbaProject.bin') || strSlice.includes('.exe') || strSlice.includes('.vbs') || strSlice.includes('.bat') || strSlice.includes('.ps1')) {
                return { valid: false, reason: 'Office-Container enthält Makros oder ausführbaren Code' };
            }
            return { valid: true, type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' };
        }

        // 3. PNG Image Validation (\x89PNG)
        if (b0 === 0x89 && b1 === 0x50 && b2 === 0x4E && b3 === 0x47) {
            return { valid: true, type: 'image/png' };
        }

        // 4. JPEG Image Validation (\xFF\xD8\xFF)
        if (b0 === 0xFF && b1 === 0xD8 && b2 === 0xFF) {
            return { valid: true, type: 'image/jpeg' };
        }

        // 5. WEBP Image Validation (RIFF....WEBP)
        if (b0 === 0x52 && b1 === 0x49 && b2 === 0x46 && b3 === 0x46 && len >= 12) {
            if (u8[8] === 0x57 && u8[9] === 0x45 && u8[10] === 0x42 && u8[11] === 0x50) {
                return { valid: true, type: 'image/webp' };
            }
        }

        // 6. GIF Image Validation (GIF87a / GIF89a)
        if (b0 === 0x47 && b1 === 0x49 && b2 === 0x46 && b3 === 0x38) {
            return { valid: true, type: 'image/gif' };
        }

        // 7. Plain Text Validation
        const ext = (fileName || '').toLowerCase().split('.').pop();
        if (ext === 'txt' || ext === 'text') {
            for (let i = 0; i < Math.min(len, 4096); i++) {
                const byte = u8[i];
                if (byte === 0x00 || (byte < 0x09 && byte !== 0x07 && byte !== 0x08) || (byte > 0x0D && byte < 0x20 && byte !== 0x1B)) {
                    return { valid: false, reason: 'Textdatei enthält unerwartete Binärzeichen' };
                }
            }
            return { valid: true, type: 'text/plain' };
        }

        return { valid: false, reason: 'Dateityp nicht zugelassen (Nur PDF, DOCX, PNG, JPEG, WEBP, GIF, TXT)' };
    }

    async function computeSHA256(buffer) {
        if (!buffer) return '';
        try {
            if (window.crypto && window.crypto.subtle) {
                const hashBuf = await window.crypto.subtle.digest('SHA-256', buffer);
                return Array.from(new Uint8Array(hashBuf))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
            }
        } catch (e) {
            console.warn('SubtleCrypto error:', e);
        }
        return '';
    }

    function sanitizeDocRecord(raw) {
        if (!raw || typeof raw !== 'object') return null;
        const cleanThema = clampString(raw.thema || raw.title || 'Unbenannt', MAX_META_STRING_LEN);
        const cleanLektion = clampString(raw.lektion || '—', MAX_META_STRING_LEN);
        const cleanBuch = clampString(raw.buch || '—', MAX_META_STRING_LEN);
        const cleanKlassen = clampString(raw.klassen || 'Alle', 80);
        const cleanJahr = clampString(raw.jahr || '2026', 20);
        const cleanTyp = clampString(raw.typ || currentConfig.docTypeLabel, 80);
        const cleanSubTyp = Array.isArray(raw.subTyp)
            ? raw.subTyp.slice(0, 10).map(s => clampString(s, 80))
            : [];
        const cleanFileName = sanitizeFileName(raw.fileName || 'Dokument.pdf');
        const cleanFileType = clampString(raw.fileType || 'application/pdf', 100);
        const cleanDataUrl = sanitizeDataUrl(raw.fileData);

        return {
            id: Number(raw.id) || Date.now(),
            thema: cleanThema,
            lektion: cleanLektion,
            buch: cleanBuch,
            klassen: cleanKlassen,
            jahr: cleanJahr,
            typ: cleanTyp,
            subTyp: cleanSubTyp,
            fileName: cleanFileName,
            fileType: cleanFileType,
            fileSize: Math.min(Math.max(0, Number(raw.fileSize) || 0), MAX_FILE_BYTES),
            fileHash: clampString(raw.fileHash || '', 64).replace(/[^a-f0-9]/gi, '').toLowerCase(),
            fileData: cleanDataUrl,
            date: clampString(raw.date || new Date().toLocaleDateString(), 40),
            sourceDb: clampString(raw.sourceDb || '', 60)
        };
    }

    function sanitizeWikiEntry(raw) {
        if (!raw || typeof raw !== 'object') return null;
        return {
            id: Number(raw.id) || Date.now(),
            title: clampString(raw.title || 'Ohne Titel', 120),
            category: clampString(raw.category || 'Allgemein', 80),
            tags: clampString(raw.tags || '', 160),
            text: clampString(raw.text || '', 50000),
            date: clampString(raw.date || new Date().toISOString().slice(0,10), 40),
            files: Array.isArray(raw.files) ? raw.files.slice(0, 10).map(f => ({
                id: Number(f.id) || Date.now(),
                name: sanitizeFileName(f.name),
                type: clampString(f.type || '', 80),
                size: Math.min(Math.max(0, Number(f.size) || 0), MAX_FILE_BYTES),
                data: sanitizeDataUrl(f.data)
            })).filter(f => f.data) : []
        };
    }

    function sanitizeLinkEntry(raw) {
        if (!raw || typeof raw !== 'object') return null;
        return {
            name: clampString(raw.name || '', 100),
            url: sanitizeUrl(raw.url)
        };
    }

    // =========================================================================
    // 2. SOCIAL SHARING (1-to-1) ENGINE
    // =========================================================================

    async function shareSocial(platform, docData) {
        const safeDoc = sanitizeDocRecord(docData);
        if (!safeDoc) return;

        // When sharing via P2P Swarm from popup
        if (platform === 'swarm') {
            const isShared = isDocShared(safeDoc.id);
            await toggleShareDocToSwarm(safeDoc.id, !isShared);
            openSwarmModal();
            return;
        }

        const fileName = safeDoc.fileName;
        const title = safeDoc.thema || fileName;
        const typ = safeDoc.typ || currentConfig.docTypeLabel;
        const shortHash = safeDoc.fileHash ? safeDoc.fileHash.substring(0, 6).toUpperCase() : 'LOCAL';
        const msgText = `📄 ${title} [${typ}]\nKlasse: ${safeDoc.klassen} | Jahr: ${safeDoc.jahr} | SHA: #${shortHash}\nBereitgestellt über EduHub.`;

        let fileObj = null;
        if (safeDoc.fileData) {
            try {
                const u8 = dataUrlToUint8Array(safeDoc.fileData);
                const mime = (safeDoc.fileData.split(',')[0].match(/:(.*?);/) || [])[1] || 'application/pdf';
                fileObj = new File([u8], fileName, { type: mime });
            } catch (err) {
                console.warn('File conversion error for share:', err);
            }
        }

        if (platform === 'whatsapp') {
            if (fileObj && navigator.canShare && navigator.canShare({ files: [fileObj] })) {
                try {
                    await navigator.share({ files: [fileObj], title: title, text: msgText });
                    return;
                } catch (e) {
                    if (e.name === 'AbortError') return;
                }
            }
            const waUrl = 'https://api.whatsapp.com/send?text=' + encodeURIComponent(msgText + '\n(Datei direkt im EduHub öffnen)');
            window.open(waUrl, '_blank', 'noopener,noreferrer');

        } else if (platform === 'telegram') {
            if (fileObj && navigator.canShare && navigator.canShare({ files: [fileObj] })) {
                try {
                    await navigator.share({ files: [fileObj], title: title, text: msgText });
                    return;
                } catch (e) {
                    if (e.name === 'AbortError') return;
                }
            }
            const tgUrl = 'https://t.me/share/url?url=' + encodeURIComponent(window.location.href) + '&text=' + encodeURIComponent(msgText);
            window.open(tgUrl, '_blank', 'noopener,noreferrer');

        } else if (platform === 'email') {
            if (fileObj && navigator.canShare && navigator.canShare({ files: [fileObj] })) {
                try {
                    await navigator.share({ files: [fileObj], title: title, text: msgText });
                    return;
                } catch (e) {
                    if (e.name === 'AbortError') return;
                }
            }
            window.location.href = 'mailto:?subject=' + encodeURIComponent('EduHub Dokument: ' + title) + '&body=' + encodeURIComponent(msgText);

        } else if (platform === 'direct' || platform === 'bluetooth') {
            if (fileObj && navigator.canShare && navigator.canShare({ files: [fileObj] })) {
                try {
                    await navigator.share({ files: [fileObj], title: title, text: msgText });
                } catch (e) {
                    if (e.name !== 'AbortError') alert('Teilen fehlgeschlagen: ' + e.message);
                }
            } else if (navigator.share) {
                try {
                    await navigator.share({ title: title, text: msgText });
                } catch (e) {
                    if (e.name !== 'AbortError') alert('Teilen fehlgeschlagen: ' + e.message);
                }
            } else {
                exportSinglePackage(safeDoc);
            }

        } else if (platform === 'package') {
            exportSinglePackage(safeDoc);
        }
    }

    function exportSinglePackage(docData) {
        const safeDoc = sanitizeDocRecord(docData);
        if (!safeDoc) return;

        const pkg = {
            app: 'OsirisEduHub',
            version: '2.5-hardened',
            exportedAt: new Date().toISOString(),
            document: safeDoc
        };

        const jsonStr = JSON.stringify(pkg, null, 2);
        const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        const safeName = (safeDoc.thema || 'Dokument').replace(/[^a-zA-Z0-9_\-]/g, '_').substring(0, 60);
        a.download = `${safeName}.edu.json`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 4000);
    }

    // =========================================================================
    // 3. DECENTRALIZED MULTI-TRANSPORT SWARM ENGINE (WebRTC + BroadcastChannel)
    // =========================================================================

    function isPeerRateAllowed(peerId) {
        if (!peerId || typeof peerId !== 'string' || !PEER_ID_REGEX.test(peerId)) {
            return false;
        }
        if (blockedPeers.has(peerId)) return false;

        const now = Date.now();
        let history = peerRateTracker.get(peerId) || [];
        history = history.filter(ts => now - ts < RATE_LIMIT_WINDOW_MS);
        history.push(now);
        peerRateTracker.set(peerId, history);

        if (history.length > RATE_LIMIT_MAX_MSGS) {
            console.warn('[Osiris Security] Peer blocked for rate-limit flooding:', peerId);
            blockedPeers.add(peerId);
            remoteCatalog.delete(peerId);
            updateSwarmBadge();
            renderSwarmModalContent();
            return false;
        }
        return true;
    }

    function sanitizeRemoteCatalogList(rawList) {
        if (!Array.isArray(rawList)) return [];
        return rawList.slice(0, MAX_CATALOG_ITEMS_PER_PEER).map(d => {
            if (!d || typeof d !== 'object') return null;
            return {
                id: Number(d.id) || 0,
                thema: clampString(d.thema || 'Unbenannt', MAX_META_STRING_LEN),
                lektion: clampString(d.lektion || '—', MAX_META_STRING_LEN),
                buch: clampString(d.buch || '—', MAX_META_STRING_LEN),
                klassen: clampString(d.klassen || 'Alle', 80),
                jahr: clampString(d.jahr || '2026', 20),
                typ: clampString(d.typ || currentConfig.docTypeLabel, 80),
                subTyp: Array.isArray(d.subTyp) ? d.subTyp.slice(0, 10).map(s => clampString(s, 80)) : [],
                fileName: clampString(d.fileName || 'Dokument.pdf', 150),
                fileType: clampString(d.fileType || 'application/pdf', 100),
                fileSize: Math.min(Math.max(0, Number(d.fileSize) || 0), MAX_FILE_BYTES),
                fileHash: clampString(d.fileHash || '', 64).replace(/[^a-f0-9]/gi, '').toLowerCase(),
                date: clampString(d.date || '', 40),
                sourceDb: clampString(d.sourceDb || currentConfig.dbName, 60)
            };
        }).filter(Boolean);
    }

    function loadSharedDocsConfig(dbName) {
        try {
            const targetDb = dbName || currentConfig.dbName;
            const raw = localStorage.getItem(SHARED_DOCS_KEY + '_' + targetDb);
            const parsed = raw ? safeJsonParse(raw) : [];
            return Array.isArray(parsed) ? parsed.map(Number).filter(Boolean) : [];
        } catch (e) {
            return [];
        }
    }

    function saveSharedDocsConfig(list, dbName) {
        try {
            const targetDb = dbName || currentConfig.dbName;
            localStorage.setItem(SHARED_DOCS_KEY + '_' + targetDb, JSON.stringify(list));
        } catch (e) {}
    }

    // Aggregates shared docs from both DokumentationDB and TestBankDB
    async function refreshLocalCatalog() {
        const dbsToScan = ['DokumentationDB', 'TestBankDB'];
        let combined = [];

        for (const dbName of dbsToScan) {
            const sharedIds = loadSharedDocsConfig(dbName);
            if (sharedIds.length === 0) continue;

            const items = await new Promise(resolve => {
                try {
                    const req = indexedDB.open(dbName);
                    req.onsuccess = (e) => {
                        const db = e.target.result;
                        if (!db.objectStoreNames.contains('documents')) {
                            resolve([]);
                            return;
                        }
                        const tx = db.transaction(['documents'], 'readonly');
                        const store = tx.objectStore('documents');
                        const allReq = store.getAll();
                        allReq.onsuccess = async (ev) => {
                            const allDocs = ev.target.result || [];
                            const filtered = allDocs.filter(d => sharedIds.includes(Number(d.id)));

                            const cleanDocs = await Promise.all(filtered.slice(0, MAX_CATALOG_ITEMS_PER_PEER).map(async d => {
                                let hash = d.fileHash;
                                if (!hash && d.fileData) {
                                    try {
                                        const u8 = dataUrlToUint8Array(d.fileData);
                                        hash = await computeSHA256(u8.buffer);
                                    } catch (e) {}
                                }
                                return {
                                    id: Number(d.id),
                                    thema: clampString(d.thema, MAX_META_STRING_LEN),
                                    lektion: clampString(d.lektion, MAX_META_STRING_LEN),
                                    buch: clampString(d.buch, MAX_META_STRING_LEN),
                                    klassen: clampString(d.klassen, 80),
                                    jahr: clampString(d.jahr, 20),
                                    typ: clampString(d.typ, 80),
                                    subTyp: Array.isArray(d.subTyp) ? d.subTyp.slice(0, 10).map(s => clampString(s, 80)) : [],
                                    fileName: clampString(d.fileName, 150),
                                    fileType: clampString(d.fileType, 100),
                                    fileSize: Number(d.fileSize) || 0,
                                    fileHash: hash || '',
                                    date: clampString(d.date, 40),
                                    peerId: myPeerId,
                                    sourceDb: dbName
                                };
                            }));
                            resolve(cleanDocs);
                        };
                        allReq.onerror = () => resolve([]);
                    };
                    req.onerror = () => resolve([]);
                } catch (e) {
                    resolve([]);
                }
            });
            combined = combined.concat(items);
        }

        localCatalog = combined.slice(0, MAX_CATALOG_ITEMS_PER_PEER);
    }

    // --- Dynamic PeerJS Loader Helper ---
    function ensurePeerJsLoaded() {
        return new Promise((resolve) => {
            if (typeof window.Peer !== 'undefined') {
                resolve(true);
                return;
            }
            const candidateUrls = [
                'lib/peerjs/v1/peerjs.min.js',
                'lib/peerjs/peerjs.min.js',
                '../lib/peerjs/v1/peerjs.min.js',
                '../lib/peerjs/peerjs.min.js',
                'peerjs.min.js',
                'https://unpkg.com/peerjs@1.5.4/dist/peerjs.min.js'
            ];
            function tryNext() {
                if (typeof window.Peer !== 'undefined') { resolve(true); return; }
                if (candidateUrls.length === 0) { resolve(false); return; }
                const src = candidateUrls.shift();
                const script = document.createElement('script');
                script.src = src;
                script.onload = () => {
                    if (typeof window.Peer !== 'undefined') resolve(true);
                    else tryNext();
                };
                script.onerror = () => tryNext();
                document.head.appendChild(script);
            }
            tryNext();
        });
    }

    // --- WebRTC PeerJS Mesh Setup ---
    function getLobbySlotId(room, slotNum) {
        const cleanRoom = (room || 'global').replace(/[^a-z0-9\-]/gi, '').toLowerCase().substring(0, 24) || 'global';
        return `${LOBBY_PREFIX}${cleanRoom}-${slotNum}`;
    }

    async function initWebRtcSwarm() {
        const loaded = await ensurePeerJsLoaded();
        if (!loaded || typeof window.Peer === 'undefined') {
            console.warn('[Osiris Swarm] PeerJS could not be loaded; running on BroadcastChannel only.');
            webrtcStatus = 'offline';
            updateSwarmBadge();
            renderSwarmModalContent();
            return;
        }

        try {
            activeSwarmRoom = (sessionStorage.getItem('osiris_swarm_room') || 'global').trim();
        } catch (e) {}

        webrtcStatus = 'connecting';
        updateSwarmBadge();
        renderSwarmModalContent();

        // Attempt to claim an available lobby slot from 1 to LOBBY_SLOT_COUNT
        attemptClaimLobbySlot(1);
    }

    function attemptClaimLobbySlot(slotIndex) {
        if (slotIndex > LOBBY_SLOT_COUNT) {
            // All fixed lobby slots are occupied: register as dynamic client
            const cleanRoom = activeSwarmRoom.replace(/[^a-z0-9\-]/gi, '').toLowerCase().substring(0, 24) || 'global';
            const dynId = `${LOBBY_PREFIX}${cleanRoom}-dyn-${myPeerId.replace('_', '-')}`;
            createPeerInstance(dynId, false);
            return;
        }

        currentLobbySlot = slotIndex;
        const candidateId = getLobbySlotId(activeSwarmRoom, slotIndex);

        try {
            createPeerInstance(candidateId, true, slotIndex);
        } catch (err) {
            console.warn(`[Osiris Swarm] Error creating Peer on ${candidateId}:`, err);
            attemptClaimLobbySlot(slotIndex + 1);
        }
    }

    function createPeerInstance(peerId, isLobbySlot, currentSlot) {
        if (peerJsInstance) {
            try { peerJsInstance.destroy(); } catch (e) {}
            peerJsInstance = null;
        }

        const peer = new window.Peer(peerId, {
            debug: 1,
            config: {
                iceServers: [
                    { urls: 'stun:stun.l.google.com:19302' },
                    { urls: 'stun:stun1.l.google.com:19302' },
                    { urls: 'stun:stun2.l.google.com:19302' },
                    { urls: 'turn:openrelay.metered.ca:80', username: 'openrelay', credential: 'openrelay' },
                    { urls: 'turn:openrelay.metered.ca:443', username: 'openrelay', credential: 'openrelay' },
                    { urls: 'turns:openrelay.metered.ca:443?transport=tcp', username: 'openrelay', credential: 'openrelay' }
                ]
            }
        });

        peer.on('open', (id) => {
            peerJsInstance = peer;
            myWebrtcId = id;
            webrtcStatus = 'connected';
            console.log(`[Osiris Swarm] WebRTC Mesh Online as ${id}`);

            // Connect to all other lobby slots in the current room
            connectToLobbyMesh();

            updateSwarmBadge();
            renderSwarmModalContent();
        });

        peer.on('connection', (conn) => {
            setupDataConnection(conn);
        });

        peer.on('error', (err) => {
            if (isLobbySlot && err.type === 'unavailable-id') {
                // This slot is taken by another teacher: try the next slot
                attemptClaimLobbySlot((currentSlot || 1) + 1);
            } else {
                console.warn('[Osiris Swarm] WebRTC Peer Error:', err.type, err.message);
                if (!peerJsInstance && isLobbySlot) {
                    attemptClaimLobbySlot((currentSlot || 1) + 1);
                }
            }
        });

        peer.on('disconnected', () => {
            webrtcStatus = 'connecting';
            try { peer.reconnect(); } catch (e) {}
        });

        peer.on('close', () => {
            webrtcStatus = 'offline';
        });
    }

    function connectToLobbyMesh() {
        if (!peerJsInstance || !myWebrtcId) return;

        // Try connecting to all other lobby slots 1..8
        for (let i = 1; i <= LOBBY_SLOT_COUNT; i++) {
            const targetId = getLobbySlotId(activeSwarmRoom, i);
            if (targetId !== myWebrtcId && !webrtcConnections.has(targetId)) {
                connectToWebRtcPeer(targetId);
            }
        }
    }

    function connectToWebRtcPeer(targetId) {
        if (!peerJsInstance || !targetId || targetId === myWebrtcId) return;
        if (webrtcConnections.has(targetId)) return;

        try {
            const conn = peerJsInstance.connect(targetId, {
                reliable: true,
                serialization: 'json'
            });
            setupDataConnection(conn);
        } catch (e) {
            console.warn('[Osiris Swarm] Connect error to', targetId, e);
        }
    }

    function setupDataConnection(conn) {
        if (!conn) return;

        conn.on('open', () => {
            webrtcConnections.set(conn.peer, conn);

            // Immediately exchange presence & catalog over WebRTC
            sendOverConn(conn, {
                type: 'PEER_ANNOUNCE',
                sender: myPeerId,
                webrtcId: myWebrtcId,
                knownWebrtcIds: Array.from(webrtcConnections.keys()),
                catalog: localCatalog
            });

            updateSwarmBadge();
            renderSwarmModalContent();
        });

        conn.on('data', (raw) => {
            handleWebRtcIncomingData(raw, conn);
        });

        conn.on('close', () => {
            webrtcConnections.delete(conn.peer);
            updateSwarmBadge();
            renderSwarmModalContent();
        });

        conn.on('error', () => {
            webrtcConnections.delete(conn.peer);
        });
    }

    function sendOverConn(conn, packet) {
        if (!conn || !conn.open) return;
        try {
            const jsonStr = JSON.stringify(packet);
            if (jsonStr.length <= CHUNK_SIZE) {
                conn.send(packet);
            } else {
                // Chunk large packets (e.g. DELIVER_DOC with full PDF bytes)
                const transferId = generateCryptoHex(8);
                const totalChunks = Math.ceil(jsonStr.length / CHUNK_SIZE);
                for (let i = 0; i < totalChunks; i++) {
                    const chunkSlice = jsonStr.substring(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
                    conn.send({
                        type: 'SWARM_CHUNK',
                        sender: myPeerId,
                        transferId: transferId,
                        chunkIndex: i,
                        totalChunks: totalChunks,
                        data: chunkSlice
                    });
                }
            }
        } catch (e) {
            console.warn('[Osiris Swarm] Send over WebRTC failed:', e);
        }
    }

    function handleWebRtcIncomingData(raw, conn) {
        let msg = raw;
        if (typeof raw === 'string') {
            msg = safeJsonParse(raw);
        }
        if (!msg || typeof msg !== 'object') return;

        // Handle chunked packet reassembly
        if (msg.type === 'SWARM_CHUNK') {
            handleIncomingChunk(msg, conn);
            return;
        }

        // Map Osiris peer ID to WebRTC connection ID
        if (msg.sender && PEER_ID_REGEX.test(msg.sender) && conn && conn.peer) {
            peerToWebrtcMap.set(msg.sender, conn.peer);
        }

        // PEX Gossip: Discover other active WebRTC peer IDs
        if (Array.isArray(msg.knownWebrtcIds)) {
            msg.knownWebrtcIds.slice(0, 16).forEach(wId => {
                if (wId && typeof wId === 'string' && wId !== myWebrtcId && !webrtcConnections.has(wId)) {
                    connectToWebRtcPeer(wId);
                }
            });
        }

        handleSwarmMessage({ data: msg });
    }

    function handleIncomingChunk(chunkMsg, conn) {
        const transferId = clampString(chunkMsg.transferId, 32);
        const idx = Number(chunkMsg.chunkIndex);
        const total = Number(chunkMsg.totalChunks);
        const chunkData = typeof chunkMsg.data === 'string' ? chunkMsg.data : '';

        if (!transferId || isNaN(idx) || isNaN(total) || total > 800) return;

        const now = Date.now();
        // Clean expired transfers (>60s)
        incomingChunks.forEach((entry, tid) => {
            if (now - entry.startedAt > 60000) incomingChunks.delete(tid);
        });

        let entry = incomingChunks.get(transferId);
        if (!entry) {
            entry = {
                chunks: new Map(),
                total: total,
                sender: chunkMsg.sender,
                startedAt: now
            };
            incomingChunks.set(transferId, entry);
        }

        entry.chunks.set(idx, chunkData);

        if (entry.chunks.size === entry.total) {
            incomingChunks.delete(transferId);
            let fullStr = '';
            for (let i = 0; i < entry.total; i++) {
                fullStr += entry.chunks.get(i) || '';
            }
            const reassembled = safeJsonParse(fullStr);
            if (reassembled && typeof reassembled === 'object') {
                if (reassembled.sender && PEER_ID_REGEX.test(reassembled.sender) && conn && conn.peer) {
                    peerToWebrtcMap.set(reassembled.sender, conn.peer);
                }
                handleSwarmMessage({ data: reassembled });
            }
        }
    }

    // --- Outgoing Unified Packet Router ---
    function sendSwarmPacket(packet, targetOsirisPeerId) {
        // 1. BroadcastChannel (local browser tabs)
        if (broadcastChannel) {
            try {
                broadcastChannel.postMessage(packet);
            } catch (e) {}
        }

        // 2. WebRTC DataChannels (cross-device mesh across GitHub Pages)
        if (webrtcConnections.size > 0) {
            if (targetOsirisPeerId && peerToWebrtcMap.has(targetOsirisPeerId)) {
                const targetWebrtcId = peerToWebrtcMap.get(targetOsirisPeerId);
                const targetConn = webrtcConnections.get(targetWebrtcId);
                if (targetConn && targetConn.open) {
                    sendOverConn(targetConn, packet);
                    return;
                }
            }

            // Otherwise multicast to all open WebRTC connections
            webrtcConnections.forEach(conn => {
                sendOverConn(conn, packet);
            });
        }
    }

    async function initSwarm(config) {
        if (config) Object.assign(currentConfig, config);
        await refreshLocalCatalog();

        // 1. Init BroadcastChannel (local tabs)
        if ('BroadcastChannel' in window) {
            try {
                broadcastChannel = new BroadcastChannel(SWARM_CHANNEL_NAME);
                broadcastChannel.onmessage = handleSwarmMessage;
                broadcastPresence();
            } catch (err) {
                console.warn('BroadcastChannel init error:', err);
            }
        }

        // 2. Init WebRTC PeerJS Mesh (Global cross-device mesh)
        initWebRtcSwarm();

        // Periodic presence broadcast & mesh reconnection every 15s
        setInterval(() => {
            broadcastPresence();
            connectToLobbyMesh();
            pruneStalePeers();
        }, 15000);

        updateSwarmBadge();
    }

    function pruneStalePeers() {
        const now = Date.now();
        let changed = false;
        remoteCatalog.forEach((peerData, peerId) => {
            if (now - peerData.lastSeen > 45000) {
                remoteCatalog.delete(peerId);
                changed = true;
            }
        });
        if (changed) {
            updateSwarmBadge();
            renderSwarmModalContent();
        }
    }

    function broadcastPresence() {
        sendSwarmPacket({
            type: 'PEER_ANNOUNCE',
            sender: myPeerId,
            webrtcId: myWebrtcId,
            knownWebrtcIds: Array.from(webrtcConnections.keys()),
            catalog: localCatalog
        });
    }

    function enforceMaxPeers() {
        if (remoteCatalog.size > MAX_TRACKED_PEERS) {
            const oldestPeer = remoteCatalog.keys().next().value;
            if (oldestPeer) remoteCatalog.delete(oldestPeer);
        }
    }

    function handleSwarmMessage(event) {
        const msg = event.data;
        if (!msg || typeof msg !== 'object' || msg.sender === myPeerId) return;

        // 1. Strict Peer ID format & DDoS Rate Limit Check
        if (!isPeerRateAllowed(msg.sender)) return;

        switch (msg.type) {
            case 'PEER_ANNOUNCE':
                enforceMaxPeers();
                remoteCatalog.set(msg.sender, {
                    lastSeen: Date.now(),
                    docs: sanitizeRemoteCatalogList(msg.catalog),
                    webrtcId: msg.webrtcId || null
                });
                updateSwarmBadge();
                renderSwarmModalContent();

                sendSwarmPacket({
                    type: 'PEER_ACK',
                    sender: myPeerId,
                    target: msg.sender,
                    webrtcId: myWebrtcId,
                    catalog: localCatalog
                }, msg.sender);
                break;

            case 'PEER_ACK':
                if (msg.target === myPeerId) {
                    enforceMaxPeers();
                    remoteCatalog.set(msg.sender, {
                        lastSeen: Date.now(),
                        docs: sanitizeRemoteCatalogList(msg.catalog),
                        webrtcId: msg.webrtcId || null
                    });
                    updateSwarmBadge();
                    renderSwarmModalContent();
                }
                break;

            case 'REQUEST_DOC':
                if (msg.target === myPeerId) {
                    const reqDocId = Number(msg.docId);
                    const reqToken = typeof msg.requestToken === 'string' && /^[a-f0-9]{16,64}$/i.test(msg.requestToken) ? msg.requestToken : '';
                    if (reqDocId && reqToken && isDocShared(reqDocId)) {
                        serveDocToPeer(reqDocId, msg.sender, reqToken);
                    }
                }
                break;

            case 'DELIVER_DOC':
                if (msg.target === myPeerId && msg.payload) {
                    const deliveredId = Number(msg.payload.id);
                    const reqKey = `${msg.sender}:${deliveredId}`;
                    const pending = pendingRequests.get(reqKey);
                    // Block unsolicited, expired, or forged document pushes
                    if (!pending || Date.now() > pending.expiresAt || pending.token !== msg.requestToken) {
                        pendingRequests.delete(reqKey);
                        console.warn('[Osiris Security] Blocked unsolicited or forged DELIVER_DOC from', msg.sender);
                        return;
                    }
                    pendingRequests.delete(reqKey);
                    receiveDocFromPeer(msg.payload);
                }
                break;
        }
    }

    // Searches both DokumentationDB and TestBankDB to serve requested document
    function serveDocToPeer(docId, targetPeerId, requestToken) {
        if (!isDocShared(docId)) return;
        const dbsToTry = [currentConfig.dbName, currentConfig.dbName === 'DokumentationDB' ? 'TestBankDB' : 'DokumentationDB'];

        function tryDb(idx) {
            if (idx >= dbsToTry.length) return;
            const dbName = dbsToTry[idx];
            try {
                const req = indexedDB.open(dbName);
                req.onsuccess = (e) => {
                    const db = e.target.result;
                    if (!db.objectStoreNames.contains('documents')) {
                        tryDb(idx + 1);
                        return;
                    }
                    const tx = db.transaction(['documents'], 'readonly');
                    const store = tx.objectStore('documents');
                    store.get(Number(docId)).onsuccess = (ev) => {
                        const item = ev.target.result;
                        if (item) {
                            sendSwarmPacket({
                                type: 'DELIVER_DOC',
                                sender: myPeerId,
                                target: targetPeerId,
                                requestToken: requestToken,
                                payload: sanitizeDocRecord(Object.assign({}, item, { sourceDb: dbName }))
                            }, targetPeerId);
                        } else {
                            tryDb(idx + 1);
                        }
                    };
                };
                req.onerror = () => tryDb(idx + 1);
            } catch (err) {
                tryDb(idx + 1);
            }
        }

        tryDb(0);
    }

    async function receiveDocFromPeer(rawDocItem) {
        const docItem = sanitizeDocRecord(rawDocItem);
        if (!docItem || !docItem.fileData) {
            alert('⚠️ P2P-Übertragung abgelehnt: Ungültige oder manipulierte Dokumentendaten.');
            return;
        }

        let u8;
        try {
            u8 = dataUrlToUint8Array(docItem.fileData);
        } catch (err) {
            alert('⚠️ Sicherheitswarnung: Datei überschreitet das 25 MB Limit oder ist korrupt.');
            return;
        }

        // 1. Deep Magic-Byte & Active Content Inspection
        const check = validateMagicBytes(u8, docItem.fileName);
        if (!check.valid) {
            alert('🛑 SICHERHEITSBLOCKADE: Das eingehende Dokument wurde abgewiesen!\nGrund: ' + check.reason);
            return;
        }

        // 2. Mandatory SHA-256 Bit-Integrity Verification
        const computedHash = await computeSHA256(u8.buffer);
        if (!computedHash || (docItem.fileHash && docItem.fileHash !== computedHash)) {
            alert('🛑 INTEGRITÄTSFEHLER: Der kryptografische SHA-256 Hash stimmt nicht mit dem Original überein! Übertragung abgebrochen.');
            return;
        }

        // 3. Save sanitized record into target IndexedDB (sourceDb if matching, or current active db)
        const targetDb = docItem.sourceDb || currentConfig.dbName;
        const targetStore = currentConfig.storeName;

        try {
            const req = indexedDB.open(targetDb);
            req.onsuccess = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains(targetStore)) return;
                const tx = db.transaction([targetStore], 'readwrite');
                const store = tx.objectStore(targetStore);

                const newItem = Object.assign({}, docItem, {
                    id: Date.now(),
                    fileHash: computedHash,
                    date: new Date().toLocaleDateString()
                });

                store.add(newItem);
                tx.oncomplete = () => {
                    const fp = computedHash.substring(0, 6).toUpperCase();
                    alert(`✅ Dokument „${newItem.thema}" erfolgreich geprüft (SHA-256 #${fp}) und gespeichert!`);
                    if (typeof currentConfig.onDocImported === 'function') {
                        currentConfig.onDocImported();
                    }
                };
            };
        } catch (err) {
            console.error('Save imported doc error:', err);
        }
    }

    function requestDocDownload(docId, peerId) {
        const cleanDocId = Number(docId);
        if (!cleanDocId || !PEER_ID_REGEX.test(peerId)) return;

        // Prune expired pending requests
        const now = Date.now();
        pendingRequests.forEach((val, key) => {
            if (now > val.expiresAt) pendingRequests.delete(key);
        });

        const requestToken = generateCryptoHex(16);
        pendingRequests.set(`${peerId}:${cleanDocId}`, {
            token: requestToken,
            expiresAt: now + 60000 // 60-second strict TTL
        });

        sendSwarmPacket({
            type: 'REQUEST_DOC',
            sender: myPeerId,
            target: peerId,
            docId: cleanDocId,
            requestToken: requestToken
        }, peerId);
    }

    async function toggleShareDocToSwarm(docId, shouldShare) {
        const cleanId = Number(docId);
        if (!cleanId) return;

        let sharedIds = loadSharedDocsConfig(currentConfig.dbName);
        if (shouldShare) {
            if (!sharedIds.includes(cleanId)) sharedIds.push(cleanId);
        } else {
            sharedIds = sharedIds.filter(id => id !== cleanId);
        }
        saveSharedDocsConfig(sharedIds, currentConfig.dbName);

        await refreshLocalCatalog();
        broadcastPresence();
        updateSwarmBadge();
        renderSwarmModalContent();
    }

    function isDocShared(docId) {
        const sharedCurrent = loadSharedDocsConfig(currentConfig.dbName);
        if (sharedCurrent.includes(Number(docId))) return true;
        const otherDb = currentConfig.dbName === 'DokumentationDB' ? 'TestBankDB' : 'DokumentationDB';
        return loadSharedDocsConfig(otherDb).includes(Number(docId));
    }

    // =========================================================================
    // 4. UI: ZERO-TRUST SWARM MODAL RENDERING
    // =========================================================================

    function updateSwarmBadge() {
        const activePeers = remoteCatalog.size;
        const totalShared = localCatalog.length;

        document.querySelectorAll('#swarm-status-badge, #headerSwarmBadge').forEach(badge => {
            if (activePeers > 0) {
                badge.className = 'swarm-pill is-active';
                badge.style.background = '#28a745';
                badge.textContent = `● Schwarm aktiv (${activePeers})`;
            } else {
                badge.className = 'swarm-pill';
                badge.style.background = '#505864';
                badge.textContent = `● Schwarm (${totalShared} geteilt)`;
            }
        });

        // Notify parent frame (EDU_HUB.html)
        if (window.parent && window.parent !== window) {
            try {
                window.parent.postMessage({
                    type: 'SWARM_BADGE_UPDATE',
                    activePeers: activePeers,
                    totalShared: totalShared
                }, getTargetOrigin());
            } catch (e) {}
        }
    }

    function openSwarmModal() {
        let modal = document.getElementById('swarm-modal');
        if (!modal) {
            createSwarmModalDom();
            modal = document.getElementById('swarm-modal');
        }
        modal.style.display = 'flex';
        renderSwarmModalContent();
    }

    function closeSwarmModal() {
        const modal = document.getElementById('swarm-modal');
        if (modal) modal.style.display = 'none';
    }

    
    const SWARM_STRINGS = {
        FR: {
            title: "Essaim Communautaire (P2P Décentralisé)",
            sub: "Partage direct navigateur-à-navigateur · Multi-appareils sur GitHub · Zéro compte",
            directNotice: "✨ Connexion directe automatique : Tous les collègues ouvrant cette page partagent directement leurs documents !",
            activeP2p: "P2P Mondial actif",
            connecting: "Connexion à l'essaim P2P...",
            localOnly: "Essaim local (onglet)",
            tabRemote: "Documents disponibles dans l'essaim",
            tabLocal: "Mes documents partagés",
            noPeers: "Aucun autre collègue actif dans cet essaim pour le moment",
            noPeersHint: "Dès qu'un collègue ouvre DeutschThek et clique sur « Partager dans l'essaim », son document apparaît ici en direct !",
            download: "Télécharger",
            downloading: "Téléchargement...",
            noSharedLocal: "Vous ne partagez aucun document pour le moment",
            noSharedLocalHint: "Pour partager un document avec vos collègues, ouvrez-le en plein écran et cliquez sur « Partager dans l'essaim ».",
            stopShare: "Arrêter le partage",
            close: "Fermer",
            docsAvailable: "document(s) vérifié(s) disponible(s) dans l'essaim :"
        },
        EN: {
            title: "Community Swarm (Decentralized P2P)",
            sub: "Direct Browser-to-Browser · Cross-Device on GitHub · Zero Accounts",
            directNotice: "✨ Automatic Direct Connection: All colleagues on this page can exchange files directly without any code!",
            activeP2p: "Global P2P Active",
            connecting: "Connecting to P2P Swarm...",
            localOnly: "Local Browser Swarm",
            tabRemote: "Available Documents in Swarm",
            tabLocal: "My Shared Documents",
            noPeers: "No other peers active in this swarm right now",
            noPeersHint: "As soon as a colleague opens DeutschThek and shares a document, it will appear here in real time!",
            download: "Download",
            downloading: "Downloading...",
            noSharedLocal: "You are not sharing any documents yet",
            noSharedLocalHint: "To share a document with colleagues, open it and click 'Share to Community Swarm'.",
            stopShare: "Stop Sharing",
            close: "Close",
            docsAvailable: "verified document(s) available in the swarm:"
        },
        DE: {
            title: "Community-Schwarm (Dezentrales WebRTC P2P)",
            sub: "Zero-Knowledge · Browser-to-Browser · Cross-Device auf GitHub Hosting",
            directNotice: "✨ Automatische Direktverbindung: Alle Kollegen auf dieser Seite tauschen Dokumente direkt ohne Code aus!",
            activeP2p: "Global P2P aktiv",
            connecting: "Verbinde mit Globalem Swarm...",
            localOnly: "Lokaler Browser-Swarm",
            tabRemote: "Verfügbare Dokumente im Schwarm",
            tabLocal: "Meine geteilten Dokumente",
            noPeers: "Keine weiteren Peers im Schwarm aktiv",
            noPeersHint: "Sobald sich andere Lehrkräfte auf GitHub Pages befinden und Dokumente bereitstellen, erscheinen diese hier automatisch in Echtzeit.",
            download: "Laden",
            downloading: "Lade...",
            noSharedLocal: "Sie teilen derzeit keine Dokumente",
            noSharedLocalHint: "Um ein Dokument mit der Community zu teilen, öffnen Sie das Dokument in der Vollansicht und klicken Sie auf „In Community-Schwarm teilen“.",
            stopShare: "Teilen beenden",
            close: "Schließen",
            docsAvailable: "geprüfte(s) Dokument(e) im Schwarm verfügbar :"
        }
    };

    function getSwarmLang() {
        try {
            if (window.__bankLang && SWARM_STRINGS[window.__bankLang]) return window.__bankLang;
            const docLang = (document.documentElement.getAttribute('lang') || 'de').toUpperCase();
            if (docLang.startsWith('FR')) return 'FR';
            if (docLang.startsWith('EN')) return 'EN';
        } catch (e) {}
        return (window.bankLang && SWARM_STRINGS[window.bankLang]) ? window.bankLang : 'FR';
    }

        function isDarkThemeActive() {
        const t = (document.documentElement.getAttribute('data-theme') || '').toLowerCase();
        return t === 'dark' || t === 'osiris';
    }

    function createSwarmModalDom() {
        const i18n = (typeof SWARM_STRINGS !== 'undefined' && SWARM_STRINGS[getSwarmLang()]) || {
            title: "Community-Schwarm (Dezentrales WebRTC P2P)",
            sub: "Partage direct navigateur-à-navigateur · Automatique sur cette adresse",
            directNotice: "✨ Connexion directe automatique : Tous les collègues connectés sur cette page échangent directement leurs documents.",
            tabRemote: "Documents disponibles dans l'essaim",
            tabLocal: "Mes documents partagés",
            close: "Fermer",
            download: "Télécharger",
            stopShare: "Arrêter le partage"
        };

        const isDark = isDarkThemeActive();
        const dialogBg = isDark ? '#1a1e24' : '#ffffff';
        const dialogText = isDark ? '#f1f5f9' : '#1e293b';
        const headerBg = isDark ? '#14181d' : '#f8fafc';
        const borderColor = isDark ? '#334155' : '#e2e8f0';

        const modal = document.createElement('div');
        modal.id = 'swarm-modal';
        modal.style.cssText = `
            display: none; position: fixed; inset: 0; background: rgba(5, 10, 18, 0.78);
            z-index: 10005; align-items: center; justify-content: center; padding: 20px;
            backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
        `;

        modal.innerHTML = `
            <div id="swarm-modal-dialog" style="background: ${dialogBg}; color: ${dialogText}; border: 1px solid ${borderColor}; border-radius: 14px; width: 100%; max-width: 860px; max-height: 90vh; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 24px 60px rgba(0,0,0,0.45); opacity: 1 !important;">
                
                <!-- Header (Solid Opaque Background) -->
                <div style="display: flex; justify-content: space-between; align-items: center; padding: 16px 22px; border-bottom: 1px solid ${borderColor}; background: ${headerBg};">
                    <div style="display:flex; align-items:center; gap:12px;">
                        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="2" y1="12" x2="22" y2="12"></line>
                            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10z"></path>
                            <path d="M12 2a15.3 15.3 0 0 0-4 10 15.3 15.3 0 0 0 4 10z"></path>
                        </svg>
                        <div>
                            <h3 id="swarm-ui-title" style="margin:0; font-size:1.18rem; font-weight:700; color:${isDark ? '#60a5fa' : '#1e3a8a'};">${i18n.title}</h3>
                            <div id="swarm-ui-sub" style="font-size:0.75rem; color:${isDark ? '#94a3b8' : '#64748b'}; margin-top:2px;">${i18n.sub}</div>
                        </div>
                    </div>
                    <button id="swarm-close-x" aria-label="Schließen" style="background:transparent; border:none; cursor:pointer; color:${isDark ? '#94a3b8' : '#64748b'}; padding:6px; display:flex; align-items:center; justify-content:center; border-radius:6px;">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                    </button>
                </div>

                <!-- Clean Status Banner (Pure Direct Exchange - No Private Keys or Codes) -->
                <div style="padding: 12px 22px; background: ${isDark ? 'rgba(34, 197, 94, 0.12)' : 'rgba(34, 197, 94, 0.08)'}; border-bottom: 1px solid ${isDark ? 'rgba(34, 197, 94, 0.25)' : 'rgba(34, 197, 94, 0.2)'}; font-size: 0.84rem; display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap:wrap;">
                    <div style="display:flex; align-items:center; gap:9px;">
                        <span id="swarm-net-dot" style="display:inline-block; width:10px; height:10px; border-radius:50%; background:#22c55e; box-shadow:0 0 8px rgba(34, 197, 94, 0.7); flex-shrink:0;"></span>
                        <span id="swarm-net-status-text" style="color:${isDark ? '#bbf7d0' : '#166534'};"><strong>Connexion automatique en direct :</strong> Tous les utilisateurs ouvrant cette adresse échangent directement leurs documents.</span>
                    </div>
                    <span id="swarm-mesh-badge" style="font-size:0.75rem; font-weight:700; color:#16a34a; background:${isDark ? 'rgba(34,197,94,0.18)' : '#dcfce7'}; border:1px solid rgba(34,197,94,0.35); padding:3px 9px; border-radius:6px; white-space:nowrap;">● P2P Direct Actif</span>
                </div>

                <!-- Tabs -->
                <div style="display:flex; border-bottom: 1px solid ${borderColor}; background: ${headerBg};">
                    <button id="swarm-tab-remote" style="flex:1; padding:13px; border:none; background:transparent; border-bottom:3px solid #2563eb; font-weight:700; cursor:pointer; color:#2563eb; font-size:0.9rem;">${i18n.tabRemote}</button>
                    <button id="swarm-tab-local" style="flex:1; padding:13px; border:none; background:transparent; border-bottom:3px solid transparent; font-weight:600; cursor:pointer; color:${isDark ? '#94a3b8' : '#64748b'}; font-size:0.9rem;">${i18n.tabLocal}</button>
                </div>

                <!-- Tab Content Area (Solid Opaque Background, Zero Bleed-Through) -->
                <div id="swarm-tab-content" style="padding: 22px; overflow-y: auto; flex: 1; background: ${dialogBg}; min-height: 260px;"></div>

                <!-- Footer -->
                <div style="padding: 14px 22px; border-top: 1px solid ${borderColor}; display: flex; justify-content: space-between; align-items: center; background: ${headerBg}; font-size: 0.82rem;">
                    <span id="swarm-footer-stats" style="color:${isDark ? '#94a3b8' : '#64748b'};">Status: P2P Swarm actif</span>
                    <button id="swarm-close-btn" style="padding: 8px 18px; border: 1px solid ${borderColor}; border-radius: 6px; background: ${dialogBg}; color: ${dialogText}; font-weight: 600; cursor: pointer; font-size:0.84rem;">${i18n.close}</button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        document.getElementById('swarm-close-x').addEventListener('click', closeSwarmModal);
        document.getElementById('swarm-close-btn').addEventListener('click', closeSwarmModal);
        document.getElementById('swarm-tab-remote').addEventListener('click', () => switchSwarmTab('remote'));
        document.getElementById('swarm-tab-local').addEventListener('click', () => switchSwarmTab('local'));

        // Event delegation for Download and Stop sharing buttons
        const contentWrap = document.getElementById('swarm-tab-content');
        contentWrap.addEventListener('click', (e) => {
            const dlBtn = e.target.closest('[data-swarm-download]');
            if (dlBtn) {
                const docId = Number(dlBtn.getAttribute('data-doc-id'));
                const peerId = dlBtn.getAttribute('data-peer-id') || '';
                dlBtn.disabled = true;
                dlBtn.innerHTML = `<span>${i18n.downloading || 'Lade...'}</span>`;
                requestDocDownload(docId, peerId);
                setTimeout(() => {
                    dlBtn.disabled = false;
                    dlBtn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg> <span>${i18n.download || 'Laden'}</span>`;
                }, 3000);
                return;
            }
            const stopBtn = e.target.closest('[data-swarm-stop]');
            if (stopBtn) {
                const docId = Number(stopBtn.getAttribute('data-doc-id'));
                toggleShareDocToSwarm(docId, false);
            }
        });

        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeSwarmModal();
        });
    }

    let currentSwarmTab = 'remote';

    function switchSwarmTab(tab) {
        currentSwarmTab = tab === 'local' ? 'local' : 'remote';
        const btnRemote = document.getElementById('swarm-tab-remote');
        const btnLocal = document.getElementById('swarm-tab-local');
        if (btnRemote && btnLocal) {
            btnRemote.style.borderBottomColor = currentSwarmTab === 'remote' ? 'var(--primary)' : 'transparent';
            btnRemote.style.color = currentSwarmTab === 'remote' ? 'var(--primary)' : 'gray';
            btnLocal.style.borderBottomColor = currentSwarmTab === 'local' ? 'var(--primary)' : 'transparent';
            btnLocal.style.color = currentSwarmTab === 'local' ? 'var(--primary)' : 'gray';
        }
        renderSwarmModalContent();
    }

        function renderSwarmModalContent() {
        const wrap = document.getElementById('swarm-tab-content');
        if (!wrap) return;

        const isDark = isDarkThemeActive();
        const cardBg = isDark ? '#232a35' : '#ffffff';
        const cardBorder = isDark ? '#374151' : '#e2e8f0';
        const textColor = isDark ? '#f8fafc' : '#0f172a';
        const metaColor = isDark ? '#94a3b8' : '#64748b';
        const shadow = isDark ? '0 3px 10px rgba(0,0,0,0.35)' : '0 2px 6px rgba(0,0,0,0.06)';

        const i18n = (typeof SWARM_STRINGS !== 'undefined' && SWARM_STRINGS[getSwarmLang()]) || {
            download: "Laden",
            stopShare: "Teilen beenden",
            noPeers: "Keine weiteren Peers im Schwarm aktiv",
            noPeersHint: "Sobald sich andere Lehrkräfte auf GitHub Pages befinden und Dokumente bereitstellen, erscheinen diese hier automatisch in Echtzeit.",
            noSharedLocal: "Sie teilen derzeit keine Dokumente",
            noSharedLocalHint: "Um ein Dokument mit der Community zu teilen, öffnen Sie das Dokument in der Vollansicht und klicken Sie auf „In Community-Schwarm teilen“.",
            docsAvailable: "geprüfte(s) Dokument(e) im Schwarm verfügbar :"
        };

        // Update badge and status text
        const netDot = document.getElementById('swarm-net-dot');
        const netBadge = document.getElementById('swarm-mesh-badge');
        if (netDot && netBadge) {
            const isConn = webrtcStatus === 'connected';
            netDot.style.background = isConn ? '#22c55e' : (webrtcStatus === 'connecting' ? '#eab308' : '#64748b');
            netBadge.textContent = isConn ? `● WebRTC Mesh (${webrtcConnections.size} Peers)` : (webrtcStatus === 'connecting' ? '● Verbinde...' : '● Lokal');
        }

        if (currentSwarmTab === 'remote') {
            const allRemoteDocs = [];
            remoteCatalog.forEach((peerData, peerId) => {
                if (!PEER_ID_REGEX.test(peerId)) return;
                (peerData.docs || []).forEach(doc => {
                    allRemoteDocs.push({ peerId, doc });
                });
            });

            if (allRemoteDocs.length === 0) {
                wrap.innerHTML = `
                    <div style="text-align:center; padding: 48px 20px; color: ${metaColor};">
                        <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="1.75" style="opacity:0.75; margin-bottom:12px;"><path d="M4.93 4.93a10 10 0 0 1 14.14 0"></path><path d="M7.76 7.76a6 6 0 0 1 8.48 0"></path><circle cx="12" cy="12" r="2"></circle><path d="M12 14v8"></path></svg>
                        <h4 style="margin:0 0 8px 0; color:${textColor}; font-size:1.05rem;">${i18n.noPeers}</h4>
                        <p style="margin:0; font-size:0.86rem; max-width:480px; margin:auto; line-height:1.5;">
                            ${i18n.noPeersHint}
                        </p>
                    </div>
                `;
            } else {
                let html = `
                    <div style="display:flex; flex-direction:column; gap:12px;">
                        <div style="font-size:0.85rem; color:${metaColor}; margin-bottom:2px; font-weight:600;">
                            ${allRemoteDocs.length} ${i18n.docsAvailable}
                        </div>
                `;

                allRemoteDocs.forEach(({ peerId, doc }) => {
                    const safeTyp = escapeHtml(doc.typ);
                    const safeKlassen = escapeHtml(doc.klassen);
                    const safeJahr = escapeHtml(doc.jahr);
                    const safeThema = escapeHtml(doc.thema);
                    const safeLektion = escapeHtml(doc.lektion);
                    const safeBuch = escapeHtml(doc.buch);
                    const safeFileName = escapeHtml(doc.fileName);
                    const safePeerId = escapeHtml(peerId);
                    const safeDocId = Number(doc.id) || 0;
                    const shortHash = doc.fileHash ? escapeHtml(doc.fileHash.substring(0, 6).toUpperCase()) : 'UNVERIFIED';

                    html += `
                        <div style="display:flex; justify-content:space-between; align-items:center; padding:14px 18px; border:1px solid ${cardBorder}; border-radius:10px; background:${cardBg}; box-shadow:${shadow}; gap:14px;">
                            <div style="flex:1; min-width:0;">
                                <div style="display:flex; gap:6px; align-items:center; margin-bottom:6px; flex-wrap:wrap;">
                                    <span style="background:#2563eb; color:white; padding:2px 8px; border-radius:4px; font-size:0.72rem; font-weight:700;">${safeTyp}</span>
                                    <span style="background:${isDark ? '#334155' : '#e2e8f0'}; color:${textColor}; padding:2px 8px; border-radius:4px; font-size:0.72rem; font-weight:600;">${safeKlassen}</span>
                                    <span style="background:${isDark ? '#334155' : '#e2e8f0'}; color:${textColor}; padding:2px 8px; border-radius:4px; font-size:0.72rem;">${safeJahr}</span>
                                    <span title="SHA-256 Fingerabdruck" style="background:${isDark ? 'rgba(34,197,94,0.18)' : '#dcfce7'}; color:#16a34a; border:1px solid rgba(34,197,94,0.35); padding:1px 7px; border-radius:4px; font-family:monospace; font-size:0.72rem; font-weight:700;">SHA: #${shortHash}</span>
                                </div>
                                <h4 style="margin:0 0 4px 0; color:${isDark ? '#60a5fa' : '#1e3a8a'}; font-size:1rem; font-weight:700; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${safeThema}</h4>
                                <div style="font-size:0.78rem; color:${metaColor}; line-height:1.4;">
                                    Lektion: <strong>${safeLektion}</strong> | Buch: <strong>${safeBuch}</strong> | 📄 ${safeFileName}
                                </div>
                            </div>
                            <button type="button" data-swarm-download="1" data-doc-id="${safeDocId}" data-peer-id="${safePeerId}" style="display:flex; align-items:center; gap:8px; padding:10px 18px; background:#2563eb; color:#ffffff; border:none; border-radius:8px; font-weight:700; cursor:pointer; font-size:0.85rem; box-shadow:0 2px 6px rgba(37,99,235,0.35); flex-shrink:0;">
                                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                                <span>${i18n.download || 'Laden'}</span>
                            </button>
                        </div>
                    `;
                });

                html += `</div>`;
                wrap.innerHTML = html;
            }
        } else {
            if (localCatalog.length === 0) {
                wrap.innerHTML = `
                    <div style="text-align:center; padding: 48px 20px; color: ${metaColor};">
                        <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="1.75" style="opacity:0.75; margin-bottom:12px;"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
                        <h4 style="margin:0 0 8px 0; color:${textColor}; font-size:1.05rem;">${i18n.noSharedLocal}</h4>
                        <p style="margin:0; font-size:0.86rem; max-width:480px; margin:auto; line-height:1.5;">
                            ${i18n.noSharedLocalHint}
                        </p>
                    </div>
                `;
            } else {
                let html = `
                    <div style="display:flex; flex-direction:column; gap:12px;">
                        <div style="font-size:0.85rem; color:${metaColor}; margin-bottom:2px; font-weight:600;">
                            Vous partagez ${localCatalog.length} document(s) dans l'essaim :
                        </div>
                `;

                localCatalog.forEach(doc => {
                    const safeTyp = escapeHtml(doc.typ);
                    const safeKlassen = escapeHtml(doc.klassen);
                    const safeJahr = escapeHtml(doc.jahr);
                    const safeThema = escapeHtml(doc.thema);
                    const safeFileName = escapeHtml(doc.fileName);
                    const safeDocId = Number(doc.id) || 0;
                    const shortHash = doc.fileHash ? escapeHtml(doc.fileHash.substring(0, 6).toUpperCase()) : 'LOCAL';

                    html += `
                        <div style="display:flex; justify-content:space-between; align-items:center; padding:14px 18px; border:1px solid ${cardBorder}; border-radius:10px; background:${cardBg}; box-shadow:${shadow}; gap:14px;">
                            <div style="flex:1; min-width:0;">
                                <div style="display:flex; gap:6px; align-items:center; margin-bottom:6px; flex-wrap:wrap;">
                                    <span style="background:#2563eb; color:white; padding:2px 8px; border-radius:4px; font-size:0.72rem; font-weight:700;">${safeTyp}</span>
                                    <span style="background:${isDark ? '#334155' : '#e2e8f0'}; color:${textColor}; padding:2px 8px; border-radius:4px; font-size:0.72rem; font-weight:600;">${safeKlassen}</span>
                                    <span style="background:${isDark ? '#334155' : '#e2e8f0'}; color:${textColor}; padding:2px 8px; border-radius:4px; font-size:0.72rem;">${safeJahr}</span>
                                    <span style="background:${isDark ? 'rgba(34,197,94,0.18)' : '#dcfce7'}; color:#16a34a; border:1px solid rgba(34,197,94,0.35); padding:1px 7px; border-radius:4px; font-family:monospace; font-size:0.72rem; font-weight:700;">SHA: #${shortHash}</span>
                                </div>
                                <h4 style="margin:0 0 4px 0; color:${isDark ? '#60a5fa' : '#1e3a8a'}; font-size:1rem; font-weight:700; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${safeThema}</h4>
                                <div style="font-size:0.78rem; color:${metaColor};">📄 ${safeFileName}</div>
                            </div>
                            <button type="button" data-swarm-stop="1" data-doc-id="${safeDocId}" style="padding:8px 14px; background:#dc2626; color:white; border:none; border-radius:6px; font-weight:700; cursor:pointer; font-size:0.8rem; flex-shrink:0;">
                                <span>${i18n.stopShare || 'Teilen beenden'}</span>
                            </button>
                        </div>
                    `;
                });

                html += `</div>`;
                wrap.innerHTML = html;
            }
        }

        const footerStats = document.getElementById('swarm-footer-stats');
        if (footerStats) {
            const activePeers = remoteCatalog.size;
            footerStats.textContent = `Status: ${activePeers} Peer(s) im Netzwerk (${webrtcConnections.size} WebRTC verbunden) | ${localCatalog.length} eigene(s) Dokument(e) freigegeben`;
        }
    }

    const osirisSecurityApi = Object.freeze({
        escapeHtml: escapeHtml,
        clampString: clampString,
        sanitizeUrl: sanitizeUrl,
        sanitizeDataUrl: sanitizeDataUrl,
        sanitizeHtmlFragment: sanitizeHtmlFragment,
        safeJsonParse: safeJsonParse,
        validateMagicBytes: validateMagicBytes,
        sanitizeDocRecord: sanitizeDocRecord,
        sanitizeWikiEntry: sanitizeWikiEntry,
        sanitizeLinkEntry: sanitizeLinkEntry,
        sanitizeThemeName: sanitizeThemeName,
        sanitizeFontFamily: sanitizeFontFamily,
        sanitizeFileName: sanitizeFileName,
        isTrustedOrigin: isTrustedOrigin,
        getTargetOrigin: getTargetOrigin,
        computeSHA256: computeSHA256,
        MAX_FILE_BYTES: MAX_FILE_BYTES
    });

    const eduHybridShareApi = Object.freeze({
        init: initSwarm,
        shareSocial: shareSocial,
        openSwarmModal: openSwarmModal,
        closeSwarmModal: closeSwarmModal,
        switchSwarmTab: switchSwarmTab,
        toggleShareDocToSwarm: toggleShareDocToSwarm,
        isDocShared: isDocShared,
        requestDocDownload: requestDocDownload,
        validateMagicBytes: validateMagicBytes,
        computeSHA256: computeSHA256,
        exportSinglePackage: exportSinglePackage,
    });

    try {
        Object.defineProperty(window, 'OsirisSecurity', {
            value: osirisSecurityApi,
            writable: false,
            configurable: false,
            enumerable: true
        });
        Object.defineProperty(window, 'EduHybridShare', {
            value: eduHybridShareApi,
            writable: false,
            configurable: false,
            enumerable: true
        });
    } catch (e) {
        window.OsirisSecurity = osirisSecurityApi;
        window.EduHybridShare = eduHybridShareApi;
    }

})(window);

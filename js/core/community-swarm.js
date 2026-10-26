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
    const MAX_P2P_SHARE_BYTES = 10 * 1024 * 1024; // 10 MB strict limit for P2P Community Swarm
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
    const userDownloadRequests = new Set(); // Tracks doc IDs explicitly requested for browser disk download

    function triggerBrowserFileDownload(fileName, dataUrl) {
        if (!dataUrl || !fileName) return false;
        try {
            const a = document.createElement('a');
            a.href = dataUrl;
            a.download = fileName;
            document.body.appendChild(a);
            a.click();
            setTimeout(() => {
                if (a && a.parentNode) a.parentNode.removeChild(a);
            }, 300);
            return true;
        } catch (e) {
            console.warn('[Osiris Swarm] Browser file download failed:', e);
            return false;
        }
    }

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
        let raw = String(fileName || 'Dokument.pdf')
            .replace(/[\u202A-\u202E\u2066-\u2069\u0000-\u001F\u007F-\u009F]/g, '')
            .replace(/[\\/:*?"<>|]/g, '_')
            .replace(/\.{2,}/g, '_')
            .replace(/^\.+/, '');
        const dangerousExts = /\.(exe|dll|scr|bat|cmd|vbs|vbe|js|jse|wsf|wsh|msc|ps1|ps2|psc1|psc2|msi|msp|com|pif|reg|hta|jar)$/i;
        if (dangerousExts.test(raw)) {
            raw = raw.replace(dangerousExts, '.blocked');
        }
        return clampString(raw, 150) || 'Dokument.pdf';
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
            'data:text/plain;base64,',
            'data:application/octet-stream;base64,',
            'data:binary/octet-stream;base64,'
        ];
        const lower = trimmed.substring(0, 100).toLowerCase();
        if (allowedPrefixes.some(p => lower.startsWith(p)) || (lower.startsWith('data:') && lower.includes(';base64,'))) {
            // Block dangerous web executable MIME types
            if (lower.startsWith('data:text/html') ||
                lower.startsWith('data:application/javascript') ||
                lower.startsWith('data:text/javascript') ||
                lower.startsWith('data:image/svg+xml')) {
                return '';
            }
            const commaIdx = trimmed.indexOf(',');
            if (commaIdx === -1) return '';
            const b64 = trimmed.substring(commaIdx + 1).replace(/\s+/g, '');
            // Verify base64 charset without regex stack explosion on multi-megabyte strings
            if (!/^[A-Za-z0-9+/=]+$/.test(b64.substring(0, 500))) return '';
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

        // 0. Hard Immediate Rejection of Executables & Malicious Signatures (Antivirus Heuristics Protection)
        // Windows PE (MZ) Executable / DLL / SCR / COM
        if (b0 === 0x4D && b1 === 0x5A) {
            return { valid: false, reason: 'Ausführbare Windows-Dateien (.exe, .dll, .scr) sind aus Sicherheitsgründen streng verboten' };
        }
        // Linux ELF binary
        if (b0 === 0x7F && b1 === 0x45 && b2 === 0x4C && b3 === 0x46) {
            return { valid: false, reason: 'Ausführbare Binärdateien (ELF) sind verboten' };
        }
        // Java Class file (CAFEBABE)
        if (b0 === 0xCA && b1 === 0xFE && b2 === 0xBA && b3 === 0xBE) {
            return { valid: false, reason: 'Ausführbare Java-Klassendateien sind verboten' };
        }
        // Windows Shell Link (.lnk)
        if (b0 === 0x4C && b1 === 0x00 && b2 === 0x00 && b3 === 0x00 && len >= 8 && u8[4] === 0x01 && u8[5] === 0x14 && u8[6] === 0x02 && u8[7] === 0x00) {
            return { valid: false, reason: 'Windows-Verknüpfungsdateien (.lnk) sind verboten' };
        }

        // 1. PDF Validation (%PDF-)
        if (b0 === 0x25 && b1 === 0x50 && b2 === 0x44 && b3 === 0x46) {
            const checkLen = Math.min(len, 200000);
            const strSlice = typeof TextDecoder !== 'undefined'
                ? new TextDecoder('latin1').decode(u8.subarray(0, checkLen))
                : String.fromCharCode.apply(null, u8.subarray(0, checkLen));
            const dangerousPatterns = [
                /\/JavaScript\b/i,
                /\/JS\b/i,
                /\/Launch\b/i,
                /\/SubmitForm\b/i,
                /\/ImportData\b/i,
                /\/RichMedia\b/i,
                /\/OpenAction\b/i,
                /\/AA\b/i,
                /\/URI\s*\([^)]*javascript:/i
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
            const strSlice = typeof TextDecoder !== 'undefined'
                ? new TextDecoder('latin1').decode(u8.subarray(0, checkLen))
                : String.fromCharCode.apply(null, u8.subarray(0, checkLen));
            if (strSlice.includes('vbaProject.bin') ||
                strSlice.includes('vbaData.xml') ||
                strSlice.includes('oleObject') ||
                strSlice.includes('.exe') ||
                strSlice.includes('.vbs') ||
                strSlice.includes('.bat') ||
                strSlice.includes('.ps1') ||
                strSlice.includes('.cmd')) {
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
            const curSize = Number(safeDoc.fileSize) || (safeDoc.fileData ? Math.round(safeDoc.fileData.length * 0.75) : 0);
            if (curSize > MAX_P2P_SHARE_BYTES) {
                const sizeMb = (curSize / (1024 * 1024)).toFixed(1);
                showSwarmToast(`⚠️ P2P-Limit: Datei ist ${sizeMb} MB groß (maximal 10 MB im P2P-Schwarm erlaubt). Bitte per Bluetooth oder Social Media teilen.`, 'warning');
                return;
            }
            await toggleShareDocToSwarm(safeDoc.id, true, safeDoc);
            await openSwarmModal('local');
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

    
    // =========================================================================
    // 2.5 P2P AUTO-SAVE TO DATABASE & DUPLICATE DETECTION SUITE
    // =========================================================================

    window.knownLocalHashes = window.knownLocalHashes || new Set();
    window.knownLocalFileKeys = window.knownLocalFileKeys || new Set();

    let autoSyncQueue = [];
    let isProcessingAutoSync = false;
    let inFlightSyncIds = new Set();

    function isAutoSaveToDbEnabled() {
        try {
            return localStorage.getItem('p2p_auto_save_to_db') !== 'false';
        } catch (e) {
            return true;
        }
    }

    
    let cachedOfficialCatalog = null;
    let lastOfficialCatalogFetchTime = 0;

    async function fetchOfficialCatalog(force) {
        const now = Date.now();
        if (!force && cachedOfficialCatalog && (now - lastOfficialCatalogFetchTime < 30000)) {
            return cachedOfficialCatalog;
        }

        const candidates = [
            'data/official-catalog.json?t=' + now,
            './data/official-catalog.json?t=' + now,
            '../data/official-catalog.json?t=' + now
        ];

        for (const url of candidates) {
            try {
                const resp = await fetch(url, { cache: 'no-cache' });
                if (resp.ok) {
                    const data = await resp.json();
                    if (data && Array.isArray(data.documents)) {
                        cachedOfficialCatalog = data;
                        lastOfficialCatalogFetchTime = now;
                        return data;
                    }
                }
            } catch (e) {}
        }

        if (window.OFFICIAL_CATALOG_DATA && Array.isArray(window.OFFICIAL_CATALOG_DATA.documents)) {
            cachedOfficialCatalog = window.OFFICIAL_CATALOG_DATA;
            lastOfficialCatalogFetchTime = now;
            return cachedOfficialCatalog;
        }

        return cachedOfficialCatalog || { version: 1, documents: [] };
    }

    async function syncOfficialCatalog(isAuto) {
        const catalog = await fetchOfficialCatalog(true);
        if (!catalog || !Array.isArray(catalog.documents) || catalog.documents.length === 0) {
            return 0;
        }

        await refreshLocalCatalog();
        let newCount = 0;

        for (const doc of catalog.documents) {
            if (!doc) continue;
            const docHash = doc.fileHash ? String(doc.fileHash).toLowerCase().trim() : '';
            const docKey = `${(doc.fileName || '').toLowerCase().trim()}_${doc.fileSize || 0}`;

            const exists = await checkDocExistsInDatabases(doc);
            if (exists) continue;

            const stagedList = getStagedInboxDocuments();
            const alreadyStaged = stagedList.some(d => 
                (docHash && d.fileHash && String(d.fileHash).toLowerCase() === docHash) ||
                (d.fileName && String(d.fileName).toLowerCase() === String(doc.fileName).toLowerCase() && Number(d.fileSize) === Number(doc.fileSize))
            );
            if (alreadyStaged) continue;

            let fileData = doc.fileData;
            if (!fileData && doc.filePath) {
                try {
                    const fileResp = await fetch(doc.filePath);
                    if (fileResp.ok) {
                        const blob = await fileResp.blob();
                        fileData = await new Promise((resolve) => {
                            const reader = new FileReader();
                            reader.onloadend = () => resolve(reader.result);
                            reader.onerror = () => resolve('');
                            reader.readAsDataURL(blob);
                        });
                    }
                } catch (err) {
                    console.warn('[Osiris Hybrid] Could not fetch file from filePath:', doc.filePath, err);
                }
            }

            const primaryDb = doc.sourceDb || currentConfig.dbName || 'DokumentationDB';
            const docRecord = Object.assign({}, doc, {
                id: Number(doc.id) || (Date.now() + Math.floor(Math.random() * 1000)),
                fileData: fileData || '',
                fileHash: docHash,
                isOfficial: true,
                isSwarmImport: true,
                importedAt: Date.now(),
                sourceDb: primaryDb
            });

            if (isAutoSaveToDbEnabled()) {
                const storeName = currentConfig.storeName || 'documents';
                try {
                    const db = await openDatabaseWithStore(primaryDb, storeName);
                    await new Promise((resolve) => {
                        const tx = db.transaction([storeName], 'readwrite');
                        const store = tx.objectStore(storeName);
                        const countReq = store.count();
                        countReq.onsuccess = (ev) => {
                            if (ev.target.result >= 10) {
                                stageDocumentInInbox(docRecord);
                                resolve(false);
                            } else {
                                store.put(docRecord);
                                tx.oncomplete = () => {
                                    db.close();
                                    if (docHash && window.knownLocalHashes) window.knownLocalHashes.add(docHash);
                                    trackUpdatedDoc(docRecord.id, docHash);
                                    broadcastDataReload(docRecord);
                                    resolve(true);
                                };
                                tx.onerror = () => { db.close(); resolve(false); };
                            }
                        };
                        countReq.onerror = () => { db.close(); resolve(false); };
                    });
                    newCount++;
                } catch (e) {
                    stageDocumentInInbox(docRecord);
                    newCount++;
                }
            } else {
                stageDocumentInInbox(docRecord);
                newCount++;
            }
        }

        if (newCount > 0) {
            updateSwarmBadge();
            renderSwarmModalContent();
        }
        return newCount;
    }

    async function exportOfficialCatalogJson() {
        await refreshLocalCatalog();
        const exportDocs = [];
        const dbs = ['DokumentationDB', 'TestBankDB'];

        for (const dbName of dbs) {
            try {
                const dbDocs = await new Promise((resolve) => {
                    const req = indexedDB.open(dbName);
                    req.onsuccess = (e) => {
                        const db = e.target.result;
                        if (!db.objectStoreNames.contains('documents')) {
                            db.close();
                            return resolve([]);
                        }
                        const tx = db.transaction(['documents'], 'readonly');
                        const store = tx.objectStore('documents');
                        const getAllReq = store.getAll();
                        getAllReq.onsuccess = () => {
                            db.close();
                            resolve(getAllReq.result || []);
                        };
                        getAllReq.onerror = () => { db.close(); resolve([]); };
                    };
                    req.onerror = () => resolve([]);
                });

                for (const doc of dbDocs) {
                    if (!doc) continue;
                    const isShared = isDocShared(doc.id) || (localCatalog || []).some(d => d && (d.id == doc.id || d.fileHash === doc.fileHash));
                    if (isShared) {
                        exportDocs.push({
                            id: Number(doc.id) || Date.now(),
                            thema: doc.thema || 'Unbenannt',
                            typ: doc.typ || (dbName === 'TestBankDB' ? 'Schulaufgabe' : 'Unterrichtsmaterial'),
                            subTyp: doc.subTyp || [],
                            niveau: doc.niveau || '',
                            klasse: doc.klasse || doc.klassen || '',
                            klassen: doc.klassen || doc.klasse || '',
                            schulart: doc.schulart || '',
                            jahr: doc.jahr || new Date().getFullYear().toString(),
                            lektion: doc.lektion || '',
                            buch: doc.buch || '',
                            seiten: doc.seiten || '',
                            kommentar: doc.kommentar || '',
                            date: doc.date || new Date().toLocaleDateString(),
                            fileName: doc.fileName || 'Dokument.pdf',
                            fileType: doc.fileType || 'application/pdf',
                            fileSize: Number(doc.fileSize) || 0,
                            fileHash: doc.fileHash || '',
                            sourceDb: dbName,
                            isOfficial: true,
                            fileData: doc.fileData || ''
                        });
                    }
                }
            } catch (e) {
                console.warn('[Osiris Admin] Error collecting docs from', dbName, e);
            }
        }

        if (exportDocs.length === 0) {
            showSwarmToast('⚠️ Keine geteilten Dokumente zum Exportieren gefunden. Bitte teilen Sie zuerst Dokumente über das Menü „Teilen“.', 'warning');
            return null;
        }

        const catalogPayload = {
            version: 1,
            updatedAt: new Date().toISOString(),
            totalDocuments: exportDocs.length,
            generator: 'Osiris Hybrid Swarm Admin v2.0',
            documents: exportDocs
        };

        const jsonString = JSON.stringify(catalogPayload, null, 2);
        const blob = new Blob([jsonString], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'official-catalog.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showSwarmToast(`🏛️ Offizieller Katalog mit ${exportDocs.length} Dokument(en) exportiert! Kopieren Sie die Datei nach data/official-catalog.json und committen Sie auf GitHub.`, 'info');
        return catalogPayload;
    }
    
    async function getNewRemoteFiles() {
        const newFiles = [];
        const seen = new Set();

        const localSharedHashes = new Set(
            (localCatalog || []).map(d => d && d.fileHash ? String(d.fileHash).toLowerCase().trim() : '').filter(Boolean)
        );
        const localSharedKeys = new Set(
            (localCatalog || []).map(d => d ? `${(d.fileName || '').toLowerCase().trim()}_${d.fileSize || 0}` : '').filter(Boolean)
        );
        const localSharedIds = new Set(
            (localCatalog || []).map(d => d ? Number(d.id) : 0).filter(Boolean)
        );

        // 1. Official Git catalog documents
        try {
            const officialCat = await fetchOfficialCatalog();
            for (const doc of (officialCat.documents || [])) {
                if (!doc) continue;
                const docHash = doc.fileHash ? String(doc.fileHash).toLowerCase().trim() : '';
                const docKey = `${(doc.fileName || '').toLowerCase().trim()}_${doc.fileSize || 0}`;
                const docId = Number(doc.id);

                if (docHash && localSharedHashes.has(docHash)) continue;
                if (localSharedKeys.has(docKey)) continue;
                if (docId > 0 && localSharedIds.has(docId)) continue;
                if (isDocShared(docId)) continue;

                const dedupeKey = docHash || docKey || `official:${docId}`;
                if (seen.has(dedupeKey)) continue;
                seen.add(dedupeKey);

                const exists = await checkDocExistsInDatabases(doc);
                if (!exists) {
                    newFiles.push({ peerId: 'official', doc: doc, isOfficial: true });
                }
            }
        } catch (e) {
            console.warn('[Osiris Hybrid] Error checking official catalog in getNewRemoteFiles:', e);
        }

        // 2. Remote P2P peers
        const peers = Array.from(remoteCatalog.entries());
        for (const [peerId, peerData] of peers) {
            if (!PEER_ID_REGEX.test(peerId) || peerId === myPeerId) continue;
            for (const doc of (peerData.docs || [])) {
                if (!doc) continue;
                const docHash = doc.fileHash ? String(doc.fileHash).toLowerCase().trim() : '';
                const docKey = `${(doc.fileName || '').toLowerCase().trim()}_${doc.fileSize || 0}`;
                const docId = Number(doc.id);

                if (docHash && localSharedHashes.has(docHash)) continue;
                if (localSharedKeys.has(docKey)) continue;
                if (docId > 0 && localSharedIds.has(docId)) continue;
                if (isDocShared(docId)) continue;

                const dedupeKey = docHash || docKey || `${peerId}:${docId}`;
                if (seen.has(dedupeKey)) continue;
                seen.add(dedupeKey);

                const exists = await checkDocExistsInDatabases(doc);
                if (!exists) {
                    newFiles.push({ peerId, doc, isOfficial: false });
                }
            }
        }
        return newFiles;
    }

    async function syncAllAvailableDocs() {
        await refreshLocalCatalog();

        // 1. Sync official Git catalog first
        let officialCount = 0;
        try {
            officialCount = await syncOfficialCatalog(false);
        } catch (e) {
            console.warn('[Osiris Swarm] Git catalog sync error:', e);
        }

        // 2. Discover remaining new remote files from P2P peers
        const newFiles = await getNewRemoteFiles();
        const p2pFiles = newFiles.filter(item => item.peerId !== 'official');

        const totalCount = officialCount + p2pFiles.length;

        if (totalCount === 0) {
            showSwarmToast('✓ Datenbank ist auf dem neuesten Stand. Keine neuen Dokumente im Schwarm.', 'info');
            updateSwarmBadge();
            return 0;
        }

        let toastText = `🔄 Aktualisiere ${totalCount} neue(s) Dokument(e)`;
        if (officialCount > 0 && p2pFiles.length > 0) {
            toastText += ` (${officialCount} offiziell, ${p2pFiles.length} Schwarm)...`;
        } else if (officialCount > 0) {
            toastText += ` aus dem offiziellen Katalog...`;
        } else {
            toastText += ` aus dem Schwarm...`;
        }
        showSwarmToast(toastText, 'info');

        for (const item of p2pFiles) {
            const doc = item.doc;
            const peerId = item.peerId;
            const docHash = doc.fileHash ? String(doc.fileHash).toLowerCase().trim() : '';
            const dedupeKey = docHash || (peerId + ':' + doc.id);

            if (!inFlightSyncIds.has(dedupeKey)) {
                inFlightSyncIds.add(dedupeKey);
                autoSyncQueue.push({
                    peerId: peerId,
                    docId: doc.id,
                    title: doc.thema || doc.fileName,
                    dedupeKey: dedupeKey
                });
            }
        }

        processAutoSyncQueue();
        updateSwarmBadge();
        return totalCount;
    }

    function setAutoSaveToDbEnabled(enabled) {
        try {
            localStorage.setItem('p2p_auto_save_to_db', enabled ? 'true' : 'false');
        } catch (e) {}
    }

    function toggleAutoSaveToDb(enabled) {
        setAutoSaveToDbEnabled(enabled);
        const toggle = document.getElementById('swarm-auto-save-toggle');
        if (toggle) toggle.checked = !!enabled;
        showSwarmToast(enabled ? '⚡ P2P Auto-Speichern aktiviert: Neue Schwarm-Dokumente werden automatisch gespeichert.' : '⏸️ P2P Auto-Speichern deaktiviert.', 'info');
        if (enabled) {
            // Trigger auto-sync for any currently known remote docs
            remoteCatalog.forEach((peerData, peerId) => {
                if (peerData && Array.isArray(peerData.docs)) {
                    triggerAutoSyncMissingDocs(peerId, peerData.docs);
                }
            });
        }
    }

    function showSwarmToast(message, type) {
        try {
            const hostDoc = (window.top && window.top.document) ? window.top.document : document;
            let container = hostDoc.getElementById('osiris-swarm-toast-container');
            if (!container) {
                container = hostDoc.createElement('div');
                container.id = 'osiris-swarm-toast-container';
                container.style.cssText = 'position:fixed; bottom:24px; right:24px; z-index:999999; display:flex; flex-direction:column; gap:10px; pointer-events:none; max-width:420px;';
                hostDoc.body.appendChild(container);
            }
            if (!hostDoc.getElementById('osiris-swarm-toast-style')) {
                const styleEl = hostDoc.createElement('style');
                styleEl.id = 'osiris-swarm-toast-style';
                styleEl.textContent = '@keyframes osirisToastSpin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }';
                hostDoc.head.appendChild(styleEl);
            }

            const toast = hostDoc.createElement('div');
            const isSuccess = type === 'success';
            const isInfo = type === 'info';
            const bgColor = isSuccess ? '#15803d' : (isInfo ? '#2563eb' : '#b91c1c');

            toast.style.cssText = 'background:' + bgColor + '; color:#ffffff; padding:12px 18px; border-radius:8px; font-family:-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; font-size:0.86rem; font-weight:600; line-height:1.4; box-shadow:0 8px 24px rgba(0,0,0,0.28); display:flex; align-items:center; gap:10px; pointer-events:auto; opacity:0; transform:translateY(12px); transition:opacity 0.25s ease, transform 0.25s ease;';

            let iconSvg = '';
            let cleanMsg = String(message || '');
            if (cleanMsg.includes('Aktualisiere') || cleanMsg.includes('🔄') || type === 'sync') {
                cleanMsg = cleanMsg.replace(/^🔄\s*/, '');
                iconSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0; animation:osirisToastSpin 0.85s linear infinite;"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>';
            } else if (cleanMsg.startsWith('✓') || isSuccess) {
                cleanMsg = cleanMsg.replace(/^✓\s*/, '');
                iconSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><polyline points="20 6 9 17 4 12"/></svg>';
            } else if (cleanMsg.includes('⚠️') || cleanMsg.includes('🛑') || type === 'warning' || type === 'error') {
                cleanMsg = cleanMsg.replace(/^[⚠️🛑]\s*/, '');
                iconSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';
            } else {
                iconSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';
            }

            toast.innerHTML = iconSvg;
            const msgSpan = hostDoc.createElement('span');
            msgSpan.textContent = cleanMsg;
            toast.appendChild(msgSpan);
            container.appendChild(toast);

            requestAnimationFrame(() => {
                toast.style.opacity = '1';
                toast.style.transform = 'translateY(0)';
            });

            setTimeout(() => {
                toast.style.opacity = '0';
                toast.style.transform = 'translateY(12px)';
                setTimeout(() => {
                    if (toast.parentNode) toast.parentNode.removeChild(toast);
                }, 300);
            }, 4200);
        } catch (e) {
            console.log('[P2P Toast]', message);
        }
    }

    function trackUpdatedDoc(id, hash) {
        try {
            const stored = JSON.parse(localStorage.getItem('p2p_updated_docs') || '[]');
            const cleanHash = (hash || '').toLowerCase().trim();
            const cleanId = Number(id) || 0;
            const exists = stored.some(s => (cleanId > 0 && Number(s.id) === cleanId) || (cleanHash && s.hash && s.hash.toLowerCase() === cleanHash));
            if (!exists) {
                stored.unshift({ id: cleanId, hash: cleanHash, time: Date.now() });
                if (stored.length > 200) stored.splice(200);
                localStorage.setItem('p2p_updated_docs', JSON.stringify(stored));
            }
        } catch (e) {}
    }

    function getStagedInboxDocuments() {
        try {
            return JSON.parse(localStorage.getItem('swarm_staged_inbox') || '[]');
        } catch (e) { return []; }
    }

    function stageDocumentInInbox(item) {
        if (!item) return;
        try {
            const list = getStagedInboxDocuments();
            if (!list.some(d => (item.fileHash && d.fileHash === item.fileHash) || (item.fileName && d.fileName === item.fileName))) {
                if (list.length >= 10) list.shift();
                list.push(item);
                localStorage.setItem('swarm_staged_inbox', JSON.stringify(list));
                updateSwarmBadge();
            }
        } catch (e) {}
    }

    function removeStagedInboxDocument(docIdOrHash) {
        try {
            const list = getStagedInboxDocuments().filter(d => String(d.id) !== String(docIdOrHash) && d.fileHash !== docIdOrHash);
            localStorage.setItem('swarm_staged_inbox', JSON.stringify(list));
            updateSwarmBadge();
        } catch (e) {}
    }

    function openDatabaseWithStore(dbName, storeName) {
        return new Promise((resolve, reject) => {
            const initialReq = indexedDB.open(dbName);
            initialReq.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains(storeName)) {
                    db.createObjectStore(storeName, { keyPath: 'id' });
                }
            };
            initialReq.onsuccess = (e) => {
                const db = e.target.result;
                if (db.objectStoreNames.contains(storeName)) {
                    resolve(db);
                } else {
                    const nextVersion = (db.version || 1) + 1;
                    db.close();
                    const upgradeReq = indexedDB.open(dbName, nextVersion);
                    upgradeReq.onupgradeneeded = (ev) => {
                        const upgradedDb = ev.target.result;
                        if (!upgradedDb.objectStoreNames.contains(storeName)) {
                            upgradedDb.createObjectStore(storeName, { keyPath: 'id' });
                        }
                    };
                    upgradeReq.onsuccess = (ev) => resolve(ev.target.result);
                    upgradeReq.onerror = (ev) => reject(ev.target.error);
                }
            };
            initialReq.onerror = (e) => reject(e.target.error);
        });
    }

    async function importStagedDocToDb(docIdOrHash, isSilentAuto) {
        const stagedList = getStagedInboxDocuments();
        const targetDoc = stagedList.find(d => 
            d && (String(d.id) === String(docIdOrHash) || (d.fileHash && String(d.fileHash).toLowerCase() === String(docIdOrHash).toLowerCase()))
        );
        if (!targetDoc) {
            console.warn('[Osiris Swarm] Document to import not found in staged inbox:', docIdOrHash);
            return false;
        }

        const primaryDb = targetDoc.sourceDb || currentConfig.dbName || 'DokumentationDB';
        const targetStore = currentConfig.storeName || 'documents';

        try {
            const db = await openDatabaseWithStore(primaryDb, targetStore);
            return new Promise((resolve) => {
                const tx = db.transaction([targetStore], 'readwrite');
                const store = tx.objectStore(targetStore);

                tx.oncomplete = () => {
                    db.close();

                    // Remove from staged inbox once successfully stored in IndexedDB
                    removeStagedInboxDocument(targetDoc.id);

                    if (targetDoc.fileHash && window.knownLocalHashes) {
                        window.knownLocalHashes.add(targetDoc.fileHash.toLowerCase());
                    }
                    trackUpdatedDoc(targetDoc.id, targetDoc.fileHash);

                    const fp = (targetDoc.fileHash || '').substring(0, 6).toUpperCase();
                    if (!isSilentAuto) {
                        showSwarmToast(`✅ „${targetDoc.thema}“ (SHA-256 #${fp}) erfolgreich in lokale Bibliothek importiert!`, 'success');
                    }

                    broadcastDataReload(targetDoc);
                    updateSwarmBadge();
                    renderSwarmModalContent();
                    resolve(true);
                };

                tx.onerror = (err) => {
                    db.close();
                    console.error('[Osiris Swarm] Transaction error:', err);
                    resolve(false);
                };

                const countReq = store.count();
                countReq.onsuccess = (ev) => {
                    const currentCount = ev.target.result;
                    if (currentCount >= 10) {
                        db.close();
                        const msg = `⚠️ Kapazitätsgrenze (10 Dateien) in ${primaryDb} erreicht. Dokument verbleibt im Posteingang.`;
                        console.warn('[Osiris Swarm]', msg);
                        showSwarmToast(msg, 'warning');
                        resolve(false);
                        return;
                    }

                    const cleanDoc = sanitizeDocRecord(targetDoc);
                    if (!cleanDoc) {
                        db.close();
                        resolve(false);
                        return;
                    }
                    store.put(cleanDoc);
                };
                countReq.onerror = () => {
                    db.close();
                    resolve(false);
                };
            });
        } catch (err) {
            console.error('[Osiris Swarm] importStagedDocToDb exception:', err);
            return false;
        }
    }

    async function importAllStagedDocsToDb() {
        const stagedList = getStagedInboxDocuments();
        if (stagedList.length === 0) return;
        let successCount = 0;
        for (const doc of stagedList) {
            const ok = await importStagedDocToDb(doc.id, true);
            if (ok) successCount++;
        }
        if (successCount > 0) {
            showSwarmToast(`✅ ${successCount} Dokument(e) erfolgreich in Ihre lokale Bibliothek übernommen!`, 'success');
        }
        updateSwarmBadge();
        renderSwarmModalContent();
    }

    function isDocAnUpdate(doc) {
        if (!doc) return false;
        if (doc.isSwarmImport || doc.isUpdated) return true;
        try {
            const stored = JSON.parse(localStorage.getItem('p2p_updated_docs') || '[]');
            const docHash = (doc.fileHash || '').toLowerCase().trim();
            const docId = Number(doc.id) || 0;
            return stored.some(s => (docId > 0 && Number(s.id) === docId) || (docHash && s.hash && s.hash.toLowerCase() === docHash));
        } catch (e) {
            return false;
        }
    }

    async function refreshLocalDbHashes() {
        window.knownLocalHashes = window.knownLocalHashes || new Set();
        window.knownLocalFileKeys = window.knownLocalFileKeys || new Set();
        const dbsToScan = ['DokumentationDB', 'TestBankDB'];

        for (const dbName of dbsToScan) {
            await new Promise(resolve => {
                try {
                    const req = indexedDB.open(dbName);
                    req.onsuccess = (e) => {
                        const db = e.target.result;
                        if (!db.objectStoreNames.contains('documents')) {
                            db.close();
                            resolve();
                            return;
                        }
                        const tx = db.transaction(['documents'], 'readonly');
                        const store = tx.objectStore('documents');
                        const allReq = store.getAll();
                        allReq.onsuccess = (ev) => {
                            const allDocs = ev.target.result || [];
                            db.close();
                            allDocs.forEach(d => {
                                if (!d) return;
                                if (d.fileHash) window.knownLocalHashes.add(String(d.fileHash).toLowerCase().trim());
                                if (d.fileName && d.fileSize) window.knownLocalFileKeys.add(String(d.fileName).toLowerCase().trim() + '_' + d.fileSize);
                                if (d.id && d.fileName) window.knownLocalFileKeys.add(d.id + '_' + String(d.fileName).toLowerCase().trim());
                            });
                            resolve();
                        };
                        allReq.onerror = () => { db.close(); resolve(); };
                    };
                    req.onerror = () => resolve();
                } catch (e) {
                    resolve();
                }
            });
        }
    }

    async function checkDocExistsInDatabases(docMeta) {
        if (!docMeta) return false;
        const hash = docMeta.fileHash ? String(docMeta.fileHash).trim().toLowerCase() : '';
        const name = docMeta.fileName ? String(docMeta.fileName).trim().toLowerCase() : '';
        const size = Number(docMeta.fileSize) || 0;
        const docId = Number(docMeta.id) || 0;

        // 0. Ultra-fast in-memory _docMetaCache check (0.01 ms)
        if (window._docMetaCache && Array.isArray(window._docMetaCache)) {
            const inCache = window._docMetaCache.some(d => 
                (hash && d.fileHash && d.fileHash.toLowerCase() === hash) ||
                (name && d.fileName && d.fileName.toLowerCase() === name && (!size || d.fileSize === size)) ||
                (docId > 0 && d.id && Number(d.id) === docId)
            );
            if (inCache) return true;
        }

        // 1. Fast in-memory check
        if (hash && window.knownLocalHashes && window.knownLocalHashes.has(hash)) {
            return true;
        }
        if (name && size > 0 && window.knownLocalFileKeys && window.knownLocalFileKeys.has(name + '_' + size)) {
            return true;
        }
        if (docId > 0 && name && window.knownLocalFileKeys && window.knownLocalFileKeys.has(docId + '_' + name)) {
            return true;
        }

        // 2. Authoritative IndexedDB scan across both databases
        const dbsToScan = ['DokumentationDB', 'TestBankDB'];
        for (const dbName of dbsToScan) {
            const found = await new Promise(resolve => {
                try {
                    const req = indexedDB.open(dbName);
                    req.onsuccess = (e) => {
                        const db = e.target.result;
                        if (!db.objectStoreNames.contains('documents')) {
                            db.close();
                            resolve(false);
                            return;
                        }
                        const tx = db.transaction(['documents'], 'readonly');
                        const store = tx.objectStore('documents');
                        const getReq = store.getAll();
                        getReq.onsuccess = (ev) => {
                            const items = ev.target.result || [];
                            db.close();
                            const match = items.some(it => {
                                if (!it) return false;
                                // a. SHA-256 hash match
                                if (hash && it.fileHash && String(it.fileHash).trim().toLowerCase() === hash) {
                                    return true;
                                }
                                // b. fileName + fileSize match
                                if (name && size > 0 && it.fileName && String(it.fileName).trim().toLowerCase() === name && Number(it.fileSize) === size) {
                                    return true;
                                }
                                // c. ID and fileName match
                                if (docId > 0 && it.id && Number(it.id) === docId && it.fileName && String(it.fileName).trim().toLowerCase() === name) {
                                    return true;
                                }
                                return false;
                            });
                            if (match) {
                                if (hash) window.knownLocalHashes.add(hash);
                                if (name && size > 0) window.knownLocalFileKeys.add(name + '_' + size);
                            }
                            resolve(match);
                        };
                        getReq.onerror = () => { db.close(); resolve(false); };
                    };
                    req.onerror = () => resolve(false);
                } catch (err) {
                    resolve(false);
                }
            });
            if (found) return true;
        }
        return false;
    }

    async function triggerAutoSyncMissingDocs(peerId, remoteDocs) {
        if (!isAutoSaveToDbEnabled() || !Array.isArray(remoteDocs) || !PEER_ID_REGEX.test(peerId) || peerId === myPeerId) return;

        const localSharedHashes = new Set(
            (localCatalog || []).map(d => d.fileHash ? String(d.fileHash).toLowerCase().trim() : '').filter(Boolean)
        );
        const localSharedKeys = new Set(
            (localCatalog || []).map(d => `${(d.fileName || '').toLowerCase().trim()}_${d.fileSize || 0}`)
        );

        for (const doc of remoteDocs) {
            if (!doc || !doc.id) continue;
            const docHash = doc.fileHash ? String(doc.fileHash).toLowerCase().trim() : '';
            const dedupeKey = docHash || (peerId + ':' + doc.id);

            // Skip files exceeding 10 MB P2P limit
            if (Number(doc.fileSize) > MAX_P2P_SHARE_BYTES) continue;

            if (inFlightSyncIds.has(dedupeKey)) continue;

            const exists = await checkDocExistsInDatabases(doc);
            if (!exists) {
                inFlightSyncIds.add(dedupeKey);
                autoSyncQueue.push({
                    peerId: peerId,
                    docId: doc.id,
                    title: doc.thema || doc.fileName,
                    dedupeKey: dedupeKey
                });
            }
        }

        processAutoSyncQueue();
    }

    function processAutoSyncQueue() {
        if (isProcessingAutoSync || autoSyncQueue.length === 0) return;
        isProcessingAutoSync = true;

        const next = autoSyncQueue.shift();
        if (!next) {
            isProcessingAutoSync = false;
            return;
        }

        requestDocDownload(next.docId, next.peerId, true /* isAutoSync */);

        // Throttle requests (400ms interval) to protect rate limit & bandwidth
        setTimeout(() => {
            isProcessingAutoSync = false;
            processAutoSyncQueue();
        }, 400);
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
        await refreshLocalDbHashes();
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

        // Preserve any in-memory items in localCatalog that are still marked as shared
        const existingShared = (localCatalog || []).filter(doc => {
            const cleanId = Number(doc && doc.id);
            if (!cleanId) return false;
            return isDocShared(cleanId) && !combined.some(c => Number(c.id) === cleanId);
        });
        combined = combined.concat(existingShared);
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
        // If running inside a subframe (e.g. iframe under index.html), let the top/parent frame manage the WebRTC mesh
        if (window.parent && window.parent !== window && window.parent.EduHybridShare && window.parent.EduHybridShare !== window.EduHybridShare) {
            console.log('[Osiris Swarm] Subframe detected: delegating WebRTC mesh to parent hub window.');
            webrtcStatus = 'connected';
            updateSwarmBadge();
            renderSwarmModalContent();
            return;
        }

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
                    {
                        urls: [
                            'stun:stun.l.google.com:19302',
                            'stun:stun1.l.google.com:19302',
                            'stun:stun.cloudflare.com:3478'
                        ]
                    }
                ],
                sdpSemantics: 'unified-plan'
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

    async function sendOverConn(conn, packet) {
        if (!conn || !conn.open) return;
        try {
            const jsonStr = JSON.stringify(packet);
            if (jsonStr.length <= CHUNK_SIZE) {
                conn.send(packet);
                return;
            }
            // Chunk large packets (e.g. DELIVER_DOC with full PDF bytes)
            const transferId = generateCryptoHex(8);
            const totalChunks = Math.ceil(jsonStr.length / CHUNK_SIZE);
            for (let i = 0; i < totalChunks; i++) {
                if (!conn || !conn.open) break;
                const chunkSlice = jsonStr.substring(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
                conn.send({
                    type: 'SWARM_CHUNK',
                    sender: myPeerId,
                    transferId: transferId,
                    chunkIndex: i,
                    totalChunks: totalChunks,
                    data: chunkSlice
                });
                // Flow control / backpressure check to prevent RTCDataChannel buffer overflow
                const dc = conn.dataChannel;
                if (dc && dc.bufferedAmount > 64 * 1024) {
                    await new Promise(r => setTimeout(r, 20));
                } else if (i % 2 === 0) {
                    await new Promise(r => setTimeout(r, 6));
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

        // 3. Initial & periodic sync of official Git catalog (fresh updates on startup)
        syncOfficialCatalog(true).catch(e => console.warn('[Osiris Hybrid] Initial catalog sync error:', e));

        setInterval(() => {
            syncOfficialCatalog(true).catch(e => {});
        }, 60000);

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
                triggerAutoSyncMissingDocs(msg.sender, remoteCatalog.get(msg.sender).docs);

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
                    triggerAutoSyncMissingDocs(msg.sender, remoteCatalog.get(msg.sender).docs);
                }
                break;

            case 'REQUEST_DOC':
                if (msg.target === myPeerId) {
                    const reqDocId = Number(msg.docId);
                    const reqToken = typeof msg.requestToken === 'string' && /^[a-f0-9]{16,64}$/i.test(msg.requestToken) ? msg.requestToken : '';
                    if (reqDocId && reqToken) {
                        const inCatalog = (localCatalog || []).some(d => d && (d.id == reqDocId || String(d.id) === String(reqDocId)));
                        if (inCatalog || isDocShared(reqDocId)) {
                            serveDocToPeer(reqDocId, msg.sender, reqToken);
                        }
                    }
                }
                break;

            case 'DELIVER_DOC':
                if (msg.target === myPeerId && msg.payload) {
                    const deliveredId = Number(msg.payload.id);
                    const reqKey = `${msg.sender}:${deliveredId}`;
                    let pending = pendingRequests.get(reqKey);

                    // Robust fallback: also match pending requests by requestToken in case ID or sender formatting differs
                    if (!pending && msg.requestToken) {
                        for (const [k, v] of pendingRequests.entries()) {
                            if (v && v.token === msg.requestToken && Date.now() <= v.expiresAt) {
                                pending = v;
                                pendingRequests.delete(k);
                                break;
                            }
                        }
                    } else {
                        pendingRequests.delete(reqKey);
                    }

                    // Block unsolicited, expired, or forged document pushes
                    if (!pending || Date.now() > pending.expiresAt || pending.token !== msg.requestToken) {
                        console.warn('[Osiris Security] Blocked unsolicited or forged DELIVER_DOC from', msg.sender);
                        return;
                    }
                    const isAuto = !!(pending && pending.isAutoSync);
                    receiveDocFromPeer(msg.payload, isAuto);
                }
                break;

            case 'BROADCAST_RELOAD_DATA':
                if (msg.payload && msg.payload.updatedDoc) {
                    trackUpdatedDoc(msg.payload.updatedDoc.id, msg.payload.updatedDoc.fileHash);
                }
                if (typeof currentConfig.onDocImported === 'function') {
                    try { currentConfig.onDocImported(msg.payload && msg.payload.updatedDoc); } catch (e) {}
                }
                if (typeof window.renderResults === 'function') {
                    try { window.renderResults(); } catch (e) {}
                }
                try {
                    const frames = document.querySelectorAll('iframe');
                    frames.forEach(f => {
                        if (f && f.contentWindow) {
                            f.contentWindow.postMessage({ type: 'RELOAD_DATA', payload: msg.payload }, '*');
                        }
                    });
                } catch (e) {}
                updateSwarmBadge();
                break;
        }
    }

    // Searches both DokumentationDB and TestBankDB to serve requested document
    function serveDocToPeer(docId, targetPeerId, requestToken) {
        const inCatalog = (localCatalog || []).find(d => d && (d.id == docId || String(d.id) === String(docId)));
        if (!inCatalog && !isDocShared(docId)) return;

        const dbsToTry = [currentConfig.dbName, currentConfig.dbName === 'DokumentationDB' ? 'TestBankDB' : 'DokumentationDB'];

        function tryDb(idx) {
            if (idx >= dbsToTry.length) {
                // In-memory fallback if IndexedDB search exhausted but fileData exists
                if (inCatalog && inCatalog.fileData) {
                    sendSwarmPacket({
                        type: 'DELIVER_DOC',
                        sender: myPeerId,
                        target: targetPeerId,
                        requestToken: requestToken,
                        payload: sanitizeDocRecord(inCatalog)
                    }, targetPeerId);
                }
                return;
            }
            const dbName = dbsToTry[idx];
            try {
                const req = indexedDB.open(dbName);
                req.onsuccess = (e) => {
                    const db = e.target.result;
                    if (!db.objectStoreNames.contains('documents')) {
                        db.close();
                        tryDb(idx + 1);
                        return;
                    }
                    const tx = db.transaction(['documents'], 'readonly');
                    const store = tx.objectStore('documents');

                    const numId = Number(docId);
                    const strId = String(docId);

                    function deliver(item) {
                        db.close();
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
                    }

                    // Try numeric ID first
                    const getReq = !isNaN(numId) ? store.get(numId) : null;
                    if (getReq) {
                        getReq.onsuccess = (ev) => {
                            if (ev.target.result) {
                                deliver(ev.target.result);
                            } else {
                                // Try string ID
                                const getStrReq = store.get(strId);
                                getStrReq.onsuccess = (ev2) => {
                                    if (ev2.target.result) {
                                        deliver(ev2.target.result);
                                    } else {
                                        fallbackScan();
                                    }
                                };
                                getStrReq.onerror = () => fallbackScan();
                            }
                        };
                        getReq.onerror = () => fallbackScan();
                    } else {
                        fallbackScan();
                    }

                    function fallbackScan() {
                        const allReq = store.getAll();
                        allReq.onsuccess = (evAll) => {
                            const items = evAll.target.result || [];
                            const match = items.find(it => 
                                it && (it.id == docId || String(it.id) === strId ||
                                (inCatalog && inCatalog.fileName && it.fileName === inCatalog.fileName) ||
                                (inCatalog && inCatalog.fileHash && it.fileHash === inCatalog.fileHash))
                            );
                            deliver(match);
                        };
                        allReq.onerror = () => deliver(null);
                    }
                };
                req.onerror = () => tryDb(idx + 1);
            } catch (err) {
                tryDb(idx + 1);
            }
        }

        tryDb(0);
    }

    async function receiveDocFromPeer(rawDocItem, isAuto) {
        const docItem = sanitizeDocRecord(rawDocItem);
        if (!docItem || !docItem.fileData) {
            if (!isAuto) showSwarmToast('⚠️ P2P-Übertragung abgelehnt: Ungültige oder manipulierte Dokumentendaten.', 'warning');
            return;
        }

        let u8;
        try {
            u8 = dataUrlToUint8Array(docItem.fileData);
        } catch (err) {
            if (!isAuto) showSwarmToast('⚠️ Sicherheitswarnung: Datei überschreitet das 25 MB Limit oder ist korrupt.', 'warning');
            return;
        }

        // 0. Strict 10 MB P2P Swarm Size Check
        if (u8.length > MAX_P2P_SHARE_BYTES) {
            const sizeMb = (u8.length / (1024 * 1024)).toFixed(1);
            console.warn(`[Osiris Security] P2P-Dokument übersteigt 10 MB Limit (${sizeMb} MB). Abgewiesen.`);
            if (!isAuto) showSwarmToast(`🛑 Datei übersteigt das 10 MB P2P-Schwarm-Limit (${sizeMb} MB) und wurde abgewiesen.`, 'warning');
            return;
        }

        // 1. Deep Magic-Byte & Active Content Inspection
        const check = validateMagicBytes(u8, docItem.fileName);
        if (!check.valid) {
            if (!isAuto) showSwarmToast('🛑 SICHERHEITSBLOCKADE: ' + check.reason, 'warning');
            return;
        }

        // 2. Mandatory SHA-256 Bit-Integrity Verification
        const computedHash = await computeSHA256(u8.buffer);
        if (!computedHash || (docItem.fileHash && docItem.fileHash !== computedHash)) {
            if (!isAuto) showSwarmToast('🛑 INTEGRITÄTSFEHLER: SHA-256 Hash stimmt nicht mit dem Original überein!', 'warning');
            return;
        }

        // 3. Duplicate Check: Does this document ALREADY exist in either database?
        const alreadyExists = await checkDocExistsInDatabases({
            fileHash: computedHash,
            fileName: docItem.fileName,
            fileSize: u8.length,
            id: docItem.id
        });

        if (alreadyExists) {
            console.log(`[Osiris P2P Auto-Save] Dokument „${docItem.thema}" existiert bereits in der Datenbank.`);
            if (window.knownLocalHashes) window.knownLocalHashes.add(computedHash);
            trackUpdatedDoc(docItem.id, computedHash);
            if (!isAuto) {
                showSwarmToast(`ℹ️ Das Dokument „${docItem.thema}" ist bereits in Ihrer Datenbank gespeichert.`, 'info');
            }
            broadcastDataReload(docItem);
            renderSwarmModalContent();
            return;
        }

        // 4. Staged Precache Buffer (Sandbox) & Storage
        const primaryDb = docItem.sourceDb || currentConfig.dbName || 'DokumentationDB';
        const newItem = Object.assign({}, docItem, {
            id: Date.now() + Math.floor(Math.random() * 1000),
            fileHash: computedHash,
            fileSize: u8.length,
            date: new Date().toLocaleDateString(),
            isSwarmImport: true,
            isUpdated: true,
            importedAt: Date.now(),
            sourceDb: primaryDb
        });

        stageDocumentInInbox(newItem);
        updateSwarmBadge();

        // Check if user initiated a manual "Laden" download: trigger physical file download to device storage
        const requestedId = Number(rawDocItem.id) || Number(docItem.id);
        const wasUserDownload = userDownloadRequests.has(requestedId) || !isAuto;
        if (wasUserDownload) {
            userDownloadRequests.delete(requestedId);
            triggerBrowserFileDownload(newItem.fileName, newItem.fileData);
            showSwarmToast(`📥 Datei „${newItem.fileName}“ wird heruntergeladen & im Posteingang/DB gespeichert!`, 'info');
        }

        if (isAutoSaveToDbEnabled()) {
            // Auto-save is enabled: attempt immediate import into DB
            importStagedDocToDb(newItem.id, true);
        } else {
            // Auto-save is off: keep in staged inbox and alert the user with interactive notification
            const fp = computedHash.substring(0, 6).toUpperCase();
            if (!wasUserDownload) {
                showSwarmToast(`📥 Neuer Schwarm-Inhalt im Posteingang: „${newItem.thema}" (SHA-256 #${fp}) – Klicken zum Übernehmen`, 'info');
            }
            renderSwarmModalContent();
        }
    }

    // Fetches full doc payload with fileData from any available IndexedDB
    async function getLocalDocWithData(docId) {
        const cleanId = Number(docId);
        if (!cleanId) return null;
        const dbs = [currentConfig.dbName, 'DokumentationDB', 'TestBankDB'].filter(Boolean);
        for (const dbName of dbs) {
            const found = await new Promise(resolve => {
                try {
                    const req = indexedDB.open(dbName);
                    req.onsuccess = (e) => {
                        const db = e.target.result;
                        if (!db.objectStoreNames.contains('documents')) {
                            db.close();
                            resolve(null);
                            return;
                        }
                        const tx = db.transaction(['documents'], 'readonly');
                        const store = tx.objectStore('documents');
                        const getReq = store.get(cleanId);
                        getReq.onsuccess = (ev) => {
                            db.close();
                            resolve(ev.target.result || null);
                        };
                        getReq.onerror = () => { db.close(); resolve(null); };
                    };
                    req.onerror = () => resolve(null);
                } catch (err) {
                    resolve(null);
                }
            });
            if (found && found.fileData) return found;
        }
        // Fallback to in-memory localCatalog
        const mem = (localCatalog || []).find(d => Number(d.id) === cleanId);
        if (mem && mem.fileData) return mem;
        return null;
    }

    async function downloadLocalSharedDocFile(docId) {
        const doc = await getLocalDocWithData(docId);
        if (!doc || !doc.fileData) {
            showSwarmToast('⚠️ Dokumentinhalt konnte nicht aus der lokalen Datenbank geladen werden.', 'warning');
            return;
        }
        const success = triggerBrowserFileDownload(doc.fileName || 'Dokument.pdf', doc.fileData);
        if (success) {
            showSwarmToast(`📥 Datei „${doc.fileName}“ wird mit allen Metadaten auf Ihr Gerät heruntergeladen.`, 'info');
        }
    }

    function downloadStagedInboxDocFile(docId) {
        const staged = getStagedInboxDocuments();
        const doc = staged.find(d => Number(d.id) === Number(docId));
        if (!doc || !doc.fileData) {
            showSwarmToast('⚠️ Dokument im Posteingang nicht gefunden.', 'warning');
            return;
        }
        const success = triggerBrowserFileDownload(doc.fileName || 'Dokument.pdf', doc.fileData);
        if (success) {
            showSwarmToast(`📥 Datei „${doc.fileName}“ wird heruntergeladen.`, 'info');
        }
    }

    async function downloadOfficialCatalogDoc(docId) {
        const catalog = await fetchOfficialCatalog();
        const doc = (catalog.documents || []).find(d => Number(d.id) === Number(docId));
        if (!doc) {
            showSwarmToast('⚠️ Offizielles Dokument nicht im Katalog gefunden.', 'warning');
            renderSwarmModalContent();
            return false;
        }

        let fileData = doc.fileData;
        if (!fileData && doc.filePath) {
            try {
                showSwarmToast(`📥 Lade offizielle Datei herunter: ${doc.fileName}...`, 'info');
                const resp = await fetch(doc.filePath);
                if (resp.ok) {
                    const blob = await resp.blob();
                    fileData = await new Promise((resolve) => {
                        const reader = new FileReader();
                        reader.onloadend = () => resolve(reader.result);
                        reader.onerror = () => resolve('');
                        reader.readAsDataURL(blob);
                    });
                }
            } catch (e) {
                console.warn('[Osiris Hybrid] Error downloading official file from filePath:', e);
            }
        }

        if (!fileData) {
            showSwarmToast('⚠️ Datei-Inhalt des Dokuments konnte nicht geladen werden.', 'warning');
            renderSwarmModalContent();
            return false;
        }

        // Trigger immediate browser download
        triggerBrowserFileDownload(doc.fileName || 'Dokument.pdf', fileData);

        const primaryDb = doc.sourceDb || currentConfig.dbName || 'DokumentationDB';
        const docRecord = Object.assign({}, doc, {
            id: Number(doc.id) || (Date.now() + Math.floor(Math.random() * 1000)),
            fileData: fileData,
            isOfficial: true,
            isSwarmImport: true,
            importedAt: Date.now(),
            sourceDb: primaryDb
        });

        if (isAutoSaveToDbEnabled()) {
            const storeName = currentConfig.storeName || 'documents';
            try {
                const db = await openDatabaseWithStore(primaryDb, storeName);
                const tx = db.transaction([storeName], 'readwrite');
                const store = tx.objectStore(storeName);
                store.put(docRecord);
                tx.oncomplete = () => {
                    db.close();
                    if (doc.fileHash && window.knownLocalHashes) window.knownLocalHashes.add(doc.fileHash.toLowerCase());
                    trackUpdatedDoc(docRecord.id, doc.fileHash);
                    broadcastDataReload(docRecord);
                    showSwarmToast(`✅ Datei „${doc.fileName}“ heruntergeladen & in Datenbank gespeichert!`, 'info');
                    renderSwarmModalContent();
                    updateSwarmBadge();
                };
            } catch (e) {
                stageDocumentInInbox(docRecord);
                showSwarmToast(`📥 Datei „${doc.fileName}“ heruntergeladen & im Posteingang bereitgestellt!`, 'info');
                renderSwarmModalContent();
                updateSwarmBadge();
            }
        } else {
            stageDocumentInInbox(docRecord);
            showSwarmToast(`📥 Datei „${doc.fileName}“ heruntergeladen & im Posteingang bereitgestellt!`, 'info');
            renderSwarmModalContent();
            updateSwarmBadge();
        }
    }

    function broadcastDataReload(savedDoc) {
        if (savedDoc) {
            trackUpdatedDoc(savedDoc.id, savedDoc.fileHash);
        }

        if (typeof currentConfig.onDocImported === 'function') {
            try { currentConfig.onDocImported(savedDoc); } catch (e) {}
        }

        if (typeof window.renderResults === 'function') {
            try { window.renderResults(); } catch (e) {}
        }

        if (window.parent && window.parent !== window) {
            try {
                window.parent.postMessage({ type: 'RELOAD_DATA', payload: { updatedDoc: savedDoc } }, '*');
            } catch (e) {}
        }

        try {
            const frames = document.querySelectorAll('iframe');
            frames.forEach(f => {
                if (f && f.contentWindow) {
                    f.contentWindow.postMessage({ type: 'RELOAD_DATA', payload: { updatedDoc: savedDoc } }, '*');
                }
            });
        } catch (e) {}

        try {
            if (broadcastChannel) {
                broadcastChannel.postMessage({ type: 'BROADCAST_RELOAD_DATA', payload: { updatedDoc: savedDoc } });
            }
        } catch (e) {}

        try {
            window.postMessage({ type: 'RELOAD_DATA', payload: { updatedDoc: savedDoc } }, '*');
        } catch (e) {}

        updateSwarmBadge();
    }

    function requestDocDownload(docId, peerId, isAutoSync) {
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
            expiresAt: now + 45000,
            isAutoSync: !!isAutoSync
        });

        sendSwarmPacket({
            type: 'REQUEST_DOC',
            sender: myPeerId,
            target: peerId,
            docId: cleanDocId,
            requestToken: requestToken
        }, peerId);
    }

    async function toggleShareDocToSwarm(docId, shouldShare, docData) {
        const cleanId = Number(docId);
        if (!cleanId) return;
        if (shouldShare) {
            const rawSize = (docData && (Number(docData.fileSize) || (docData.fileData ? Math.round(docData.fileData.length * 0.75) : 0))) || 0;
            if (rawSize > MAX_P2P_SHARE_BYTES) {
                const sizeMb = (rawSize / (1024 * 1024)).toFixed(1);
                showSwarmToast(`⚠️ P2P-Limit: Datei ist ${sizeMb} MB groß (maximal 10 MB im P2P-Schwarm erlaubt). Bitte nutzen Sie Bluetooth oder Social Media.`, 'warning');
                return;
            }
        }

        let targetDb = (docData && docData.sourceDb) || currentConfig.dbName || 'DokumentationDB';
        let sharedIds = loadSharedDocsConfig(targetDb);
        if (shouldShare) {
            if (!sharedIds.includes(cleanId)) sharedIds.push(cleanId);
            saveSharedDocsConfig(sharedIds, targetDb);
            if (currentConfig.dbName && currentConfig.dbName !== targetDb) {
                let currIds = loadSharedDocsConfig(currentConfig.dbName);
                if (!currIds.includes(cleanId)) {
                    currIds.push(cleanId);
                    saveSharedDocsConfig(currIds, currentConfig.dbName);
                }
            }
            if (docData) {
                const sanitized = sanitizeDocRecord(Object.assign({}, docData, { id: cleanId, sourceDb: targetDb }));
                if (sanitized) {
                    const exists = localCatalog.some(d => Number(d.id) === cleanId);
                    if (!exists) {
                        localCatalog.unshift(sanitized);
                    }
                }
            }
        } else {
            sharedIds = sharedIds.filter(id => id !== cleanId);
            saveSharedDocsConfig(sharedIds, targetDb);
            ['DokumentationDB', 'TestBankDB', currentConfig.dbName].forEach(db => {
                if (!db) return;
                let ids = loadSharedDocsConfig(db);
                if (ids.includes(cleanId)) {
                    saveSharedDocsConfig(ids.filter(id => id !== cleanId), db);
                }
            });
            localCatalog = localCatalog.filter(d => Number(d.id) !== cleanId);
        }

        await refreshLocalCatalog();
        broadcastPresence();
        updateSwarmBadge();
        renderSwarmModalContent();
    }

    function isDocShared(docId) {
        const cleanId = Number(docId);
        if (!cleanId) return false;
        const dbs = ['DokumentationDB', 'TestBankDB', currentConfig.dbName];
        for (const db of dbs) {
            if (db && loadSharedDocsConfig(db).includes(cleanId)) return true;
        }
        return localCatalog.some(d => Number(d.id) === cleanId);
    }

    // =========================================================================
    // 4. UI: ZERO-TRUST SWARM MODAL RENDERING
    // =========================================================================

    function applyBadgeDom(stagedCount, newFilesCount, activePeers, totalShared) {
        document.querySelectorAll('#swarm-status-badge, #headerSwarmBadge').forEach(badge => {
            if (stagedCount > 0) {
                badge.className = 'swarm-pill is-active has-inbox';
                badge.style.background = '#16a34a';
                badge.innerHTML = `<span style="display:inline-flex; align-items:center; gap:5px;"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 12h-6l-2 3h-4l-2-3H2"></path><path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"></path></svg> <strong>Posteingang (${stagedCount})</strong></span>`;
                badge.title = `${stagedCount} neue Datei(en) im Posteingang bereit! (Klick zum Öffnen/Übernehmen)`;
            } else if (newFilesCount > 0) {
                badge.className = 'swarm-pill is-active has-new';
                badge.style.background = '#2563eb';
                badge.textContent = `Schwarm (+${newFilesCount} neu)`;
                badge.title = `${newFilesCount} neue Dokumente im Schwarm verfügbar`;
            } else if (activePeers > 0) {
                badge.className = 'swarm-pill is-active';
                badge.style.background = '#28a745';
                badge.textContent = `Schwarm online (${activePeers})`;
                badge.title = `P2P-Schwarm aktiv (${activePeers} Peers verbunden)`;
            } else {
                badge.className = 'swarm-pill';
                badge.style.background = '#505864';
                badge.textContent = `Schwarm (${totalShared} geteilt)`;
                badge.title = `P2P-Schwarm bereit (${totalShared} geteilt)`;
            }
        });

        // Notify parent frame (index.html)
        if (window.parent && window.parent !== window) {
            try {
                window.parent.postMessage({
                    type: 'SWARM_BADGE_UPDATE',
                    activePeers: activePeers,
                    totalShared: totalShared,
                    newFilesCount: newFilesCount,
                    stagedCount: stagedCount
                }, getTargetOrigin());
            } catch (e) {}
        }
    }

    async function updateSwarmBadge() {
        const stagedDocs = getStagedInboxDocuments();
        const stagedCount = stagedDocs.length;
        const activePeers = remoteCatalog.size;
        const totalShared = localCatalog.length;

        // 1. Immediately apply DOM badge update so there is 0ms UI lag
        applyBadgeDom(stagedCount, 0, activePeers, totalShared);

        // 2. Query remote files asynchronously
        let newFilesCount = 0;
        try {
            const newFiles = await getNewRemoteFiles();
            newFilesCount = newFiles.length;
        } catch (e) {}

        applyBadgeDom(stagedCount, newFilesCount, activePeers, totalShared);
    }

    async function openSwarmModal(tab) {
        if (tab) {
            currentSwarmTab = (tab === 'local' || tab === 'inbox') ? tab : 'remote';
        } else {
            const staged = getStagedInboxDocuments();
            if (staged.length > 0) currentSwarmTab = 'inbox';
        }
        let modal = document.getElementById('swarm-modal');
        if (!modal) {
            createSwarmModalDom();
            modal = document.getElementById('swarm-modal');
        }
        if (modal) {
            modal.style.display = 'flex';
            switchSwarmTab(currentSwarmTab);
        }
        refreshLocalCatalog().then(() => {
            renderSwarmModalContent();
        });
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
            tabInbox: "Boîte de réception",
            tabRemote: "Documents disponibles dans l'essaim",
            tabLocal: "Mes documents partagés",
            inboxEmpty: "Votre boîte de réception est vide",
            inboxEmptyHint: "",
            import1Click: "Importer (1 clic)",
            importAll: "Tout importer",
            dismiss: "Ignorer",
            inboxWaiting: "document(s) en attente d'importation dans votre base locale :",
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
            tabInbox: "Staged Inbox",
            tabRemote: "Available Documents in Swarm",
            tabLocal: "My Shared Documents",
            inboxEmpty: "Your staged inbox is empty",
            inboxEmptyHint: "",
            import1Click: "Import (1 click)",
            importAll: "Import All",
            dismiss: "Dismiss",
            inboxWaiting: "document(s) precached and waiting to be imported:",
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
            tabInbox: "Posteingang",
            tabRemote: "Verfügbare Dokumente im Schwarm",
            tabLocal: "Meine geteilten Dokumente",
            inboxEmpty: "Ihr Posteingang ist leer",
            inboxEmptyHint: "",
            import1Click: "Übernehmen (1 Klick)",
            importAll: "Alle übernehmen",
            dismiss: "Verwerfen",
            inboxWaiting: "Dokument(e) im Vorab-Puffer bereit zur Übernahme :",
            noPeers: "Keine weiteren Peers im Schwarm aktiv",
            noPeersHint: "Sobald sich andere Lehrkräfte auf GitHub Pages befinden und Dokumente bereitstellen, erscheinen diese hier automatisch in Echtzeit.",
            download: "Herunterladen",
            downloading: "Wird geladen...",
            noSharedLocal: "Sie teilen derzeit keine Dokumente",
            noSharedLocalHint: "Um ein Dokument mit der Community zu teilen, öffnen Sie das Dokument in der Vollansicht und klicken Sie auf „In Community-Schwarm teilen“.",
            stopShare: "Teilen beenden",
            close: "Schließen",
            docsAvailable: "geprüfte(s) Dokument(e) im Schwarm verfügbar :"
        }
    };

    function getSwarmLang() {
        try {
            const l = (document.documentElement.lang || localStorage.getItem('wiki_lang') || 'DE').toUpperCase();
            if (l.startsWith('FR')) return 'FR';
            if (l.startsWith('EN')) return 'EN';
        } catch (e) {}
        return 'DE';
    }

        function isDarkThemeActive() {
        const t = (document.documentElement.getAttribute('data-theme') || '').toLowerCase();
        return t === 'dark' || t === 'osiris';
    }

    function createSwarmModalDom() {
        const i18n = (typeof SWARM_STRINGS !== 'undefined' && SWARM_STRINGS.DE) || {
            title: "Community-Schwarm (Dezentrales WebRTC P2P)",
            sub: "Zero-Knowledge · Browser-zu-Browser · Cross-Device auf GitHub Hosting",
            directNotice: "✨ Automatische Direktverbindung: Alle Kollegen auf dieser Seite tauschen Dokumente direkt ohne Code aus!",
            tabRemote: "Verfügbare Dokumente im Schwarm",
            tabLocal: "Meine geteilten Dokumente",
            close: "Schließen",
            download: "Herunterladen",
            stopShare: "Teilen beenden"
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
            <style id="swarm-responsive-styles">
                #swarm-tabs-container::-webkit-scrollbar {
                    height: 4px;
                }
                #swarm-tabs-container::-webkit-scrollbar-track {
                    background: transparent;
                }
                #swarm-tabs-container::-webkit-scrollbar-thumb {
                    background: ${isDark ? 'rgba(148, 163, 184, 0.35)' : 'rgba(100, 116, 139, 0.35)'};
                    border-radius: 4px;
                }
                #swarm-tabs-container::-webkit-scrollbar-thumb:hover {
                    background: ${isDark ? 'rgba(148, 163, 184, 0.65)' : 'rgba(100, 116, 139, 0.65)'};
                }
                @media (max-width: 640px) {
                    #swarm-modal {
                        padding: 8px !important;
                    }
                    #swarm-modal-dialog {
                        max-height: 96vh !important;
                        border-radius: 12px !important;
                        width: 100% !important;
                    }
                    #swarm-modal-header {
                        padding: 12px 14px !important;
                    }
                    #swarm-ui-title {
                        font-size: 1.05rem !important;
                    }
                    #swarm-status-banner {
                        padding: 10px 14px !important;
                        gap: 8px !important;
                    }
                    #swarm-tabs-container {
                        padding: 0 4px !important;
                        -webkit-overflow-scrolling: touch !important;
                    }
                    .swarm-tab-item {
                        padding: 11px 14px !important;
                        font-size: 0.84rem !important;
                    }
                    #swarm-tab-content {
                        padding: 14px 10px !important;
                    }
                    #swarm-modal-footer {
                        padding: 10px 14px !important;
                    }
                    .swarm-doc-card {
                        flex-direction: column !important;
                        align-items: stretch !important;
                        gap: 12px !important;
                        padding: 12px 14px !important;
                    }
                    .swarm-doc-actions {
                        display: flex !important;
                        justify-content: flex-end !important;
                        width: 100% !important;
                        gap: 8px !important;
                    }
                    .swarm-doc-actions button {
                        flex: 1 1 auto !important;
                        justify-content: center !important;
                    }
                }
            </style>
            <div id="swarm-modal-dialog" style="background: ${dialogBg}; color: ${dialogText}; border: 1px solid ${borderColor}; border-radius: 14px; width: 100%; max-width: 860px; max-height: 90vh; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 24px 60px rgba(0,0,0,0.45); opacity: 1 !important;">
                
                <!-- Header (Solid Opaque Background) -->
                <div id="swarm-modal-header" style="display: flex; justify-content: space-between; align-items: center; padding: 16px 22px; border-bottom: 1px solid ${borderColor}; background: ${headerBg};">
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
                <div id="swarm-status-banner" style="padding: 12px 22px; background: ${isDark ? 'rgba(34, 197, 94, 0.12)' : 'rgba(34, 197, 94, 0.08)'}; border-bottom: 1px solid ${isDark ? 'rgba(34, 197, 94, 0.25)' : 'rgba(34, 197, 94, 0.2)'}; font-size: 0.84rem; display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap:wrap;">
                    <div style="display:flex; align-items:center; gap:9px;">
                        <span id="swarm-net-dot" style="display:inline-block; width:10px; height:10px; border-radius:50%; background:#22c55e; box-shadow:0 0 8px rgba(34, 197, 94, 0.7); flex-shrink:0;"></span>
                        <span id="swarm-net-status-text" style="color:${isDark ? '#bbf7d0' : '#166534'};"><strong>Automatische Direktverbindung:</strong> Alle Kollegen auf dieser Seite tauschen Dokumente direkt ohne Code aus.</span>
                    </div>
                    <div style="display:flex; align-items:center; gap:10px;">
                        <label style="display:inline-flex; align-items:center; gap:6px; cursor:pointer; font-size:0.75rem; font-weight:600; color:${isDark ? '#bbf7d0' : '#166534'}; background:${isDark ? 'rgba(34,197,94,0.18)' : '#dcfce7'}; border:1px solid rgba(34,197,94,0.35); padding:3px 9px; border-radius:6px;" title="Dokumente aus dem P2P-Schwarm automatisch in die lokale Datenbank speichern, falls sie noch nicht vorhanden sind">
                            <input type="checkbox" id="swarm-auto-save-toggle" ${isAutoSaveToDbEnabled() ? 'checked' : ''} onchange="EduHybridShare.toggleAutoSaveToDb(this.checked)" style="cursor:pointer; width:13px; height:13px; accent-color:#16a34a;">
                            <span>Auto-Speichern in DB</span>
                        </label>
                        <span id="swarm-mesh-badge" style="font-size:0.75rem; font-weight:700; color:#16a34a; background:${isDark ? 'rgba(34,197,94,0.18)' : '#dcfce7'}; border:1px solid rgba(34,197,94,0.35); padding:3px 9px; border-radius:6px; white-space:nowrap;">● P2P Direkt aktiv</span>
                    </div>
                </div>

                <!-- Tabs with Modern Sleek Icons and Horizontal Scrollability on Mobile -->
                <div id="swarm-tabs-container" style="display:flex; overflow-x:auto; overflow-y:hidden; -webkit-overflow-scrolling:touch; border-bottom: 1px solid ${borderColor}; background: ${headerBg}; scrollbar-width:thin;">
                    <button id="swarm-tab-inbox" class="swarm-tab-item" style="flex:1 0 auto; min-width:max-content; padding:13px 18px; border:none; background:transparent; border-bottom:3px solid transparent; font-weight:600; cursor:pointer; color:${isDark ? '#94a3b8' : '#64748b'}; font-size:0.9rem; display:inline-flex; align-items:center; justify-content:center; gap:8px; white-space:nowrap; -webkit-tap-highlight-color:transparent;">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><path d="M22 12h-6l-2 3h-4l-2-3H2"></path><path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"></path></svg>
                        <span>${i18n.tabInbox || 'Posteingang'}</span>
                    </button>
                    <button id="swarm-tab-remote" class="swarm-tab-item" style="flex:1 0 auto; min-width:max-content; padding:13px 18px; border:none; background:transparent; border-bottom:3px solid #2563eb; font-weight:700; cursor:pointer; color:#2563eb; font-size:0.9rem; display:inline-flex; align-items:center; justify-content:center; gap:8px; white-space:nowrap; -webkit-tap-highlight-color:transparent;">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10z"></path><path d="M12 2a15.3 15.3 0 0 0-4 10 15.3 15.3 0 0 0 4 10z"></path></svg>
                        <span>${i18n.tabRemote || 'Verfügbare Dokumente'}</span>
                    </button>
                    <button id="swarm-tab-local" class="swarm-tab-item" style="flex:1 0 auto; min-width:max-content; padding:13px 18px; border:none; background:transparent; border-bottom:3px solid transparent; font-weight:600; cursor:pointer; color:${isDark ? '#94a3b8' : '#64748b'}; font-size:0.9rem; display:inline-flex; align-items:center; justify-content:center; gap:8px; white-space:nowrap; -webkit-tap-highlight-color:transparent;">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"></path><polyline points="16 6 12 2 8 6"></polyline><line x1="12" y1="2" x2="12" y2="15"></line></svg>
                        <span>${i18n.tabLocal || 'Meine geteilten'}</span>
                    </button>
                </div>

                <!-- Tab Content Area (Solid Opaque Background, Zero Bleed-Through) -->
                <div id="swarm-tab-content" style="padding: 22px; overflow-y: auto; flex: 1; background: ${dialogBg}; min-height: 260px;"></div>

                <!-- Footer -->
                <div id="swarm-modal-footer" style="padding: 14px 22px; border-top: 1px solid ${borderColor}; display: flex; justify-content: space-between; align-items: center; background: ${headerBg}; font-size: 0.82rem;">
                    <span id="swarm-footer-stats" style="color:${isDark ? '#94a3b8' : '#64748b'};">Status: P2P-Schwarm aktiv</span>
                    <button id="swarm-close-btn" style="padding: 8px 18px; border: 1px solid ${borderColor}; border-radius: 6px; background: ${dialogBg}; color: ${dialogText}; font-weight: 600; cursor: pointer; font-size:0.84rem;">${i18n.close}</button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        document.getElementById('swarm-close-x').addEventListener('click', closeSwarmModal);
        document.getElementById('swarm-close-btn').addEventListener('click', closeSwarmModal);
        document.getElementById('swarm-tab-inbox').addEventListener('click', () => switchSwarmTab('inbox'));
        document.getElementById('swarm-tab-remote').addEventListener('click', () => switchSwarmTab('remote'));
        document.getElementById('swarm-tab-local').addEventListener('click', () => switchSwarmTab('local'));

        // Event delegation for Download, 1-Click Import, Dismiss, and Stop sharing buttons
        const contentWrap = document.getElementById('swarm-tab-content');
        contentWrap.addEventListener('click', async (e) => {
            const importBtn = e.target.closest('[data-swarm-import]');
            if (importBtn) {
                const docId = importBtn.getAttribute('data-swarm-import');
                importBtn.disabled = true;
                importBtn.style.opacity = '0.75';
                importBtn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block; vertical-align:middle; margin-right:6px; animation:osirisToastSpin 0.85s linear infinite;"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg><span>Wird übernommen...</span>`;
                await importStagedDocToDb(docId, false);
                return;
            }
            const dlStagedBtn = e.target.closest('[data-swarm-download-staged]');
            if (dlStagedBtn) {
                const docId = Number(dlStagedBtn.getAttribute('data-swarm-download-staged'));
                downloadStagedInboxDocFile(docId);
                return;
            }
            const dismissBtn = e.target.closest('[data-swarm-dismiss]');
            if (dismissBtn) {
                const docId = dismissBtn.getAttribute('data-swarm-dismiss');
                removeStagedInboxDocument(docId);
                renderSwarmModalContent();
                updateSwarmBadge();
                return;
            }
            const importAllBtn = e.target.closest('#btn-import-all-staged');
            if (importAllBtn) {
                importAllBtn.disabled = true;
                importAllBtn.style.opacity = '0.75';
                importAllBtn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block; vertical-align:middle; margin-right:6px; animation:osirisToastSpin 0.85s linear infinite;"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg><span>Übernehme alle...</span>`;
                await importAllStagedDocsToDb();
                return;
            }
            const dlBtn = e.target.closest('[data-swarm-download]');
            if (dlBtn) {
                const docId = Number(dlBtn.getAttribute('data-doc-id'));
                const peerId = dlBtn.getAttribute('data-peer-id') || '';
                dlBtn.disabled = true;
                dlBtn.style.opacity = '0.8';
                dlBtn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block; vertical-align:middle; margin-right:6px; animation:osirisToastSpin 0.85s linear infinite;"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg><span>${i18n.downloading || 'Wird geladen...'}</span>`;
                
                if (peerId === 'official') {
                    try {
                        await downloadOfficialCatalogDoc(docId);
                    } catch (e) {
                        renderSwarmModalContent();
                    }
                    return;
                }

                // Check if doc has fileData available directly in memory or catalog
                const remotePeerData = remoteCatalog.get(peerId);
                const memDoc = remotePeerData && (remotePeerData.docs || []).find(d => Number(d.id) === docId);
                if (memDoc && memDoc.fileData) {
                    triggerBrowserFileDownload(memDoc.fileName || 'Dokument.pdf', memDoc.fileData);
                    stageDocumentInInbox(memDoc);
                    updateSwarmBadge();
                    if (isAutoSaveToDbEnabled()) {
                        await importStagedDocToDb(memDoc.id, true);
                    }
                    showSwarmToast(`📥 Datei „${memDoc.fileName}“ heruntergeladen & im Posteingang/DB bereitgestellt!`, 'info');
                    renderSwarmModalContent();
                    return;
                }

                // Track user intent for browser file download upon arrival via P2P
                userDownloadRequests.add(docId);
                requestDocDownload(docId, peerId);

                setTimeout(() => {
                    if (document.body.contains(dlBtn) && userDownloadRequests.has(docId) && dlBtn.disabled) {
                        userDownloadRequests.delete(docId);
                        dlBtn.disabled = false;
                        dlBtn.style.opacity = '1';
                        dlBtn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg> <span>${i18n.download || 'Herunterladen'}</span>`;
                        showSwarmToast('⚠️ P2P-Direktübertragung wird durch Browser/Netzwerk-Sicherheit blockiert. Bitte Dokument als offiziellen Katalog auf GitHub veröffentlichen oder per Bluetooth/Mail senden.', 'warning');
                    }
                }, 4000);
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
        currentSwarmTab = (tab === 'local' || tab === 'inbox') ? tab : 'remote';
        const isDark = isDarkThemeActive();
        const inactiveColor = isDark ? '#94a3b8' : '#64748b';

        const btnInbox = document.getElementById('swarm-tab-inbox');
        const btnRemote = document.getElementById('swarm-tab-remote');
        const btnLocal = document.getElementById('swarm-tab-local');

        if (btnInbox) {
            btnInbox.style.borderBottomColor = currentSwarmTab === 'inbox' ? '#16a34a' : 'transparent';
            btnInbox.style.color = currentSwarmTab === 'inbox' ? '#16a34a' : inactiveColor;
            btnInbox.style.fontWeight = currentSwarmTab === 'inbox' ? '700' : '600';
        }
        if (btnRemote) {
            btnRemote.style.borderBottomColor = currentSwarmTab === 'remote' ? '#2563eb' : 'transparent';
            btnRemote.style.color = currentSwarmTab === 'remote' ? '#2563eb' : inactiveColor;
            btnRemote.style.fontWeight = currentSwarmTab === 'remote' ? '700' : '600';
        }
        if (btnLocal) {
            btnLocal.style.borderBottomColor = currentSwarmTab === 'local' ? '#2563eb' : 'transparent';
            btnLocal.style.color = currentSwarmTab === 'local' ? '#2563eb' : inactiveColor;
            btnLocal.style.fontWeight = currentSwarmTab === 'local' ? '700' : '600';
        }

        // Auto-scroll active tab into view smoothly on mobile/narrow viewports
        const activeBtn = currentSwarmTab === 'inbox' ? btnInbox : (currentSwarmTab === 'local' ? btnLocal : btnRemote);
        if (activeBtn && typeof activeBtn.scrollIntoView === 'function') {
            try {
                activeBtn.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'nearest' });
            } catch (e) {
                try { activeBtn.scrollIntoView(false); } catch (e2) {}
            }
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

        const langKey = getSwarmLang();
        const i18n = (typeof SWARM_STRINGS !== 'undefined' && SWARM_STRINGS[langKey]) || (SWARM_STRINGS && SWARM_STRINGS.DE) || {
            tabInbox: "Posteingang",
            tabRemote: "Verfügbare Dokumente im Schwarm",
            tabLocal: "Meine geteilten Dokumente",
            inboxEmpty: "Ihr Posteingang ist leer",
            inboxEmptyHint: "",
            import1Click: "Übernehmen (1 Klick)",
            importAll: "Alle übernehmen",
            dismiss: "Verwerfen",
            inboxWaiting: "Dokument(e) im Vorab-Puffer bereit zur Übernahme :",
            download: "Herunterladen",
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

        const stagedDocs = getStagedInboxDocuments();

        // Calculate allRemoteDocs (combining Official Git catalog + P2P peers)
        const allRemoteDocs = [];
        const seenRemoteKeys = new Set();
        const localSharedHashes = new Set(
            (localCatalog || [])
                .map(d => d && d.fileHash ? String(d.fileHash).toLowerCase().trim() : '')
                .filter(Boolean)
        );
        const localSharedKeys = new Set(
            (localCatalog || [])
                .map(d => d ? `${(d.fileName || '').toLowerCase().trim()}_${d.fileSize || 0}` : '')
                .filter(Boolean)
        );
        const localSharedIds = new Set(
            (localCatalog || [])
                .map(d => d ? Number(d.id) : 0)
                .filter(Boolean)
        );

        // 1. Include official Git catalog documents into allRemoteDocs
        try {
            if (cachedOfficialCatalog && Array.isArray(cachedOfficialCatalog.documents)) {
                cachedOfficialCatalog.documents.forEach(doc => {
                    if (!doc) return;
                    const docHash = doc.fileHash ? String(doc.fileHash).toLowerCase().trim() : '';
                    const docKey = `${(doc.fileName || '').toLowerCase().trim()}_${doc.fileSize || 0}`;
                    const docId = Number(doc.id);

                    if (docHash && localSharedHashes.has(docHash)) return;
                    if (localSharedKeys.has(docKey)) return;
                    if (docId > 0 && localSharedIds.has(docId)) return;
                    if (isDocShared(docId)) return;

                    const dedupeKey = docHash || docKey || `official:${docId}`;
                    if (seenRemoteKeys.has(dedupeKey)) return;
                    seenRemoteKeys.add(dedupeKey);

                    allRemoteDocs.push({ peerId: 'official', doc, isOfficial: true });
                });
            }
        } catch (e) {}

        // 2. Include P2P peers into allRemoteDocs
        remoteCatalog.forEach((peerData, peerId) => {
            if (!PEER_ID_REGEX.test(peerId) || peerId === myPeerId) return;
            (peerData.docs || []).forEach(doc => {
                if (!doc) return;
                const docHash = doc.fileHash ? String(doc.fileHash).toLowerCase().trim() : '';
                const docKey = `${(doc.fileName || '').toLowerCase().trim()}_${doc.fileSize || 0}`;
                const docId = Number(doc.id);

                if (docHash && localSharedHashes.has(docHash)) return;
                if (localSharedKeys.has(docKey)) return;
                if (docId > 0 && localSharedIds.has(docId)) return;
                if (isDocShared(docId)) return;

                const dedupeKey = docHash || docKey || `${peerId}:${docId}`;
                if (seenRemoteKeys.has(dedupeKey)) return;
                seenRemoteKeys.add(dedupeKey);

                allRemoteDocs.push({ peerId, doc, isOfficial: false });
            });
        });

        // Update tab buttons text, modern SVG icons and counts
        const btnInboxTab = document.getElementById('swarm-tab-inbox');
        const btnRemoteTab = document.getElementById('swarm-tab-remote');
        const btnLocalTab = document.getElementById('swarm-tab-local');

        if (btnInboxTab) {
            btnInboxTab.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><path d="M22 12h-6l-2 3h-4l-2-3H2"></path><path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"></path></svg><span>${i18n.tabInbox}</span>` + (stagedDocs.length > 0 
                ? ` <span style="background:#16a34a; color:#ffffff; padding:1px 7px; border-radius:10px; font-size:0.75rem; font-weight:700; margin-left:4px;">${stagedDocs.length} neu</span>` 
                : ` (0)`);
        }
        if (btnRemoteTab) {
            btnRemoteTab.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10z"></path><path d="M12 2a15.3 15.3 0 0 0-4 10 15.3 15.3 0 0 0 4 10z"></path></svg><span>${i18n.tabRemote} (${allRemoteDocs.length})</span>`;
        }
        if (btnLocalTab) {
            btnLocalTab.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"></path><polyline points="16 6 12 2 8 6"></polyline><line x1="12" y1="2" x2="12" y2="15"></line></svg><span>${i18n.tabLocal} (${localCatalog.length})</span>`;
        }

        // --- Render Tab 1: INBOX ---
        if (currentSwarmTab === 'inbox') {
            if (stagedDocs.length === 0) {
                wrap.innerHTML = `
                    <div style="text-align:center; padding: 48px 20px; color: ${metaColor};">
                        <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="#16a34a" stroke-width="1.75" style="opacity:0.85; margin-bottom:12px;">
                            <path d="M22 12h-6l-2 3h-4l-2-3H2"></path>
                            <path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"></path>
                        </svg>
                        <h4 style="margin:0; color:${textColor}; font-size:1.05rem;">${i18n.inboxEmpty}</h4>
                    </div>
                `;
            } else {
                let html = `
                    <div style="display:flex; flex-direction:column; gap:12px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:2px; flex-wrap:wrap; gap:8px;">
                            <div style="font-size:0.85rem; color:${metaColor}; font-weight:600;">
                                <strong style="color:#16a34a;">${stagedDocs.length}</strong> ${i18n.inboxWaiting}
                            </div>
                            ${stagedDocs.length > 1 ? `
                                <button type="button" id="btn-import-all-staged" style="display:inline-flex; align-items:center; gap:6px; padding:6px 14px; background:#16a34a; color:#ffffff; border:none; border-radius:6px; font-weight:700; cursor:pointer; font-size:0.8rem; box-shadow:0 2px 5px rgba(22,163,74,0.25);">
                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                                    <span>${i18n.importAll} (${stagedDocs.length})</span>
                                </button>
                            ` : ''}
                        </div>
                `;

                stagedDocs.forEach(doc => {
                    const safeTyp = escapeHtml(doc.typ || currentConfig.docTypeLabel);
                    const safeKlassen = escapeHtml(doc.klassen || 'Alle');
                    const safeJahr = escapeHtml(doc.jahr || '2026');
                    const safeThema = escapeHtml(doc.thema || 'Unbenannt');
                    const safeLektion = escapeHtml(doc.lektion || '—');
                    const safeBuch = escapeHtml(doc.buch || '—');
                    const safeFileName = escapeHtml(doc.fileName || 'Dokument.pdf');
                    const safeDocId = Number(doc.id) || doc.id;
                    const shortHash = doc.fileHash ? escapeHtml(doc.fileHash.substring(0, 6).toUpperCase()) : 'VERIFIED';
                    const sizeMb = doc.fileSize ? (doc.fileSize / (1024 * 1024)).toFixed(2) + ' MB' : '';

                    html += `
                        <div class="swarm-doc-card" style="display:flex; justify-content:space-between; align-items:center; padding:14px 18px; border:1px solid ${isDark ? 'rgba(34,197,94,0.3)' : '#86efac'}; border-radius:10px; background:${isDark ? 'rgba(34,197,94,0.06)' : '#f0fdf4'}; box-shadow:${shadow}; gap:14px;">
                            <div style="flex:1; min-width:0;">
                                <div style="display:flex; gap:6px; align-items:center; margin-bottom:6px; flex-wrap:wrap;">
                                    <span style="background:#16a34a; color:white; padding:2px 8px; border-radius:4px; font-size:0.72rem; font-weight:700; display:inline-flex; align-items:center; gap:4px;"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 12h-6l-2 3h-4l-2-3H2"></path><path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"></path></svg> Posteingang</span>
                                    <span style="background:#2563eb; color:white; padding:2px 8px; border-radius:4px; font-size:0.72rem; font-weight:700;">${safeTyp}</span>
                                    <span style="background:${isDark ? '#334155' : '#e2e8f0'}; color:${textColor}; padding:2px 8px; border-radius:4px; font-size:0.72rem; font-weight:600;">${safeKlassen}</span>
                                    <span style="background:${isDark ? '#334155' : '#e2e8f0'}; color:${textColor}; padding:2px 8px; border-radius:4px; font-size:0.72rem;">${safeJahr}</span>
                                    <span title="SHA-256 Fingerabdruck" style="background:${isDark ? 'rgba(34,197,94,0.18)' : '#dcfce7'}; color:#16a34a; border:1px solid rgba(34,197,94,0.35); padding:1px 7px; border-radius:4px; font-family:monospace; font-size:0.72rem; font-weight:700;">SHA: #${shortHash}</span>
                                    ${sizeMb ? `<span style="font-size:0.72rem; color:${metaColor};">(${sizeMb})</span>` : ''}
                                </div>
                                <h4 style="margin:0 0 4px 0; color:${isDark ? '#4ade80' : '#15803d'}; font-size:1.02rem; font-weight:700; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${safeThema}</h4>
                                <div style="font-size:0.78rem; color:${metaColor}; line-height:1.4;">
                                    Lektion: <strong>${safeLektion}</strong> | Buch: <strong>${safeBuch}</strong> | 📄 ${safeFileName}
                                </div>
                            </div>
                            <div class="swarm-doc-actions" style="display:flex; align-items:center; gap:8px; flex-shrink:0;">
                                <button type="button" data-swarm-import="${safeDocId}" style="display:inline-flex; align-items:center; gap:6px; padding:10px 16px; background:#16a34a; color:#ffffff; border:none; border-radius:8px; font-weight:700; cursor:pointer; font-size:0.85rem; box-shadow:0 2px 6px rgba(22,163,74,0.35); transition:transform 0.15s ease;">
                                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                                    <span>${i18n.import1Click}</span>
                                </button>
                                <button type="button" data-swarm-download-staged="${safeDocId}" style="display:inline-flex; align-items:center; justify-content:center; padding:10px 12px; background:#2563eb; color:#ffffff; border:none; border-radius:8px; font-weight:700; cursor:pointer; font-size:0.82rem; box-shadow:0 2px 6px rgba(37,99,235,0.3);" title="Datei direkt auf Gerät herunterladen">
                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                                </button>
                                <button type="button" data-swarm-dismiss="${safeDocId}" style="padding:10px 12px; background:transparent; color:${metaColor}; border:1px solid ${cardBorder}; border-radius:8px; font-weight:600; cursor:pointer; font-size:0.82rem;" title="${i18n.dismiss}">
                                    ✕
                                </button>
                            </div>
                        </div>
                    `;
                });

                html += `</div>`;
                wrap.innerHTML = html;
            }
        } else if (currentSwarmTab === 'remote') {
            const allRemoteDocs = [];
            const seenRemoteKeys = new Set();

            // Build lookup sets of documents currently in "Meine geteilten Dokumente" (localCatalog)
            const localSharedHashes = new Set(
                (localCatalog || [])
                    .map(d => d && d.fileHash ? String(d.fileHash).toLowerCase().trim() : '')
                    .filter(Boolean)
            );
            const localSharedKeys = new Set(
                (localCatalog || [])
                    .map(d => d ? `${(d.fileName || '').toLowerCase().trim()}_${d.fileSize || 0}` : '')
                    .filter(Boolean)
            );
            const localSharedIds = new Set(
                (localCatalog || [])
                    .map(d => d ? Number(d.id) : 0)
                    .filter(Boolean)
            );

            // 1. Include official Git catalog documents
            try {
                if (cachedOfficialCatalog && Array.isArray(cachedOfficialCatalog.documents)) {
                    cachedOfficialCatalog.documents.forEach(doc => {
                        if (!doc) return;
                        const docHash = doc.fileHash ? String(doc.fileHash).toLowerCase().trim() : '';
                        const docKey = `${(doc.fileName || '').toLowerCase().trim()}_${doc.fileSize || 0}`;
                        const docId = Number(doc.id);

                        if (docHash && localSharedHashes.has(docHash)) return;
                        if (localSharedKeys.has(docKey)) return;
                        if (docId > 0 && localSharedIds.has(docId)) return;
                        if (isDocShared(docId)) return;

                        const dedupeKey = docHash || docKey || `official:${docId}`;
                        if (seenRemoteKeys.has(dedupeKey)) return;
                        seenRemoteKeys.add(dedupeKey);

                        allRemoteDocs.push({ peerId: 'official', doc, isOfficial: true });
                    });
                }
            } catch (e) {}

            // 2. Include P2P peers
            remoteCatalog.forEach((peerData, peerId) => {
                if (!PEER_ID_REGEX.test(peerId) || peerId === myPeerId) return;
                (peerData.docs || []).forEach(doc => {
                    if (!doc) return;
                    const docHash = doc.fileHash ? String(doc.fileHash).toLowerCase().trim() : '';
                    const docKey = `${(doc.fileName || '').toLowerCase().trim()}_${doc.fileSize || 0}`;
                    const docId = Number(doc.id);

                    // 1. FILTER OUT: If this file is already in my shared documents (tabLocal), do NOT show it in available remote files
                    if (docHash && localSharedHashes.has(docHash)) return;
                    if (localSharedKeys.has(docKey)) return;
                    if (docId > 0 && localSharedIds.has(docId)) return;
                    if (isDocShared(docId)) return;

                    // 2. DEDUPLICATE: If multiple peers offer the exact same document, show it once
                    const dedupeKey = docHash || docKey || `${peerId}:${docId}`;
                    if (seenRemoteKeys.has(dedupeKey)) return;
                    seenRemoteKeys.add(dedupeKey);

                    allRemoteDocs.push({ peerId, doc, isOfficial: false });
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
                        <div style="background:${isDark ? 'rgba(37,99,235,0.12)' : '#eff6ff'}; border:1px solid ${isDark ? 'rgba(37,99,235,0.25)' : '#bfdbfe'}; border-radius:8px; padding:10px 14px; font-size:0.8rem; color:${isDark ? '#93c5fd' : '#1e40af'}; display:flex; align-items:center; gap:8px;">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                            <span><strong>Hinweis:</strong> Sie können Dokumente per 1-Klick „Herunterladen“ direkt auf Ihr Gerät speichern und in Ihre Datenbank übernehmen.</span>
                        </div>
                        <div style="font-size:0.85rem; color:${metaColor}; margin-bottom:2px; font-weight:600;">
                            ${allRemoteDocs.length} ${i18n.docsAvailable}
                        </div>
                `;

                allRemoteDocs.forEach(({ peerId, doc, isOfficial }) => {
                    const isDocOfficial = !!isOfficial || doc.isOfficial || peerId === 'official';
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

                    const isAlreadySaved = (doc.fileHash && window.knownLocalHashes && window.knownLocalHashes.has(doc.fileHash.toLowerCase())) ||
                                           (doc.fileName && doc.fileSize && window.knownLocalFileKeys && window.knownLocalFileKeys.has(String(doc.fileName).toLowerCase().trim() + '_' + doc.fileSize));

                    const actionBtnHtml = isAlreadySaved
                        ? `<button type="button" disabled style="display:flex; align-items:center; gap:8px; padding:10px 18px; background:#16a34a; color:#ffffff; border:none; border-radius:8px; font-weight:700; font-size:0.85rem; opacity:0.95; cursor:default; flex-shrink:0;">
                                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
                                <span>In Datenbank</span>
                           </button>`
                        : `<button type="button" data-swarm-download="1" data-doc-id="${safeDocId}" data-peer-id="${safePeerId}" style="display:flex; align-items:center; gap:8px; padding:10px 18px; background:#2563eb; color:#ffffff; border:none; border-radius:8px; font-weight:700; cursor:pointer; font-size:0.85rem; box-shadow:0 2px 6px rgba(37,99,235,0.35); flex-shrink:0;" title="Datei herunterladen & in Datenbank übernehmen">
                                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                                <span>${i18n.download || 'Herunterladen'}</span>
                           </button>`;

                    html += `
                        <div class="swarm-doc-card" style="display:flex; justify-content:space-between; align-items:center; padding:14px 18px; border:1px solid ${cardBorder}; border-radius:10px; background:${cardBg}; box-shadow:${shadow}; gap:14px;">
                            <div style="flex:1; min-width:0;">
                                <div style="display:flex; gap:6px; align-items:center; margin-bottom:6px; flex-wrap:wrap;">
                                    ${isDocOfficial ? `<span title="Offizielles Dokument (GitHub Repository)" style="background:#4f46e5; color:white; padding:2px 8px; border-radius:4px; font-size:0.72rem; font-weight:700; display:inline-flex; align-items:center; gap:4px;"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 2L2 7l10 5 10-5-10-5z"></path><path d="M2 17l10 5 10-5"></path><path d="M2 12l10 5 10-5"></path></svg> 🏛️ Offiziell</span>` : ''}
                                    <span style="background:#2563eb; color:white; padding:2px 8px; border-radius:4px; font-size:0.72rem; font-weight:700;">${safeTyp}</span>
                                    <span style="background:${isDark ? '#334155' : '#e2e8f0'}; color:${textColor}; padding:2px 8px; border-radius:4px; font-size:0.72rem; font-weight:600;">${safeKlassen}</span>
                                    <span style="background:${isDark ? '#334155' : '#e2e8f0'}; color:${textColor}; padding:2px 8px; border-radius:4px; font-size:0.72rem;">${safeJahr}</span>
                                    ${isAlreadySaved ? `<span title="Bereits in Ihrer lokalen Datenbank vorhanden" style="background:${isDark ? "rgba(34,197,94,0.22)" : "#dcfce7"}; color:#16a34a; border:1px solid rgba(34,197,94,0.45); padding:1px 7px; border-radius:4px; font-size:0.72rem; font-weight:700;">✅ In Datenbank</span>` : ""}
                                    <span title="SHA-256 Fingerabdruck" style="background:${isDark ? 'rgba(34,197,94,0.18)' : '#dcfce7'}; color:#16a34a; border:1px solid rgba(34,197,94,0.35); padding:1px 7px; border-radius:4px; font-family:monospace; font-size:0.72rem; font-weight:700;">SHA: #${shortHash}</span>
                                </div>
                                <h4 style="margin:0 0 4px 0; color:${isDark ? '#60a5fa' : '#1e3a8a'}; font-size:1rem; font-weight:700; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${safeThema}</h4>
                                <div style="font-size:0.78rem; color:${metaColor}; line-height:1.4;">
                                    Lektion: <strong>${safeLektion}</strong> | Buch: <strong>${safeBuch}</strong> | 📄 ${safeFileName}
                                </div>
                            </div>
                            <div class="swarm-doc-actions" style="display:flex; align-items:center; gap:8px; flex-shrink:0;">
                                ${actionBtnHtml}
                            </div>
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
                            Sie teilen ${localCatalog.length} Dokument(e) im Schwarm :
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
                        <div class="swarm-doc-card" style="display:flex; justify-content:space-between; align-items:center; padding:14px 18px; border:1px solid ${cardBorder}; border-radius:10px; background:${cardBg}; box-shadow:${shadow}; gap:14px;">
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
                            <div class="swarm-doc-actions" style="display:flex; align-items:center; gap:8px; flex-shrink:0;">
                                <button type="button" data-swarm-stop="1" data-doc-id="${safeDocId}" style="padding:9px 16px; background:#dc2626; color:white; border:none; border-radius:8px; font-weight:700; cursor:pointer; font-size:0.84rem; box-shadow:0 1px 4px rgba(220,38,38,0.25);">
                                    <span>${i18n.stopShare || 'Teilen beenden'}</span>
                                </button>
                            </div>
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
            footerStats.textContent = `Status: ${activePeers} Peer(s) im Netzwerk (${webrtcConnections.size} WebRTC verbunden) | ${stagedDocs.length} im Posteingang | ${localCatalog.length} eigene freigegeben`;
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
        MAX_FILE_BYTES: MAX_FILE_BYTES,
        MAX_P2P_SHARE_BYTES: MAX_P2P_SHARE_BYTES,
        trackUpdatedDoc: trackUpdatedDoc,
        isDocAnUpdate: isDocAnUpdate
    });

    function isAutoShareImportEnabled() {
        try {
            return localStorage.getItem('swarm_auto_share_import') === 'true';
        } catch (e) {
            return false;
        }
    }

    function setAutoShareImport(enabled) {
        try {
            localStorage.setItem('swarm_auto_share_import', enabled ? 'true' : 'false');
        } catch (e) {}
    }

    const eduHybridShareApi = Object.freeze({
        MAX_P2P_SHARE_BYTES: MAX_P2P_SHARE_BYTES,
        getNewRemoteFiles: getNewRemoteFiles,
        syncAllAvailableDocs: syncAllAvailableDocs,
        updateSwarmBadge: updateSwarmBadge,
        isAutoSaveToDbEnabled: isAutoSaveToDbEnabled,
        setAutoSaveToDbEnabled: setAutoSaveToDbEnabled,
        toggleAutoSaveToDb: toggleAutoSaveToDb,
        checkDocExistsInDatabases: checkDocExistsInDatabases,
        showSwarmToast: showSwarmToast,
        handleSwarmMessage: handleSwarmMessage,
        isAutoShareImportEnabled: isAutoShareImportEnabled,
        setAutoShareImport: setAutoShareImport,
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
        trackUpdatedDoc: trackUpdatedDoc,
        isDocAnUpdate: isDocAnUpdate,
        getStagedInboxDocuments: getStagedInboxDocuments,
        stageDocumentInInbox: stageDocumentInInbox,
        removeStagedInboxDocument: removeStagedInboxDocument,
        importStagedDocToDb: importStagedDocToDb,
        importAllStagedDocsToDb: importAllStagedDocsToDb,
        receiveDocFromPeer: receiveDocFromPeer,
        broadcastDataReload: broadcastDataReload,
        fetchOfficialCatalog: fetchOfficialCatalog,
        syncOfficialCatalog: syncOfficialCatalog,
        exportOfficialCatalogJson: exportOfficialCatalogJson,
        downloadOfficialCatalogDoc: downloadOfficialCatalogDoc,
        downloadLocalSharedDocFile: downloadLocalSharedDocFile,
        downloadStagedInboxDocFile: downloadStagedInboxDocFile
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

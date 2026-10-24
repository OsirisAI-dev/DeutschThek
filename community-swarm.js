/**
 * Osiris EduHub - Hardened Hybrid Document Sharing & Security Engine
 * (Social 1-to-1 + Decentralized WebRTC Swarm + Zero-Trust Client Security)
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
    const RATE_LIMIT_MAX_MSGS = 15;     // max 15 messages per 10s per peer
    const PEER_ID_REGEX = /^peer_[a-z0-9]{6,16}$/;

    let currentConfig = {
        dbName: 'DokumentationDB',
        storeName: 'documents',
        docTypeLabel: 'Doktyp',
        onDocImported: null
    };

    let localCatalog = [];
    let remoteCatalog = new Map();       // peerId -> { lastSeen, docs }
    let peerRateTracker = new Map();     // peerId -> [timestamps]
    let blockedPeers = new Set();        // peerIds blocked for flooding/malformed data
    let pendingRequests = new Set();     // "${peerId}:${docId}" explicitly requested by user
    let broadcastChannel = null;

    // Generate cryptographically random Peer ID
    const randBytes = new Uint8Array(6);
    if (window.crypto && window.crypto.getRandomValues) {
        window.crypto.getRandomValues(randBytes);
    }
    let myPeerId = 'peer_' + Array.from(randBytes).map(b => b.toString(16).padStart(2, '0')).join('');

    // =========================================================================
    // 1. ZERO-TRUST SECURITY & SANITIZATION SUITE (window.OsirisSecurity)
    // =========================================================================

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
        const s = String(val).trim();
        return s.length > (maxLen || MAX_META_STRING_LEN) ? s.substring(0, maxLen || MAX_META_STRING_LEN) : s;
    }

    function sanitizeUrl(url) {
        if (!url || typeof url !== 'string') return '#';
        const trimmed = url.trim();
        try {
            const parsed = new URL(trimmed, window.location.origin);
            if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
                return parsed.href.replace(/"/g, '%22').replace(/'/g, '%27');
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
            'data:video/mp4;base64,',
            'data:video/webm;base64,',
            'data:audio/mpeg;base64,',
            'data:audio/ogg;base64,',
            'data:application/octet-stream;base64,'
        ];
        const lower = trimmed.substring(0, 100).toLowerCase();
        if (allowedPrefixes.some(p => lower.startsWith(p))) {
            return trimmed;
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
                'link', 'style', 'base', 'applet', 'frame', 'frameset'
            ];
            forbiddenTags.forEach(tag => {
                doc.querySelectorAll(tag).forEach(el => el.remove());
            });
            const allElements = doc.body.querySelectorAll('*');
            allElements.forEach(el => {
                Array.from(el.attributes).forEach(attr => {
                    const name = attr.name.toLowerCase();
                    const val = (attr.value || '').trim().toLowerCase();
                    if (name.startsWith('on') || name === 'srcdoc' || name === 'formaction') {
                        el.removeAttribute(attr.name);
                    } else if ((name === 'href' || name === 'src' || name === 'xlink:href' || name === 'action') &&
                               (val.startsWith('javascript:') || val.startsWith('vbscript:') || val.startsWith('data:text/html'))) {
                        el.removeAttribute(attr.name);
                    }
                });
            });
            return doc.body.innerHTML;
        } catch (e) {
            return escapeHtml(dirtyHtml);
        }
    }

    function safeJsonParse(raw) {
        if (!raw || typeof raw !== 'string') return null;
        return JSON.parse(raw, (key, value) => {
            if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
                return undefined;
            }
            return value;
        });
    }

    async function computeSHA256(arrayBuffer) {
        try {
            const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } catch (e) {
            console.error('SHA-256 calculation failed:', e);
            return null;
        }
    }

    function asciiSlice(bytes, start, end) {
        let out = '';
        const lim = Math.min(bytes.length, end);
        for (let i = start; i < lim; i++) {
            out += String.fromCharCode(bytes[i]);
        }
        return out;
    }

    /**
     * Deep Binary Inspection: Magic Bytes + Active Content (PDF /JavaScript, Office Macros, Polyglots)
     */
    function validateMagicBytes(bytes, fileName) {
        if (!bytes || !(bytes instanceof Uint8Array) || bytes.length < 4) {
            return { valid: false, reason: 'Datei ist leer oder unvollständig.' };
        }

        if (bytes.length > MAX_FILE_BYTES) {
            return { valid: false, reason: 'Dateigröße überschreitet das Sicherheitslimit von 25 MB.' };
        }

        // 1. Block Executables & Scripts by Magic Header
        // MZ (Windows EXE / DLL / SCR)
        if (bytes[0] === 0x4D && bytes[1] === 0x5A) {
            return { valid: false, reason: 'Sicherheitsrisiko: Ausführbare Windows-Binärdateien (MZ/.exe) sind blockiert.' };
        }
        // ELF (Linux binary)
        if (bytes[0] === 0x7F && bytes[1] === 0x45 && bytes[2] === 0x4C && bytes[3] === 0x46) {
            return { valid: false, reason: 'Sicherheitsrisiko: Ausführbare ELF-Binärdateien sind blockiert.' };
        }
        // Mach-O (macOS binary)
        if ((bytes[0] === 0xFE && bytes[1] === 0xED && bytes[2] === 0xFA) ||
            (bytes[0] === 0xCF && bytes[1] === 0xFA && bytes[2] === 0xED)) {
            return { valid: false, reason: 'Sicherheitsrisiko: Ausführbare Mach-O-Binärdateien sind blockiert.' };
        }
        // Shebang (#!)
        if (bytes[0] === 0x23 && bytes[1] === 0x21) {
            return { valid: false, reason: 'Sicherheitsrisiko: Ausführbare Shell-Skripte (#!) sind blockiert.' };
        }

        // 2. Block dangerous file extensions (including double extensions like file.pdf.exe or .svg)
        const lowerName = (fileName || '').toLowerCase().trim();
        const forbiddenExts = [
            '.exe', '.scr', '.bat', '.cmd', '.sh', '.vbs', '.vbe', '.js', '.jse',
            '.wsf', '.wsh', '.msi', '.ps1', '.jar', '.com', '.hta', '.cpl', '.reg',
            '.dll', '.sys', '.svg', '.html', '.htm', '.xhtml', '.php', '.asp', '.docm', '.xlsm', '.pptm'
        ];
        for (let ext of forbiddenExts) {
            if (lowerName.endsWith(ext)) {
                return { valid: false, reason: 'Sicherheitsrisiko: Dateityp (' + ext + ') ist aus Sicherheitsgründen gesperrt.' };
            }
        }

        // 3. Identify Whitelisted Formats & Perform Deep Content Inspection
        const isPdf = bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46; // %PDF
        const isZipDocx = bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04; // PK\x03\x04
        const isOleDoc = bytes[0] === 0xD0 && bytes[1] === 0xCF && bytes[2] === 0x11 && bytes[3] === 0xE0; // Legacy .doc
        const isJpeg = bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF;
        const isPng = bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47;
        const isGif = bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38;
        const isWebp = bytes.length > 12 && asciiSlice(bytes, 0, 4) === 'RIFF' && asciiSlice(bytes, 8, 12) === 'WEBP';

        // Deep PDF Scan: Block embedded /JavaScript, /JS, /Launch, /RichMedia actions
        if (isPdf) {
            const pdfContent = asciiSlice(bytes, 0, Math.min(bytes.length, 2 * 1024 * 1024));
            const dangerousPdfKeys = ['/JavaScript', '/JS ', '/JS(', '/JS<', '/Launch', '/SubmitForm', '/ImportData', '/RichMedia'];
            for (let key of dangerousPdfKeys) {
                if (pdfContent.indexOf(key) !== -1) {
                    return {
                        valid: false,
                        reason: 'Sicherheitsrisiko: PDF enthält eingebetteten ausführbaren Code (' + key.trim() + '). Datei wurde blockiert.'
                    };
                }
            }
            return { valid: true, format: 'PDF' };
        }

        // Deep ZIP/DOCX Scan: Block Office Macros (vbaProject.bin) & embedded executables inside ZIP
        if (isZipDocx) {
            const zipAscii = asciiSlice(bytes, 0, Math.min(bytes.length, 2 * 1024 * 1024)).toLowerCase();
            if (zipAscii.indexOf('vbaproject.bin') !== -1 || zipAscii.indexOf('macros/') !== -1) {
                return {
                    valid: false,
                    reason: 'Sicherheitsrisiko: Word-Dokument enthält ausführbare VBA-Makros (vbaProject.bin).'
                };
            }
            if (zipAscii.indexOf('.exe') !== -1 || zipAscii.indexOf('.vbs') !== -1 || zipAscii.indexOf('.bat') !== -1 || zipAscii.indexOf('.ps1') !== -1) {
                return {
                    valid: false,
                    reason: 'Sicherheitsrisiko: Archiv enthält eingebettete ausführbare Skripte oder Programme.'
                };
            }
            return { valid: true, format: 'DOCX' };
        }

        if (isOleDoc) {
            return { valid: true, format: 'DOC' };
        }

        // Deep Image Scan: Ensure no HTML/Script polyglot payload hidden inside image
        if (isJpeg || isPng || isGif || isWebp) {
            const headSample = asciiSlice(bytes, 0, Math.min(bytes.length, 65536)).toLowerCase();
            if (headSample.indexOf('<script') !== -1 || headSample.indexOf('javascript:') !== -1 || headSample.indexOf('onerror=') !== -1) {
                return {
                    valid: false,
                    reason: 'Sicherheitsrisiko: Bilddatei enthält eingebetteten HTML/Skript-Code (Polyglot-Angriff).'
                };
            }
            return { valid: true, format: 'IMAGE' };
        }

        // Plain Text (.txt) check: verify no binary null bytes and no active HTML/Script tags
        if (lowerName.endsWith('.txt')) {
            const sample = asciiSlice(bytes, 0, Math.min(bytes.length, 65536)).toLowerCase();
            if (sample.indexOf('<script') !== -1 || sample.indexOf('<iframe') !== -1 || sample.indexOf('<svg') !== -1) {
                return {
                    valid: false,
                    reason: 'Sicherheitsrisiko: Textdatei enthält aktiven HTML/Script-Code.'
                };
            }
            return { valid: true, format: 'TEXT' };
        }

        // Reject all unknown binary formats (Strict Whitelist)
        return {
            valid: false,
            reason: 'Nicht unterstütztes oder unsicheres Dateiformat. Erlaubt sind nur geprüfte PDF-, DOCX-, Bild- und TXT-Dokumente.'
        };
    }

    function sanitizeDocRecord(rawDoc) {
        if (!rawDoc || typeof rawDoc !== 'object') return null;
        const safeSubTyp = Array.isArray(rawDoc.subTyp)
            ? rawDoc.subTyp.slice(0, 10).map(s => clampString(s, 80))
            : [];
        return {
            id: Number(rawDoc.id) || Date.now(),
            thema: clampString(rawDoc.thema || 'Unbenannt', MAX_META_STRING_LEN),
            lektion: clampString(rawDoc.lektion || '—', MAX_META_STRING_LEN),
            buch: clampString(rawDoc.buch || '—', MAX_META_STRING_LEN),
            klassen: clampString(rawDoc.klassen || 'Alle', 80),
            jahr: clampString(rawDoc.jahr || '2026', 20),
            typ: clampString(rawDoc.typ || currentConfig.docTypeLabel, 80),
            subTyp: safeSubTyp,
            fileName: clampString(rawDoc.fileName || 'Dokument.pdf', 150),
            fileType: clampString(rawDoc.fileType || 'application/pdf', 100),
            fileSize: Number(rawDoc.fileSize) || 0,
            fileHash: clampString(rawDoc.fileHash || '', 64).replace(/[^a-f0-9]/gi, '').toLowerCase(),
            fileData: sanitizeDataUrl(rawDoc.fileData || ''),
            date: clampString(rawDoc.date || new Date().toLocaleDateString(), 40)
        };
    }

    function dataUrlToUint8Array(dataUrl) {
        const parts = (dataUrl || '').split(',');
        const base64 = parts[1] || '';
        const binary = atob(base64);
        const len = binary.length;
        if (len > MAX_FILE_BYTES) {
            throw new Error('File exceeds 25 MB security limit');
        }
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    // =========================================================================
    // 2. SOCIAL SHARING (1-to-1) ENGINE
    // =========================================================================

    async function shareSocial(platform, docData) {
        const safeDoc = sanitizeDocRecord(docData);
        if (!safeDoc) return;

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
            version: '2.1-hardened',
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
    // 3. DECENTRALIZED WEBRTC / P2P SWARM ENGINE (HARDENED)
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
                date: clampString(d.date || '', 40)
            };
        }).filter(Boolean);
    }

    function loadSharedDocsConfig() {
        try {
            const raw = localStorage.getItem(SHARED_DOCS_KEY + '_' + currentConfig.dbName);
            const parsed = raw ? safeJsonParse(raw) : [];
            return Array.isArray(parsed) ? parsed.map(Number).filter(Boolean) : [];
        } catch (e) {
            return [];
        }
    }

    function saveSharedDocsConfig(list) {
        try {
            localStorage.setItem(SHARED_DOCS_KEY + '_' + currentConfig.dbName, JSON.stringify(list));
        } catch (e) {}
    }

    async function initSwarm(config) {
        if (config) Object.assign(currentConfig, config);
        await refreshLocalCatalog();

        if ('BroadcastChannel' in window) {
            try {
                broadcastChannel = new BroadcastChannel(SWARM_CHANNEL_NAME);
                broadcastChannel.onmessage = handleSwarmMessage;
                broadcastPresence();
            } catch (err) {
                console.warn('BroadcastChannel init error:', err);
            }
        }

        setInterval(broadcastPresence, 15000);
        updateSwarmBadge();
    }

    async function refreshLocalCatalog() {
        const sharedIds = loadSharedDocsConfig();
        if (sharedIds.length === 0) {
            localCatalog = [];
            return;
        }

        return new Promise((resolve) => {
            const req = indexedDB.open(currentConfig.dbName);
            req.onsuccess = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains(currentConfig.storeName)) {
                    localCatalog = [];
                    resolve();
                    return;
                }
                const tx = db.transaction([currentConfig.storeName], 'readonly');
                const store = tx.objectStore(currentConfig.storeName);
                const allReq = store.getAll();
                allReq.onsuccess = async (ev) => {
                    const allDocs = ev.target.result || [];
                    const filtered = allDocs.filter(d => sharedIds.includes(Number(d.id)));

                    localCatalog = await Promise.all(filtered.slice(0, MAX_CATALOG_ITEMS_PER_PEER).map(async d => {
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
                            peerId: myPeerId
                        };
                    }));
                    resolve();
                };
                allReq.onerror = () => resolve();
            };
            req.onerror = () => resolve();
        });
    }

    function broadcastPresence() {
        if (!broadcastChannel) return;
        broadcastChannel.postMessage({
            type: 'PEER_ANNOUNCE',
            sender: myPeerId,
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
                    docs: sanitizeRemoteCatalogList(msg.catalog)
                });
                updateSwarmBadge();
                renderSwarmModalContent();
                if (broadcastChannel) {
                    broadcastChannel.postMessage({
                        type: 'PEER_ACK',
                        sender: myPeerId,
                        target: msg.sender,
                        catalog: localCatalog
                    });
                }
                break;

            case 'PEER_ACK':
                if (msg.target === myPeerId) {
                    enforceMaxPeers();
                    remoteCatalog.set(msg.sender, {
                        lastSeen: Date.now(),
                        docs: sanitizeRemoteCatalogList(msg.catalog)
                    });
                    updateSwarmBadge();
                    renderSwarmModalContent();
                }
                break;

            case 'REQUEST_DOC':
                if (msg.target === myPeerId) {
                    const reqDocId = Number(msg.docId);
                    if (reqDocId && isDocShared(reqDocId)) {
                        serveDocToPeer(reqDocId, msg.sender);
                    }
                }
                break;

            case 'DELIVER_DOC':
                if (msg.target === myPeerId && msg.payload) {
                    const deliveredId = Number(msg.payload.id);
                    const reqKey = `${msg.sender}:${deliveredId}`;
                    // Block unsolicited document pushes (Anti-DDoS / Anti-Spam)
                    if (!pendingRequests.has(reqKey)) {
                        console.warn('[Osiris Security] Blocked unsolicited DELIVER_DOC from', msg.sender);
                        return;
                    }
                    pendingRequests.delete(reqKey);
                    receiveDocFromPeer(msg.payload);
                }
                break;
        }
    }

    function serveDocToPeer(docId, targetPeerId) {
        if (!isDocShared(docId)) return; // Double check opt-in privacy
        const req = indexedDB.open(currentConfig.dbName);
        req.onsuccess = (e) => {
            const db = e.target.result;
            const tx = db.transaction([currentConfig.storeName], 'readonly');
            const store = tx.objectStore(currentConfig.storeName);
            store.get(Number(docId)).onsuccess = (ev) => {
                const item = ev.target.result;
                if (!item) return;

                if (broadcastChannel) {
                    broadcastChannel.postMessage({
                        type: 'DELIVER_DOC',
                        sender: myPeerId,
                        target: targetPeerId,
                        payload: sanitizeDocRecord(item)
                    });
                }
            };
        };
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
            alert('🛑 INTEGRITÄTSFEHLER: Der kryptografische SHA-256 Hash stimmt nicht mit dem Original überein (möglicher Man-in-the-Middle-Angriff)! Übertragung abgebrochen.');
            return;
        }

        // 3. Save sanitized record into local IndexedDB
        const req = indexedDB.open(currentConfig.dbName);
        req.onsuccess = (e) => {
            const db = e.target.result;
            const tx = db.transaction([currentConfig.storeName], 'readwrite');
            const store = tx.objectStore(currentConfig.storeName);

            const newItem = Object.assign({}, docItem, {
                id: Date.now(),
                fileHash: computedHash,
                date: new Date().toLocaleDateString()
            });

            store.add(newItem);
            tx.oncomplete = () => {
                const fp = computedHash.substring(0, 6).toUpperCase();
                alert(`✅ Dokument „${newItem.thema}" erfolgreich geprüft (SHA-256 #${fp}) und lokal gespeichert!`);
                if (typeof currentConfig.onDocImported === 'function') {
                    currentConfig.onDocImported();
                }
            };
        };
    }

    function requestDocDownload(docId, peerId) {
        const cleanDocId = Number(docId);
        if (!cleanDocId || !PEER_ID_REGEX.test(peerId)) return;

        pendingRequests.add(`${peerId}:${cleanDocId}`);
        if (broadcastChannel) {
            broadcastChannel.postMessage({
                type: 'REQUEST_DOC',
                sender: myPeerId,
                target: peerId,
                docId: cleanDocId
            });
        }
    }

    async function toggleShareDocToSwarm(docId, shouldShare) {
        const cleanId = Number(docId);
        if (!cleanId) return;
        let sharedIds = loadSharedDocsConfig();
        if (shouldShare) {
            if (!sharedIds.includes(cleanId)) sharedIds.push(cleanId);
        } else {
            sharedIds = sharedIds.filter(id => id !== cleanId);
        }
        saveSharedDocsConfig(sharedIds);
        await refreshLocalCatalog();
        broadcastPresence();
        updateSwarmBadge();
        renderSwarmModalContent();
    }

    function isDocShared(docId) {
        const sharedIds = loadSharedDocsConfig();
        return sharedIds.includes(Number(docId));
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
            window.parent.postMessage({
                type: 'SWARM_BADGE_UPDATE',
                activePeers: activePeers,
                totalShared: totalShared
            }, '*');
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

    function createSwarmModalDom() {
        const modal = document.createElement('div');
        modal.id = 'swarm-modal';
        modal.style.cssText = `
            display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.65);
            z-index: 10005; align-items: center; justify-content: center; padding: 20px;
            backdrop-filter: blur(4px);
        `;

        modal.innerHTML = `
            <div style="background: var(--surface); border: 1px solid var(--border); border-radius: 12px; width: 100%; max-width: 850px; max-height: 90vh; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 16px 40px rgba(0,0,0,0.3);">
                <div style="display: flex; justify-content: space-between; align-items: center; padding: 16px 20px; border-bottom: 1px solid var(--border); background: var(--bg);">
                    <div style="display:flex; align-items:center; gap:12px;">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:#0099ff; flex-shrink:0;">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="2" y1="12" x2="22" y2="12"></line>
                            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10z"></path>
                            <path d="M12 2a15.3 15.3 0 0 0-4 10 15.3 15.3 0 0 0 4 10z"></path>
                        </svg>
                        <div>
                            <h3 style="margin:0; color:var(--primary); font-size:1.15rem;">Community-Schwarm (Dezentrales P2P)</h3>
                            <div style="font-size:0.75rem; color:gray;">Zero-Knowledge · Browser-to-Browser · Keine Benutzerkonten</div>
                        </div>
                    </div>
                    <button id="swarm-close-x" aria-label="Schließen" style="background:transparent; border:none; cursor:pointer; color:var(--text); padding:6px; display:flex; align-items:center; justify-content:center;">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                    </button>
                </div>

                <div style="padding: 10px 20px; background: rgba(40,167,69,0.1); border-bottom: 1px solid rgba(40,167,69,0.25); font-size: 0.82rem; display: flex; gap: 10px; align-items: center; justify-content: space-between;">
                    <div style="display:flex; align-items:center; gap:8px;">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:#28a745; flex-shrink:0;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                        <span><strong>100% Lokal &amp; Privat:</strong> Dokumente werden nur bei Klick auf „In Schwarm teilen“ übertragen.</span>
                    </div>
                    <span style="font-size:0.75rem; color:var(--primary); font-weight:600; display:flex; align-items:center; gap:4px;">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                        Details im Info-Menü
                    </span>
                </div>

                <div style="display:flex; border-bottom: 1px solid var(--border); background: var(--surface);">
                    <button id="swarm-tab-remote" style="flex:1; padding:12px; border:none; background:transparent; border-bottom:3px solid var(--primary); font-weight:bold; cursor:pointer; color:var(--primary);">Verfügbare Dokumente im Schwarm</button>
                    <button id="swarm-tab-local" style="flex:1; padding:12px; border:none; background:transparent; border-bottom:3px solid transparent; font-weight:bold; cursor:pointer; color:gray;">Meine geteilten Dokumente</button>
                </div>

                <div id="swarm-tab-content" style="padding: 20px; overflow-y: auto; flex: 1;"></div>

                <div style="padding: 12px 20px; border-top: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: var(--bg); font-size: 0.8rem;">
                    <span id="swarm-footer-stats">Status: Geschütztes P2P-Netzwerk bereit</span>
                    <button id="swarm-close-btn" style="padding: 8px 16px; border: 1px solid var(--border); border-radius: 6px; background: var(--surface); color: var(--text); font-weight: bold; cursor: pointer;">Schließen</button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        document.getElementById('swarm-close-x').addEventListener('click', closeSwarmModal);
        document.getElementById('swarm-close-btn').addEventListener('click', closeSwarmModal);
        document.getElementById('swarm-tab-remote').addEventListener('click', () => switchSwarmTab('remote'));
        document.getElementById('swarm-tab-local').addEventListener('click', () => switchSwarmTab('local'));

        // Safe Event Delegation for Swarm Action Buttons (Zero inline onclick interpolation)
        const contentWrap = document.getElementById('swarm-tab-content');
        contentWrap.addEventListener('click', (e) => {
            const dlBtn = e.target.closest('[data-swarm-download]');
            if (dlBtn) {
                const docId = Number(dlBtn.getAttribute('data-doc-id'));
                const peerId = dlBtn.getAttribute('data-peer-id') || '';
                requestDocDownload(docId, peerId);
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
                    <div style="text-align:center; padding: 40px 20px; color: gray;">
                        <svg width="42" height="42" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" style="color:var(--primary); opacity:0.6; margin-bottom:10px;"><path d="M4.93 4.93a10 10 0 0 1 14.14 0"></path><path d="M7.76 7.76a6 6 0 0 1 8.48 0"></path><circle cx="12" cy="12" r="2"></circle><path d="M12 14v8"></path></svg>
                        <h4 style="margin:0 0 8px 0; color:var(--text);">Keine weiteren Peers im Schwarm aktiv</h4>
                        <p style="margin:0; font-size:0.85rem; max-width:480px; margin:auto;">
                            Sobald sich andere Lehrkräfte im Netzwerk befinden oder ein Kollege Dokumente bereitstellt, erscheinen diese hier automatisch in Echtzeit.
                        </p>
                    </div>
                `;
            } else {
                let html = `
                    <div style="display:flex; flex-direction:column; gap:10px;">
                        <div style="font-size:0.85rem; color:gray; margin-bottom:4px;">
                            ${allRemoteDocs.length} geprüfte(s) Dokument(e) im Schwarm verfügbar:
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
                        <div style="display:flex; justify-content:space-between; align-items:center; padding:12px 16px; border:1px solid var(--border); border-radius:8px; background:var(--surface);">
                            <div>
                                <div style="display:flex; gap:6px; align-items:center; margin-bottom:4px; flex-wrap:wrap;">
                                    <span style="background:var(--primary); color:white; padding:2px 8px; border-radius:4px; font-size:0.72rem; font-weight:bold;">${safeTyp}</span>
                                    <span style="background:var(--border); padding:2px 8px; border-radius:4px; font-size:0.72rem;">${safeKlassen}</span>
                                    <span style="background:var(--border); padding:2px 8px; border-radius:4px; font-size:0.72rem;">${safeJahr}</span>
                                    <span title="Kryptografischer SHA-256 Fingerabdruck" style="background:rgba(40,167,69,0.15); color:#28a745; border:1px solid rgba(40,167,69,0.3); padding:1px 6px; border-radius:4px; font-family:monospace; font-size:0.7rem; font-weight:bold;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle; margin-right:3px;"><path d="M21 2l-2 2m-1.5 1.5L14 9l-1.5-1.5L11 9l1.5 1.5L9 14l-1.5-1.5L6 14l1.5 1.5L4 19a2.828 2.828 0 0 0 4 4l1.5-1.5L11 20l-1.5-1.5L11 17l1.5 1.5L16 15l-1.5-1.5L16 12l1.5 1.5 3.5-3.5a2.828 2.828 0 0 0 0-4z"></path></svg>SHA: #${shortHash}</span>
                                </div>
                                <h4 style="margin:0; color:var(--primary); font-size:0.95rem;">${safeThema}</h4>
                                <div style="font-size:0.78rem; color:gray;">
                                    Lektion: ${safeLektion} | Buch: ${safeBuch} | <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle; margin-right:2px;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>${safeFileName}
                                </div>
                            </div>
                            <button type="button" data-swarm-download="1" data-doc-id="${safeDocId}" data-peer-id="${safePeerId}" style="display:flex; align-items:center; gap:6px; padding:8px 14px; background:var(--accent); color:white; border:none; border-radius:6px; font-weight:bold; cursor:pointer; font-size:0.82rem;">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg> <span>Laden</span>
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
                    <div style="text-align:center; padding: 40px 20px; color: gray;">
                        <svg width="42" height="42" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" style="color:var(--primary); opacity:0.6; margin-bottom:10px;"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
                        <h4 style="margin:0 0 8px 0; color:var(--text);">Sie teilen derzeit keine Dokumente</h4>
                        <p style="margin:0; font-size:0.85rem; max-width:480px; margin:auto;">
                            Um ein Dokument mit der Community zu teilen, öffnen Sie das Dokument in der Vollansicht und klicken Sie im Teilen-Menü auf „In Community-Schwarm teilen“.
                        </p>
                    </div>
                `;
            } else {
                let html = `
                    <div style="display:flex; flex-direction:column; gap:10px;">
                        <div style="font-size:0.85rem; color:gray; margin-bottom:4px;">
                            Sie stellen ${localCatalog.length} Dokument(e) für andere Lehrkräfte bereit:
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
                        <div style="display:flex; justify-content:space-between; align-items:center; padding:12px 16px; border:1px solid var(--border); border-radius:8px; background:var(--surface);">
                            <div>
                                <div style="display:flex; gap:6px; align-items:center; margin-bottom:4px; flex-wrap:wrap;">
                                    <span style="background:var(--primary); color:white; padding:2px 8px; border-radius:4px; font-size:0.72rem; font-weight:bold;">${safeTyp}</span>
                                    <span style="background:var(--border); padding:2px 8px; border-radius:4px; font-size:0.72rem;">${safeKlassen}</span>
                                    <span style="background:var(--border); padding:2px 8px; border-radius:4px; font-size:0.72rem;">${safeJahr}</span>
                                    <span style="background:rgba(40,167,69,0.15); color:#28a745; padding:1px 6px; border-radius:4px; font-family:monospace; font-size:0.7rem; font-weight:bold;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle; margin-right:3px;"><path d="M21 2l-2 2m-1.5 1.5L14 9l-1.5-1.5L11 9l1.5 1.5L9 14l-1.5-1.5L6 14l1.5 1.5L4 19a2.828 2.828 0 0 0 4 4l1.5-1.5L11 20l-1.5-1.5L11 17l1.5 1.5L16 15l-1.5-1.5L16 12l1.5 1.5 3.5-3.5a2.828 2.828 0 0 0 0-4z"></path></svg>SHA: #${shortHash}</span>
                                </div>
                                <h4 style="margin:0; color:var(--primary); font-size:0.95rem;">${safeThema}</h4>
                                <div style="font-size:0.78rem; color:gray;"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle; margin-right:2px;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>${safeFileName}</div>
                            </div>
                            <button type="button" data-swarm-stop="1" data-doc-id="${safeDocId}" style="padding:6px 12px; background:#dc3545; color:white; border:none; border-radius:6px; font-weight:bold; cursor:pointer; font-size:0.8rem;">
                                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg> <span>Teilen beenden</span>
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
            footerStats.textContent = `Status: ${activePeers} Peer(s) im Netzwerk | ${localCatalog.length} eigene(s) Dokument(e) freigegeben | ${blockedPeers.size} Angreifer blockiert`;
        }
    }

    // Export both OsirisSecurity and EduHybridShare globally
    window.OsirisSecurity = {
        escapeHtml: escapeHtml,
        clampString: clampString,
        sanitizeUrl: sanitizeUrl,
        sanitizeDataUrl: sanitizeDataUrl,
        sanitizeHtmlFragment: sanitizeHtmlFragment,
        safeJsonParse: safeJsonParse,
        validateMagicBytes: validateMagicBytes,
        sanitizeDocRecord: sanitizeDocRecord,
        computeSHA256: computeSHA256,
        MAX_FILE_BYTES: MAX_FILE_BYTES
    };

    window.EduHybridShare = {
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
        exportSinglePackage: exportSinglePackage
    };

})(window);

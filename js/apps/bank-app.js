    let links = JSON.parse(localStorage.getItem('wiki_links')) || [];
    let idb;
    function escapeHtml(val) {
        if (window.OsirisSecurity) return window.OsirisSecurity.escapeHtml(val);
        if (val === null || val === undefined) return '';
        return String(val)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;')
            .replace(/`/g, '&#96;');
    }
    function sanitizeUrl(url) {
        if (window.OsirisSecurity) return window.OsirisSecurity.sanitizeUrl(url);
        if (!url || typeof url !== 'string') return '#';
        try {
            const parsed = new URL(url.trim(), window.location.origin);
            if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
                return parsed.href.replace(/"/g, '%22').replace(/'/g, '%27');
            }
        } catch (e) {}
        return '#';
    }
    function sanitizeDataUrl(dataUrl) {
        if (window.OsirisSecurity) return window.OsirisSecurity.sanitizeDataUrl(dataUrl);
        if (!dataUrl || typeof dataUrl !== 'string') return '';
        const t = dataUrl.trim();
        return /^data:(application\/(pdf|msword|vnd\.openxmlformats|octet-stream)|image\/(png|jpeg|jpg|webp|gif)|text\/plain|video\/|audio\/)[^,]*;base64,/i.test(t) ? t : '';
    }
    function sanitizeHtmlFragment(dirtyHtml) {
        if (window.OsirisSecurity) return window.OsirisSecurity.sanitizeHtmlFragment(dirtyHtml);
        return escapeHtml(dirtyHtml);
    }
    function safeJsonParse(raw) {
        if (window.OsirisSecurity) return window.OsirisSecurity.safeJsonParse(raw);
        return JSON.parse(raw, (k, v) => (k === '__proto__' || k === 'constructor' || k === 'prototype') ? undefined : v);
    }

    // --- Predictive Dictionary ---
    function saveToDictionary(field, value) {
        if (!value || !value.trim()) return;
        const key = 'wiki_dict_' + field;
        const dict = JSON.parse(localStorage.getItem(key)) || [];
        const normalized = value.trim();
        if (!dict.some(d => d.toLowerCase() === normalized.toLowerCase())) {
            dict.push(normalized);
            dict.sort((a, b) => a.localeCompare(b));
            localStorage.setItem(key, JSON.stringify(dict));
        }
        refreshDatalist(field);
    }

    function refreshDatalist(field) {
        const dl = document.getElementById('dict-' + field);
        if (!dl) return;
        const dict = JSON.parse(localStorage.getItem('wiki_dict_' + field)) || [];
        dl.innerHTML = dict.map(term => `<option value="${escapeHtml(term)}"></option>`).join('');
    }

    function seedDictionaryFromDB() {
        if (!idb) return;
        const tx = idb.transaction(["documents"], "readonly");
        tx.objectStore("documents").getAll().onsuccess = (e) => {
            e.target.result.forEach(item => {
                ['thema', 'lektion', 'buch'].forEach(field => {
                    if (item[field]) saveToDictionary(field, item[field]);
                });
            });
        };
    }

    // --- Reset Filters ---
    function resetFilters() {
        document.getElementById('filter-jahr').value = '';
        document.getElementById('filter-klassen').value = '';
        document.getElementById('filter-thema').value = '';
        document.getElementById('filter-typ').value = '';
        document.getElementById('toggle-filters-cb').checked = false;
        document.getElementById('filters-bar').style.display = 'none';
        renderResults();
    }

    // --- IndexedDB Initialization ---
    const request = indexedDB.open("TestBankDB", 1);
    request.onupgradeneeded = (e) => {
        idb = e.target.result;
        if (!idb.objectStoreNames.contains("documents")) {
            idb.createObjectStore("documents", { keyPath: "id" });
        }
    };
    request.onsuccess = (e) => {
        idb = e.target.result;
        renderResults();
        seedDictionaryFromDB();
    };
    request.onerror = (e) => { console.error("IndexedDB error:", e); };

    function resetImportForm() {
        window.editingId = null;
        document.querySelector('#import-submenu h2').innerHTML = `<svg width="20" height="20" style="vertical-align: middle;" viewBox="0 0 24 24" fill="currentColor"><path d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z"/></svg> Prüfungsstoff hinzufügen`;
        document.getElementById('save-entry-text').textContent = 'SPEICHERN';

        document.getElementById('inp-thema').value = '';
        document.getElementById('inp-lektion').value = '';
        document.getElementById('inp-buch').value = '';
        document.getElementById('inp-klassen').selectedIndex = 0;
        document.getElementById('inp-klassen-other').value = '';
        document.getElementById('inp-klassen-other').style.display = 'none';
        document.getElementById('inp-jahr').value = '2000';
        document.getElementById('inp-typ').value = '';
        document.getElementById('inp-typ-other').value = '';
        document.getElementById('inp-file').value = '';
        window.duplicateBlocked = false;
        delete document.getElementById('inp-file').dataset.fileHash;
        const dupStatus = document.getElementById('file-dup-status');
        if (dupStatus) { dupStatus.style.display = 'none'; dupStatus.innerHTML = ''; }
        setSaveBtnEnabled(true);
        checkTyp();
        checkKlassen();
    }

    function cancelImport() {
        resetImportForm();
        document.getElementById('import-submenu').classList.remove('open');
    }

    function toggleImport(e) {
        if(e) e.stopPropagation();
        const submenu = document.getElementById('import-submenu');
        const opening = !submenu.classList.contains('open');
        // The toolbar "add new document" button should always start from a clean
        // form — previously, closing a stale/cancelled edit left old data and
        // window.editingId behind, so reopening via this button could silently
        // resume editing someone else's entry instead of creating a new one.
        if (opening) resetImportForm();
        submenu.classList.toggle('open');
    }

    function checkKlassen() {
        const klassen = document.getElementById('inp-klassen').value;
        const otherInput = document.getElementById('inp-klassen-other');
        if (klassen === 'Sonstiges') {
            otherInput.style.display = 'block';
            setTimeout(() => { otherInput.style.opacity = '1'; }, 10); // Smooth fade-in
        } else {
            otherInput.style.display = 'none';
            otherInput.style.opacity = '0';
        }
    }

    function checkTyp() {
        const typ = document.getElementById('inp-typ').value;
        const subMenuPruefung = document.getElementById('sub-pruefung');
        const subMenuKontrolle = document.getElementById('sub-kontrolle');
        const typOther = document.getElementById('inp-typ-other');
        
        subMenuPruefung.style.display = 'none';
        subMenuKontrolle.style.display = 'none';
        typOther.style.display = 'none';

        // FIX: Explicitly disable and clear sub-text inputs to prevent data leak
        document.querySelectorAll('.sub-cb').forEach(cb => cb.checked = false);
        document.getElementById('pruefung-other-text').disabled = true;
        document.getElementById('pruefung-other-text').value = '';
        document.getElementById('kontrolle-other-text').disabled = true;
        document.getElementById('kontrolle-other-text').value = '';

        if (typ === 'PROBEPRÜFUNG' || typ === 'PRÜFUNG') {
            subMenuPruefung.style.display = 'block';
        } else if (typ === 'KONTROLLE') {
            subMenuKontrolle.style.display = 'block';
        } else if (typ === 'SONSTIGES') {
            typOther.style.display = 'block';
        }
    }

    // --- Metadata Injector: detect already-uploaded files and auto-fill the form ---

    async function computeFileHash(file) {
        try {
            const buffer = await file.arrayBuffer();
            const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
            return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
        } catch (err) {
            console.error('Hash-Berechnung fehlgeschlagen:', err);
            return null;
        }
    }

    function findMatchingEntry(file, hash) {
        return new Promise((resolve) => {
            if (!idb) { resolve(null); return; }
            const tx = idb.transaction(["documents"], "readonly");
            tx.objectStore("documents").getAll().onsuccess = (e) => {
                const items = (e.target.result || []).filter(it => it.id !== window.editingId);
                // 1) Strongest signal: identical content hash
                let match = hash ? items.find(it => it.fileHash && it.fileHash === hash) : null;
                // 2) Fallback for legacy entries saved before hashing existed: name + size
                if (!match) {
                    match = items.find(it => it.fileName === file.name && it.fileSize === file.size);
                }
                resolve(match || null);
            };
            tx.onerror = () => resolve(null);
        });
    }

    function applyMetadataFromEntry(item) {
        document.getElementById('inp-thema').value = item.thema || '';
        document.getElementById('inp-lektion').value = item.lektion || '';
        document.getElementById('inp-buch').value = item.buch || '';

        const klassSelect = document.getElementById('inp-klassen');
        const klassOther = document.getElementById('inp-klassen-other');
        const standardKlassen = Array.from(klassSelect.options).map(o => o.value);
        if (standardKlassen.includes(item.klassen)) {
            klassSelect.value = item.klassen;
            klassOther.style.display = 'none';
            klassOther.value = '';
        } else {
            klassSelect.value = 'Sonstiges';
            klassOther.style.display = 'block';
            klassOther.value = item.klassen || '';
        }

        document.getElementById('inp-jahr').value = item.jahr || '2000';

        const typSelect = document.getElementById('inp-typ');
        const standardTypen = Array.from(typSelect.options).map(o => o.value).filter(v => v);
        const typIsStandard = standardTypen.includes(item.typ);
        typSelect.value = typIsStandard ? item.typ : 'SONSTIGES';
        checkTyp(); // resets sub-panels/checkboxes, then shows the right one for this typ

        if (!typIsStandard) {
            document.getElementById('inp-typ-other').value = item.typ || '';
        }

        if (item.subTyp && item.subTyp.length > 0) {
            const standardValues = Array.from(document.querySelectorAll('.sub-cb')).map(cb => cb.value);
            document.querySelectorAll('.sub-cb').forEach(cb => {
                if (item.subTyp.includes(cb.value)) cb.checked = true;
            });
            const customValues = item.subTyp.filter(v => !standardValues.includes(v));
            if (customValues.length > 0) {
                if (item.typ === 'PROBEPRÜFUNG' || item.typ === 'PRÜFUNG') {
                    const cb = document.querySelector('#sub-pruefung input[value="SONSTIGES"]');
                    if (cb) { cb.checked = true; toggleOtherInput(cb, 'pruefung-other-text'); document.getElementById('pruefung-other-text').value = customValues[0]; }
                } else if (item.typ === 'KONTROLLE') {
                    const cb = document.querySelector('#sub-kontrolle input[value="SONSTIGES"]');
                    if (cb) { cb.checked = true; toggleOtherInput(cb, 'kontrolle-other-text'); document.getElementById('kontrolle-other-text').value = customValues[0]; }
                }
            }
        }

        saveToDictionary('thema', item.thema);
        saveToDictionary('lektion', item.lektion);
        saveToDictionary('buch', item.buch);
    }

    // --- Persistent in-file metadata: embed Info-box data directly into the
    // PDF/DOCX bytes on save, so the data travels with the file itself (e.g.
    // when handed to someone else) instead of only living in this browser's
    // IndexedDB. Marker wrapper: { app: 'OsirisMeineBank', v: 1, data: {...} } ---

    const OSIRIS_META_KEY = 'OsirisMeineBank';

    function dataUrlToBytes(dataUrl) {
        const base64 = dataUrl.split(',')[1] || '';
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes;
    }

    function bytesToDataUrl(bytes, mimeType) {
        let binary = '';
        const chunkSize = 0x8000;
        for (let i = 0; i < bytes.length; i += chunkSize) {
            binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
        }
        return `data:${mimeType};base64,${btoa(binary)}`;
    }

    function buildMetaPayload(meta) {
        return JSON.stringify({ app: 'OsirisMeineBank', v: 1, data: meta });
    }

    function parseMetaPayload(raw) {
        try {
            const parsed = JSON.parse(raw);
            if (parsed && parsed.app === 'OsirisMeineBank' && parsed.data) return parsed.data;
        } catch (err) { /* not our payload, or corrupted — ignore */ }
        return null;
    }

    async function embedMetadataIntoPdf(dataUrl, meta) {
        await window.OSIRIS_LIBS_READY;
        if (typeof PDFLib === 'undefined') return dataUrl; // library missing — skip silently
        try {
            const bytes = dataUrlToBytes(dataUrl);
            const pdfDoc = await PDFLib.PDFDocument.load(bytes, { updateMetadata: false, ignoreEncryption: true });
            // Calling a standard setter first guarantees pdf-lib creates the Info
            // dictionary if the PDF didn't already have one.
            pdfDoc.setProducer('Osiris Inc. – MeineBank');
            pdfDoc.setModificationDate(new Date());
            const infoDict = pdfDoc.context.lookup(pdfDoc.context.trailerInfo.Info);
            infoDict.set(PDFLib.PDFName.of(OSIRIS_META_KEY), PDFLib.PDFHexString.fromText(buildMetaPayload(meta)));
            const outBytes = await pdfDoc.save();
            return bytesToDataUrl(outBytes, 'application/pdf');
        } catch (err) {
            console.error('PDF-Metadaten-Einbettung fehlgeschlagen, Original wird gespeichert:', err);
            return dataUrl;
        }
    }

    async function embedMetadataIntoDocx(dataUrl, meta, mimeType) {
        await window.OSIRIS_LIBS_READY;
        if (typeof JSZip === 'undefined') return dataUrl; // library missing — skip silently
        try {
            const bytes = dataUrlToBytes(dataUrl);
            const zip = await JSZip.loadAsync(bytes);
            const escaped = buildMetaPayload(meta)
                .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

            const customEntry = zip.file('docProps/custom.xml');
            let propsInner = '';
            let pid = 2;
            if (customEntry) {
                const existingXml = await customEntry.async('string');
                const doc = new DOMParser().parseFromString(existingXml, 'application/xml');
                const props = Array.from(doc.getElementsByTagName('property'));
                const kept = props.filter(p => p.getAttribute('name') !== OSIRIS_META_KEY);
                pid = kept.reduce((max, p) => Math.max(max, parseInt(p.getAttribute('pid'), 10) || 0), 1) + 1;
                propsInner = kept.map(p => new XMLSerializer().serializeToString(p)).join('');
            }
            propsInner += `<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="${pid}" name="${OSIRIS_META_KEY}"><vt:lpwstr>${escaped}</vt:lpwstr></property>`;
            const newCustomXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">${propsInner}</Properties>`;
            zip.file('docProps/custom.xml', newCustomXml);

            const ctPath = '[Content_Types].xml';
            const ctEntry = zip.file(ctPath);
            if (ctEntry) {
                let ctXml = await ctEntry.async('string');
                if (!ctXml.includes('docProps/custom.xml')) {
                    ctXml = ctXml.replace('</Types>', '<Override PartName="/docProps/custom.xml" ContentType="application/vnd.openxmlformats-officedocument.custom-properties+xml"/></Types>');
                    zip.file(ctPath, ctXml);
                }
            }

            const relsPath = '_rels/.rels';
            const relsEntry = zip.file(relsPath);
            if (relsEntry) {
                let relsXml = await relsEntry.async('string');
                if (!relsXml.includes('docProps/custom.xml')) {
                    const relIds = Array.from(relsXml.matchAll(/Id="rId(\d+)"/g)).map(m => parseInt(m[1], 10));
                    const nextRelId = (relIds.length ? Math.max(...relIds) : 0) + 1;
                    relsXml = relsXml.replace('</Relationships>', `<Relationship Id="rId${nextRelId}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties" Target="docProps/custom.xml"/></Relationships>`);
                    zip.file(relsPath, relsXml);
                }
            }

            const outBytes = await zip.generateAsync({ type: 'uint8array' });
            return bytesToDataUrl(outBytes, mimeType || 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
        } catch (err) {
            console.error('DOCX-Metadaten-Einbettung fehlgeschlagen, Original wird gespeichert:', err);
            return dataUrl;
        }
    }

    // isPdfFile/isDocxFile mirror the detection already used for previews further down.
    function isPdfFile(name, type) {
        return (type && type.includes('pdf')) || name.toLowerCase().endsWith('.pdf');
    }
    function isDocxFile(name, type) {
        return (type && type.includes('wordprocessingml')) || name.toLowerCase().endsWith('.docx');
    }

    async function embedMetadataIfApplicable(dataUrl, meta, fileName, fileType) {
        try {
            if (isPdfFile(fileName, fileType)) return await embedMetadataIntoPdf(dataUrl, meta);
            if (isDocxFile(fileName, fileType)) return await embedMetadataIntoDocx(dataUrl, meta, fileType);
        } catch (err) {
            console.error('Metadaten-Einbettung übersprungen:', err);
        }
        return dataUrl;
    }

    async function readEmbeddedMetaFromPdf(file) {
        await window.OSIRIS_LIBS_READY;
        const pdfjsLib = window['pdfjs-dist/build/pdf'] || window.pdfjsLib;
        if (!pdfjsLib) return null;
        const buffer = await file.arrayBuffer();
        pdfjsLib.GlobalWorkerOptions.workerSrc = 'pdf.worker.min.js';
        const loadingTask = pdfjsLib.getDocument({ data: buffer, isEvalSupported: false });
        const pdf = await loadingTask.promise;
        const metadata = await pdf.getMetadata();
        const raw = metadata && metadata.info && metadata.info[OSIRIS_META_KEY];
        return raw ? parseMetaPayload(raw) : null;
    }

    async function readEmbeddedMetaFromDocx(file) {
        await window.OSIRIS_LIBS_READY;
        if (typeof JSZip === 'undefined') return null;
        const buffer = await file.arrayBuffer();
        const zip = await JSZip.loadAsync(buffer);
        const customEntry = zip.file('docProps/custom.xml');
        if (!customEntry) return null;
        const xmlText = await customEntry.async('string');
        const doc = new DOMParser().parseFromString(xmlText, 'application/xml');
        const props = Array.from(doc.getElementsByTagName('property'));
        const target = props.find(p => p.getAttribute('name') === OSIRIS_META_KEY);
        if (!target) return null;
        const lpwstr = target.getElementsByTagName('vt:lpwstr')[0] || target.getElementsByTagName('lpwstr')[0];
        if (!lpwstr) return null;
        return parseMetaPayload(lpwstr.textContent);
    }

    async function readEmbeddedMetaFromFile(file) {
        try {
            if (isPdfFile(file.name, file.type)) return await readEmbeddedMetaFromPdf(file);
            if (isDocxFile(file.name, file.type)) return await readEmbeddedMetaFromDocx(file);
        } catch (err) {
            console.error('Metadaten-Auslesen aus Datei fehlgeschlagen:', err);
        }
        return null;
    }

    function showEmbeddedMetadataNotice(statusEl, meta) {
        // Not a duplicate — this file just carries Osiris metadata from a
        // previous save (e.g. on another device). Saving stays allowed.
        window.duplicateBlocked = false;
        setSaveBtnEnabled(true);
        statusEl.style.display = 'flex';
        statusEl.style.flexDirection = 'column';
        statusEl.style.background = 'var(--highlight)';
        const label = meta.thema ? `„${escapeHtml(meta.thema)}"` : 'dieser Datei';
        statusEl.innerHTML = `
            <div style="display:flex; gap:8px; align-items:flex-start;">
                <span>📎</span>
                <span><strong>In der Datei gespeicherte Metadaten gefunden.</strong> Felder wurden automatisch aus ${label} übernommen — bitte vor dem Speichern prüfen.</span>
            </div>
            <div style="display:flex; gap:8px; margin-top:10px; flex-wrap:wrap;">
                <button type="button" onclick="hideDuplicateNotice(document.getElementById('file-dup-status'))" style="flex:1 1 auto; padding:8px 10px; border:1px solid var(--border); border-radius:5px; background:var(--surface); color:var(--text); font-weight:bold; cursor:pointer; font-size:0.8rem;">Verstanden</button>
            </div>
        `;
    }

    // Enforced hard block: an identical file already exists in the database.
    // The only ways forward are editing that entry or choosing a different
    // file — there is no "save it again anyway" path, so no duplicate can
    // be added.
    function showDuplicateNotice(statusEl, item) {
        window.duplicateBlocked = true;
        setSaveBtnEnabled(false);
        statusEl.style.display = 'flex';
        statusEl.style.flexDirection = 'column';
        statusEl.style.background = 'var(--highlight)';
        const label = item.thema ? `„${escapeHtml(item.thema)}"` : 'einem vorhandenen Eintrag';
        const safeId = Number(item.id) || 0;
        statusEl.innerHTML = `
            <div style="display:flex; gap:8px; align-items:flex-start;">
                <span>🔁</span>
                <span><strong>Diese Datei ist bereits gespeichert</strong> (als ${label}). Um Duplikate zu vermeiden, kann sie nicht erneut hinzugefügt werden — bearbeiten Sie stattdessen den vorhandenen Eintrag oder wählen Sie eine andere Datei.</span>
            </div>
            <div style="display:flex; gap:8px; margin-top:10px; flex-wrap:wrap;">
                <button type="button" onclick="useExistingEntry(${safeId})" style="flex:1 1 auto; padding:8px 10px; border:none; border-radius:5px; background:var(--accent); color:white; font-weight:bold; cursor:pointer; font-size:0.8rem;">Vorhandenen Eintrag bearbeiten</button>
            </div>
        `;
    }

    function setSaveBtnEnabled(enabled) {
        const saveBtn = document.getElementById('save-entry-btn');
        if (!saveBtn) return;
        saveBtn.disabled = !enabled;
        saveBtn.style.opacity = enabled ? '1' : '0.55';
        saveBtn.style.cursor = enabled ? 'pointer' : 'not-allowed';
        saveBtn.style.pointerEvents = enabled ? 'auto' : 'none';
    }

    function useExistingEntry(id) {
        window.duplicateBlocked = false;
        setSaveBtnEnabled(true);
        hideDuplicateNotice(document.getElementById('file-dup-status'));
        editEntry(id); // loads full entry into the form and switches to update mode
    }

    function showCheckingNotice(statusEl) {
        statusEl.style.display = 'flex';
        statusEl.style.background = 'var(--bg)';
        statusEl.innerHTML = `⏳ Datei wird auf Duplikate geprüft...`;
    }

    function hideDuplicateNotice(statusEl) {
        statusEl.style.display = 'none';
        statusEl.innerHTML = '';
    }

    async function handleFileSelect(e) {
        const file = e.target.files[0];
        const statusEl = document.getElementById('file-dup-status');
        window.duplicateBlocked = false;
        setSaveBtnEnabled(true);
        delete e.target.dataset.fileHash;

        if (!file) { hideDuplicateNotice(statusEl); return; }
        if (!idb) return; // DB not ready yet, skip silently

        showCheckingNotice(statusEl);
        // Save stays disabled while we check, so a fast click can't slip a
        // duplicate through before the hash comparison finishes.
        setSaveBtnEnabled(false);
        try {
            const rawBuf = await file.arrayBuffer();
            if (window.OsirisSecurity) {
                const secCheck = window.OsirisSecurity.validateMagicBytes(new Uint8Array(rawBuf), file.name);
                if (!secCheck.valid) {
                    window.duplicateBlocked = true;
                    setSaveBtnEnabled(false);
                    statusEl.style.display = 'flex';
                    statusEl.style.background = 'rgba(220,53,69,0.12)';
                    statusEl.innerHTML = `<div style="color:#dc3545; font-weight:bold;">🛑 Sicherheitsblockade: ${escapeHtml(secCheck.reason)}</div>`;
                    e.target.value = '';
                    return;
                }
            }
        } catch (secErr) {
            console.error('Security check failed:', secErr);
        }

        const hash = await computeFileHash(file);
        // Stash the hash so saveEntry() can reuse it without re-reading the file
        if (hash) e.target.dataset.fileHash = hash;

        // Guard against the user swapping the file again before hashing finished
        if (e.target.files[0] !== file) return;

        const match = await findMatchingEntry(file, hash);
        if (match) {
            applyMetadataFromEntry(match);
            showDuplicateNotice(statusEl, match); // sets duplicateBlocked = true
            return;
        }

        // No local record of this file — check whether the file itself carries
        // Osiris metadata embedded during a previous save (e.g. on another device).
        setSaveBtnEnabled(true);
        const embeddedMeta = await readEmbeddedMetaFromFile(file);
        if (e.target.files[0] !== file) return; // guard again after async work
        if (embeddedMeta) {
            applyMetadataFromEntry(embeddedMeta);
            showEmbeddedMetadataNotice(statusEl, embeddedMeta);
        } else {
            hideDuplicateNotice(statusEl);
        }
    }

    document.getElementById('inp-file').addEventListener('change', handleFileSelect);

function saveEntry() {
        const thema = document.getElementById('inp-thema').value.trim();
        const lektion = document.getElementById('inp-lektion').value.trim();
        const buch = document.getElementById('inp-buch').value.trim();
        
        let klassen = document.getElementById('inp-klassen').value.trim();
        if (klassen === 'Sonstiges') {
            klassen = document.getElementById('inp-klassen-other').value.trim();
        }
        
        const jahr = document.getElementById('inp-jahr').value.trim();
        
        let typ = document.getElementById('inp-typ').value;
        if (typ === 'SONSTIGES') {
            typ = document.getElementById('inp-typ-other').value.trim();
        }

        const fileInput = document.getElementById('inp-file');

        if (!thema || !lektion || !buch || !klassen || !jahr || !typ || (fileInput.files.length === 0 && !window.editingId)) {
            alert("Bitte füllen Sie alle erforderlichen Felder aus und wählen Sie ein Dokument!");
            return;
        }

        // Hard stop: never persist a file that's already in the database.
        // This mirrors the async re-check below but catches the common case
        // immediately, without waiting on IndexedDB.
        if (window.duplicateBlocked && !window.editingId) {
            alert("Diese Datei ist bereits gespeichert. Bitte bearbeiten Sie den vorhandenen Eintrag, anstatt sie erneut hinzuzufügen.");
            return;
        }

        let subTyp = [];
        if (typ === 'PROBEPRÜFUNG' || typ === 'PRÜFUNG') {
            document.querySelectorAll('#sub-pruefung .sub-cb:checked').forEach(cb => {
                if(cb.value === 'SONSTIGES') {
                    const txt = document.getElementById('pruefung-other-text').value.trim();
                    subTyp.push(txt || 'SONSTIGES');
                } else {
                    subTyp.push(cb.value);
                }
            });
            if (subTyp.length === 0) { alert("Bitte wählen Sie einen Typ!"); return; }
        } else if (typ === 'KONTROLLE') {
            document.querySelectorAll('#sub-kontrolle .sub-cb:checked').forEach(cb => {
                if (cb.value === 'SONSTIGES') {
                    const txtInput = cb.closest('div').querySelector('input[type="text"]');
                    const txt = txtInput ? txtInput.value.trim() : '';
                    subTyp.push(txt || 'SONSTIGES'); 
                } else {
                    subTyp.push(cb.value);
                }
            });
            if (subTyp.length === 0) { alert("Bitte wählen Sie einen Typ!"); return; }
        }

        const file = fileInput.files[0];
        
        // --- LOADING BAR LOGIC START ---
        const saveBtn = document.getElementById('save-entry-btn');
        const saveProgress = document.getElementById('save-entry-progress');
        const saveText = document.getElementById('save-entry-text');

        if (saveBtn) saveBtn.style.pointerEvents = 'none';
        if (saveText) saveText.textContent = 'WIRD GESPEICHERT...';
        if (saveProgress) saveProgress.style.width = '10%';

        function persist(fileData, fileName, fileType, fileSize, fileHash) {
            const isEdit = !!window.editingId;
            const entry = {
                id: isEdit ? window.editingId : Date.now(),
                thema, lektion, buch, klassen, jahr, typ, subTyp,
                fileName, fileType, fileSize, fileHash,
                fileData,
                date: new Date().toLocaleDateString()
            };
            if (isEdit) {
                const txRead = idb.transaction(["documents"], "readonly");
                txRead.objectStore("documents").get(window.editingId).onsuccess = (ev) => {
                    const orig = ev.target.result;
                    entry.date = orig ? orig.date : new Date().toLocaleDateString();
                    writeEntry(entry, isEdit);
                };
            } else {
                writeEntry(entry, isEdit);
            }
        }

        function writeEntry(entry, isEdit) {
            const tx = idb.transaction(["documents"], "readwrite");
            const store = tx.objectStore("documents");
            isEdit ? store.put(entry) : store.add(entry);
            tx.oncomplete = () => {
                if (saveProgress) saveProgress.style.width = '100%';
                
                // Slight delay to let the animation finish visually
                setTimeout(() => {
                    alert(isEdit ? "Dokument erfolgreich aktualisiert!" : "Dokument erfolgreich in der Datenbank gespeichert!");
                    document.getElementById('import-submenu').classList.remove('open');

                    if (saveProgress) {
                        saveProgress.style.transition = 'none';
                        saveProgress.style.width = '0%';
                        setTimeout(() => { saveProgress.style.transition = 'width 0.5s ease'; }, 50);
                    }
                    if (saveBtn) saveBtn.style.pointerEvents = 'auto';

                    resetImportForm();
                    saveToDictionary('thema', thema);
                    saveToDictionary('lektion', lektion);
                    saveToDictionary('buch', buch);
                    renderResults();
                }, 300);
            };
        }

        if (fileInput.files.length > 0) {
            const reader = new FileReader();
            
            // Track the progress of reading the file
            reader.onprogress = function(ev) {
                if (ev.lengthComputable && saveProgress) {
                    const percentLoaded = Math.round((ev.loaded / ev.total) * 60) + 10;
                    saveProgress.style.width = percentLoaded + '%';
                }
            };
            
            reader.onload = function(ev) {
                if (saveProgress) saveProgress.style.width = '80%';
                // Yield thread to allow DOM to paint 80% before blocking to DB
                setTimeout(async () => {
                    // Authoritative re-check right before writing: guards against
                    // the flag-based check above going stale (e.g. a second file
                    // input event racing this save) and against duplicates that
                    // were only added to the DB after the file was selected.
                    if (!window.editingId) {
                        const stashedHash = fileInput.dataset.fileHash || null;
                        const dupe = await findMatchingEntry(file, stashedHash);
                        if (dupe) {
                            alert("Diese Datei ist bereits gespeichert (als „" + (dupe.thema || dupe.fileName || 'vorhandener Eintrag') + "\"). Bitte bearbeiten Sie den vorhandenen Eintrag.");
                            if (saveBtn) saveBtn.style.pointerEvents = 'auto';
                            if (saveText) saveText.textContent = 'SPEICHERN';
                            if (saveProgress) { saveProgress.style.width = '0%'; }
                            window.duplicateBlocked = true;
                            setSaveBtnEnabled(false);
                            showDuplicateNotice(document.getElementById('file-dup-status'), dupe);
                            return;
                        }
                    }
                    const meta = { thema, lektion, buch, klassen, jahr, typ, subTyp };
                    if (saveText && (isPdfFile(file.name, file.type) || isDocxFile(file.name, file.type))) {
                        saveText.textContent = 'METADATEN WERDEN EINGEBETTET...';
                    }
                    const finalData = await embedMetadataIfApplicable(ev.target.result, meta, file.name, file.type);
                    if (saveProgress) saveProgress.style.width = '90%';
                    persist(finalData, file.name, file.type, file.size, fileInput.dataset.fileHash || null);
                }, 50);
            };
            reader.readAsDataURL(fileInput.files[0]);
        } else {
            if (saveProgress) saveProgress.style.width = '50%';
            const txRead = idb.transaction(["documents"], "readonly");
            txRead.objectStore("documents").get(window.editingId).onsuccess = async (ev) => {
                const orig = ev.target.result;
                const meta = { thema, lektion, buch, klassen, jahr, typ, subTyp };
                // Re-embed so the stored copy always reflects the latest saved
                // info, even when the user only edited fields and kept the file.
                const finalData = await embedMetadataIfApplicable(orig.fileData, meta, orig.fileName || '', orig.fileType || '');
                persist(finalData, orig.fileName, orig.fileType, orig.fileSize, orig.fileHash);
            };
        }
    }

    function deleteEntry(id) {
        if(confirm("Möchten Sie dieses Dokument wirklich löschen?")) {
            const tx = idb.transaction(["documents"], "readwrite");
            tx.objectStore("documents").delete(id);
            tx.oncomplete = () => renderResults();
        }
    }

    // Track which entry is being edited (null = new entry)
    window.editingId = null;

    function editEntry(id) {
        const tx = idb.transaction(["documents"], "readonly");
        const req = tx.objectStore("documents").get(id);
        req.onsuccess = (e) => {
            const item = e.target.result;
            if (!item) return;

            window.editingId = item.id;

            // Fill form fields
            document.getElementById('inp-thema').value = item.thema || '';
            document.getElementById('inp-lektion').value = item.lektion || '';
            document.getElementById('inp-buch').value = item.buch || '';

            const klassSelect = document.getElementById('inp-klassen');
            const standardKlassen = Array.from(klassSelect.options).map(o => o.value);
            if (standardKlassen.includes(item.klassen)) {
                klassSelect.value = item.klassen;
                document.getElementById('inp-klassen-other').style.display = 'none';
            } else {
                klassSelect.value = 'Sonstiges';
                document.getElementById('inp-klassen-other').style.display = 'block';
                document.getElementById('inp-klassen-other').value = item.klassen;
            }

            document.getElementById('inp-jahr').value = item.jahr || '2000';

            const typSelect = document.getElementById('inp-typ');
            const standardTypen = Array.from(typSelect.options).map(o => o.value);
            if (standardTypen.includes(item.typ)) {
                typSelect.value = item.typ;
                document.getElementById('inp-typ-other').style.display = 'none';
            } else {
                typSelect.value = 'SONSTIGES';
                document.getElementById('inp-typ-other').style.display = 'block';
                document.getElementById('inp-typ-other').value = item.typ;
            }
            checkTyp();

            // Restore sub-type checkboxes AND Custom text inputs
            if (item.subTyp && item.subTyp.length > 0) {
                const standardValues = Array.from(document.querySelectorAll('.sub-cb')).map(cb => cb.value);
                
                document.querySelectorAll('.sub-cb').forEach(cb => {
                    if (item.subTyp.includes(cb.value)) cb.checked = true;
                });

                const customValues = item.subTyp.filter(v => !standardValues.includes(v) && v !== 'SONSTIGES');
                
                if (customValues.length > 0 || item.subTyp.includes('SONSTIGES')) {
                    if (item.typ === 'PROBEPRÜFUNG' || item.typ === 'PRÜFUNG') {
                        const cb = document.querySelector('#sub-pruefung input[value="SONSTIGES"]');
                        if (cb) {
                            cb.checked = true;
                            toggleOtherInput(cb, 'pruefung-other-text');
                            if (customValues.length > 0) document.getElementById('pruefung-other-text').value = customValues[0];
                        }
                    } else if (item.typ === 'KONTROLLE') {
                        const cb = document.querySelector('#sub-kontrolle input[value="SONSTIGES"]');
                        if (cb) {
                            cb.checked = true;
                            toggleOtherInput(cb, 'kontrolle-other-text');
                            if (customValues.length > 0) document.getElementById('kontrolle-other-text').value = customValues[0];
                        }
                    }
                }
            }

            // Show submenu in edit mode — update header and save button label
            document.querySelector('#import-submenu h2').innerHTML = `✏️ Prüfungsstoff bearbeiten`;
            document.getElementById('save-entry-text').textContent = 'AKTUALISIEREN';
            document.getElementById('import-submenu').classList.add('open');
        };
    }

    function renderResults() {
        if (!idb) return;

        const q = document.getElementById('search-input').value.toLowerCase().trim();
        const fJahr = document.getElementById('filter-jahr').value.trim();
        const fKlass = document.getElementById('filter-klassen').value.toLowerCase().trim();
        const fThema = document.getElementById('filter-thema').value.toLowerCase().trim();
        const fTyp = document.getElementById('filter-typ').value;
        const deleteMode = document.getElementById('delete-mode-cb').checked;
        const editMode = document.getElementById('edit-mode-cb').checked;


        const tx = idb.transaction(["documents"], "readonly");
        const store = tx.objectStore("documents");
        const req = store.getAll();

        req.onsuccess = (e) => {
            const db = e.target.result.reverse(); // newest first
            const container = document.getElementById('results-container');
            container.innerHTML = '';

            const filtered = db.filter(item => {
                const searchTxt = `${item.thema} ${item.lektion} ${item.buch} ${item.fileName}`.toLowerCase();
                if (q && !searchTxt.includes(q)) return false;
                if (fJahr && !String(item.jahr).includes(fJahr)) return false;
                if (fKlass && !item.klassen.toLowerCase().includes(fKlass)) return false;
                if (fThema && !(item.thema.toLowerCase().includes(fThema) || item.lektion.toLowerCase().includes(fThema))) return false;
                if (fTyp && item.typ !== fTyp) return false;
                return true;
            });

            if (filtered.length === 0) {
                container.innerHTML = `<div style="padding:20px; color:gray;">Keine Dokumente gefunden.</div>`;
                return;
            }

            filtered.forEach(item => {
                const card = document.createElement('div');
                card.className = 'result-card';
                
                const deleteBtnHtml = deleteMode ? `<button onclick="deleteEntry(${item.id}); event.stopPropagation();" style="background:#dc3545; color:white; border:none; padding:6px 12px; border-radius:5px; cursor:pointer; font-size:0.8rem; font-weight:bold;">🗑️ LÖSCHEN</button>` : '';
                const editBtnHtml = editMode ? `<button onclick="editEntry(${item.id}); event.stopPropagation();" style="background:var(--accent); color:white; border:none; padding:6px 12px; border-radius:5px; cursor:pointer; font-size:0.8rem; font-weight:bold; margin-right:6px;">✏️ BEARBEITEN</button>` : '';

                card.innerHTML = `
                    <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                        <div>
                            <div class="pill-container">
                                <span class="pill">${item.typ}</span>
                                <span class="pill" style="background:var(--primary); color:white;">${item.klassen}</span>
                                <span class="pill" style="background:var(--border);">${item.jahr}</span>
                            </div>
                            <h3 style="margin:5px 0; color:var(--primary);">${item.thema}</h3>
                            <div class="result-meta">Lektion: ${item.lektion} | Buch: ${item.buch}</div>
                        </div>
                        <div style="text-align:right; font-size:0.8rem; color:gray;">
                            ${item.date} <br>
                            📄 ${item.fileName} <br><br>
                            ${editBtnHtml}${deleteBtnHtml}
                        </div>
                    </div>
                `;
                card.onclick = () => openModal(item.id);
                container.appendChild(card);
            });
        };
    }

    function toggleOtherInput(checkbox, inputId) {
        const input = document.getElementById(inputId);
        input.disabled = !checkbox.checked;
        if (!checkbox.checked) input.value = '';
    }

    function openModal(id) {
        const tx = idb.transaction(["documents"], "readonly");
        const store = tx.objectStore("documents");
        const req = store.get(id);

        req.onsuccess = (e) => {
            const item = e.target.result;
            if (!item) return;

            const modal = document.getElementById('fs-modal');
            const content = document.getElementById('fs-content');
            const downloadBtn = document.getElementById('btn-download');

            let subTypHtml = item.subTyp && item.subTyp.length > 0 ? `<p><strong>Spezifikation:</strong> ${item.subTyp.join(', ')}</p>` : '';
            
            let isPdf = item.fileType.includes('pdf') || item.fileName.toLowerCase().endsWith('.pdf');
            let isImg = item.fileType.startsWith('image/') || item.fileName.match(/\.(jpg|jpeg|png|gif|webp)$/i);
            let isTxt = item.fileType.startsWith('text/') || item.fileName.match(/\.(txt|html|css|js|json)$/i);
            let isMedia = item.fileType.startsWith('video/') || item.fileType.startsWith('audio/');
            let isDocx = item.fileType.includes('wordprocessingml') || item.fileName.toLowerCase().endsWith('.docx');
            
            let previewHtml = '';
            if (isPdf) {
                previewHtml = `<div id="pdf-canvas-container">Lade PDF-Vorschau...</div>`;
            } else if (isTxt) {
                previewHtml = `<pre id="txt-container" style="width:100%; height:100%; overflow:auto; white-space:pre-wrap; word-break:break-word; padding:15px; background:white; color:black; margin:0; font-family:monospace; font-size:0.9rem; text-align:left;">Lade Text...</pre>`;
            } else if (isImg) {
                previewHtml = `<img src="${item.fileData}" style="max-width:100%; max-height:100%; object-fit:contain;">`;
            } else if (isMedia) {
                previewHtml = `<video src="${item.fileData}" controls style="max-width:100%; max-height:100%; outline:none;"></video>`;
            } else if (isDocx) {
                previewHtml = `<div id="docx-container" style="width:100%; height:100%; overflow-y:auto; background:white; color:black; padding:20px; text-align: left; align-items:flex-start; justify-content:flex-start; display:block;">Dokument wird geladen...</div>`;
            } else {
                previewHtml = `<div style="text-align:center; padding:50px; color:var(--text);">Offline-Vorschau für dieses Format nicht nativ verfügbar.<br><br>Bitte verwenden Sie den <strong>DOWNLOAD</strong> Button unten.</div>`;
            }

            content.innerHTML = `
                <h1 style="color:var(--primary); margin-top:0;">${item.typ} - ${item.thema}</h1>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; background:var(--bg); padding:20px; border-radius:8px; border:1px solid var(--border);">
                    <div>
                        <p><strong>Klassen/Stufe:</strong> ${item.klassen}</p>
                        <p><strong>Jahr:</strong> ${item.jahr}</p>
                        <p><strong>Buch:</strong> ${item.buch}</p>
                    </div>
                    <div>
                        <p><strong>Lektion:</strong> ${item.lektion}</p>
                        <p><strong>Datei:</strong> ${item.fileName}</p>
                        ${subTypHtml}
                    </div>
                </div>
                <div id="fs-iframe-container">
                    ${previewHtml}
                </div>
            `;

            // --- PDF Rendering Logic ---
            if (isPdf) {
                renderPdfMobileFriendly(item.fileData);
            }

            // --- Plain Text Rendering Logic ---
            if (isTxt) {
                const pre = document.getElementById('txt-container');
                try {
                    const base64 = item.fileData.split(',')[1];
                    const binary = atob(base64);
                    const bytes = new Uint8Array(binary.length);
                    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
                    pre.textContent = new TextDecoder('utf-8').decode(bytes);
                } catch (err) {
                    pre.textContent = 'Fehler beim Laden der Textdatei.';
                    console.error('Text decode error:', err);
                }
            }

            // --- DOCX Rendering Logic ---
            if (isDocx) {
                const docxContainer = document.getElementById('docx-container');
                window.OSIRIS_LIBS_READY.then(() => {
                    if (typeof mammoth === 'undefined') {
                        docxContainer.innerHTML = `<div style="text-align:center; padding:50px; color:red;">DOCX-Bibliothek konnte nicht geladen werden (weder lokal noch über CDN).</div>`;
                        return;
                    }
                    try {
                        // Decode base64 data URL directly — no fetch() round-trip needed
                        const base64 = item.fileData.split(',')[1];
                        const binary = atob(base64);
                        const bytes = new Uint8Array(binary.length);
                        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
                        const arrayBuffer = bytes.buffer;
                        mammoth.convertToHtml({ arrayBuffer })
                            .then(result => { docxContainer.innerHTML = result.value; })
                            .catch(err => {
                                docxContainer.innerHTML = `<div style="text-align:center; padding:50px; color:red;">Fehler bei der DOCX-Vorschau.</div>`;
                                console.error("Mammoth Preview Error:", err);
                            });
                    } catch (err) {
                        docxContainer.innerHTML = `<div style="text-align:center; padding:50px; color:red;">Fehler beim Dekodieren der Datei.</div>`;
                        console.error("Base64 decode error:", err);
                    }
                });
            }

            downloadBtn.href = item.fileData;
            downloadBtn.download = item.fileName;
            
            const shareBtn = document.getElementById('btn-share');
            // Store current file info for sharing
            window._shareFileName = item.fileName;
            window._shareFileData = item.fileData;
            window._shareFileType = item.fileType || '';

            function refreshDownloadButton() {
                downloadBtn.style.opacity = '1';
                downloadBtn.style.pointerEvents = 'auto';
                shareBtn.style.opacity = '1';
                shareBtn.style.pointerEvents = 'auto';
                if (window.downloadTimeout) clearTimeout(window.downloadTimeout);
                window.downloadTimeout = setTimeout(() => {
                    downloadBtn.style.opacity = '0';
                    downloadBtn.style.pointerEvents = 'none';
                    shareBtn.style.opacity = '0';
                    shareBtn.style.pointerEvents = 'none';
                    document.getElementById('share-popup').classList.remove('visible');
                }, 5000);
            }

            refreshDownloadButton();

            modal.onclick = (event) => {
                if(event.target.id === 'fs-close') return;
                refreshDownloadButton();
            };

            modal.style.display = 'block';
            document.body.style.overflow = 'hidden'; 
        };
    }

    // Helper function for PDF.js (Pulled OUTSIDE of openModal)
    async function renderPdfMobileFriendly(base64Data) {
        await window.OSIRIS_LIBS_READY;
        const container = document.getElementById('pdf-canvas-container');
        
        try {
            // Convert base64 to Uint8Array
            const binaryString = atob(base64Data.split(',')[1]);
            const len = binaryString.length;
            const bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) { bytes[i] = binaryString.charCodeAt(i); }

            const pdfjsLib = window['pdfjs-dist/build/pdf'] || window.pdfjsLib;
            
            // ---> THE FIX IS HERE <--- 
            // We ensure the worker file correctly points to the CDN, matching your <script src="...">
            pdfjsLib.GlobalWorkerOptions.workerSrc = 'pdf.worker.min.js';

            const loadingTask = pdfjsLib.getDocument({data: bytes, isEvalSupported: false});
            const pdf = await loadingTask.promise;
            container.innerHTML = ''; // Clear loading text

            // Render every page
            for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {
                const page = await pdf.getPage(pageNum);
                const viewport = page.getViewport({scale: 1.5}); // Increase scale for clarity
                
                const canvas = document.createElement('canvas');
                canvas.className = 'pdf-page-canvas';
                const context = canvas.getContext('2d');
                canvas.height = viewport.height;
                canvas.width = viewport.width;

                await page.render({canvasContext: context, viewport: viewport}).promise;
                container.appendChild(canvas);
            }
        } catch (err) {
            container.innerHTML = `<div style="color:red; padding:20px;">PDF konnte nicht geladen werden.</div>`;
            console.error(err);
        }
    }

    function closeModal() {
        const modal = document.getElementById('fs-modal');
        modal.style.display = 'none';
        modal.onclick = null; // Clean up listener
        document.body.style.overflow = 'auto';
        document.getElementById('fs-content').innerHTML = ''; // free memory
        document.getElementById('share-popup').classList.remove('visible');
        if (window.shareAutoHideTimer) clearTimeout(window.shareAutoHideTimer);
        if (window.downloadTimeout) clearTimeout(window.downloadTimeout);
    }

    // --- DB Management & Utilities ---

    function exportDB() {
        const tx = idb.transaction(["documents"], "readonly");
        const req = tx.objectStore("documents").getAll();
        req.onsuccess = (e) => {
            const dbData = e.target.result;
            if (dbData.length === 0) { alert("Datenbank ist leer!"); return; }
            
            const jsonString = JSON.stringify(dbData);
            const blob = new Blob([jsonString], { type: "application/json;charset=utf-8" });
            const url = URL.createObjectURL(blob);
            
            const anchor = document.createElement('a');
            anchor.setAttribute("href", url);
            anchor.setAttribute("download", "test_bank_backup.json");
            document.body.appendChild(anchor); 
            anchor.click(); 
            anchor.remove();
            
            // Clean up the URL object to free up memory
            setTimeout(() => URL.revokeObjectURL(url), 5000);
        };
    }

    function importDB(event) {
        const file = event.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = function(e) {
            try {
                const importedData = JSON.parse(e.target.result);
                if (Array.isArray(importedData)) {
                    const tx = idb.transaction(["documents"], "readwrite");
                    const store = tx.objectStore("documents");
                    importedData.forEach(item => store.put(item)); // insert or update
                    tx.oncomplete = () => {
                        alert("Datenbank erfolgreich importiert!");
                        renderResults();
                    };
                } else { alert("Ungültiges JSON Format."); }
            } catch (err) { alert("Fehler beim Lesen der Datei."); }
        };
        reader.readAsText(file);
        event.target.value = '';
    }

    function resetDB() {
        if(confirm("Möchten Sie die gesamte Datenbank wirklich löschen?")) {
            if(confirm("LETZTE WARNUNG: Alle Dokumente werden gelöscht! Fortfahren?")) {
                const tx = idb.transaction(["documents"], "readwrite");
                tx.objectStore("documents").clear();
                tx.oncomplete = () => {
                    renderResults();
                    alert("Datenbank wurde zurückgesetzt.");
                };
            }
        }
    }

    // ── FR/DE i18n (synced with osiris_hub_prefs) ─────────────────────────
    const BANK_I18N = {
        FR: {
            importBtn: '✚ NOUVEAU DOCUMENT',
            themeBtn:  '🎨 Design',
            linksBtn:  'Liens utiles',
            popTitle:  'Ajouter un lien',
            popBtn:    'Ajouter',
            namePlac:  'Nom',
            fontTitle:   'Changer la police (aléatoire)',
            connOnline:  'En ligne',
            connOffline: 'Hors ligne'
        },
        DE: {
            importBtn: '✚ NEUER PRÜFUNGSSTOFF',
            themeBtn:  '🎨 Design',
            linksBtn:  'Nützliche Links',
            popTitle:  'Link hinzufügen',
            popBtn:    'Hinzufügen',
            namePlac:  'Name',
            fontTitle:   'Schriftart wechseln (zufällig)',
            connOnline:  'Online',
            connOffline: 'Offline'
        }
    };

    // ── Font pool (mirrors hub) ───────────────────────────────────────────
    const FONT_POOL = [
        "'Brush Script MT', cursive",
        "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
        "Georgia, 'Times New Roman', serif",
        "'Courier New', Courier, monospace",
        "'Trebuchet MS', Verdana, sans-serif",
        "'Arial Narrow', Arial, sans-serif",
        "'Palatino Linotype', 'Book Antiqua', Palatino, serif"
    ];

    (function restoreFont() {
        try {
            const prefs = JSON.parse(localStorage.getItem('osiris_hub_prefs') || '{}');
            if (prefs.font) document.documentElement.style.setProperty('--bank-font-family', prefs.font);
        } catch(e) {}
    })();

    function randomFont() {
        const current = getComputedStyle(document.documentElement).getPropertyValue('--bank-font-family').trim();
        const pool = FONT_POOL.filter(f => f !== current);
        const pick = pool[Math.floor(Math.random() * pool.length)];
        document.documentElement.style.setProperty('--bank-font-family', pick);
        try {
            const prefs = JSON.parse(localStorage.getItem('osiris_hub_prefs') || '{}');
            prefs.font = pick;
            localStorage.setItem('osiris_hub_prefs', JSON.stringify(prefs));
        } catch(e) {}
        document.getElementById('fontBtn').title = BANK_I18N[bankLang].fontTitle;
    }

    function readBankLang() {
        try {
            const prefs = JSON.parse(localStorage.getItem('osiris_hub_prefs') || '{}');
            if (prefs.lang === 'FR' || prefs.lang === 'DE') return prefs.lang;
        } catch(e) {}
        return localStorage.getItem('bank_lang') || 'DE';
    }

    let bankLang = readBankLang();

    function applyBankI18n() {
        const d = BANK_I18N[bankLang];
        document.getElementById('langBtnLabel').textContent   = bankLang;
        document.getElementById('importBtnLabel').textContent = d.importBtn;
        var _tbl = document.getElementById('themeBtnLabel'); if (_tbl) _tbl.textContent = '';
        document.getElementById('linksBtnLabel').textContent  = d.linksBtn;
        document.getElementById('fontBtn').title              = d.fontTitle;
        document.getElementById('pop-title').innerText        = d.popTitle;
        document.getElementById('pop-btn').innerText          = d.popBtn;
        document.getElementById('link-name').placeholder      = d.namePlac;
    }

    function toggleLang() {
        bankLang = bankLang === 'FR' ? 'DE' : 'FR';
        applyBankI18n();
        localStorage.setItem('bank_lang', bankLang);
        try {
            const prefs = JSON.parse(localStorage.getItem('osiris_hub_prefs') || '{}');
            prefs.lang = bankLang;
            localStorage.setItem('osiris_hub_prefs', JSON.stringify(prefs));
        } catch(e) {}
    }

    // ── Connection dot removed (was here: mirrors hub, online/offline
    // status) — per request, the indicator and its wiring are gone.

    // Run initial i18n
    applyBankI18n();

    // --- Theme & Links Logic ---
    
    var _tt = document.getElementById('theme-toggle'); if (_tt) _tt.onclick = () => {
        // Simplified to light/dark only — the osiris/snow/grass/ocean
        // theme CSS was already removed from the HTML, so cycling through
        // them here would silently no-op on those steps (unmatched
        // [data-theme="..."] selector just falls back to the default
        // :root/light variables).
        const themes = ['light', 'dark'];
        let current = document.documentElement.getAttribute('data-theme');
        let nextTheme = themes[(themes.indexOf(current) + 1) % themes.length];
        document.documentElement.setAttribute('data-theme', nextTheme);
        localStorage.setItem('wiki_theme', nextTheme);
        applyBankI18n();
    };

    const savedTheme = localStorage.getItem('wiki_theme');
    if (savedTheme) document.documentElement.setAttribute('data-theme', savedTheme);

    function toggleLinksPop(e) {
        if(e) e.stopPropagation();
        const pop = document.getElementById('links-pop');
        // Bug: #links-pop starts hidden via the stylesheet rule
        // (display:none in CSS), not an inline style — so pop.style.display
        // read '' (not 'none') on the very first call. '' === 'none' is
        // false, so the first click set style.display = 'none' explicitly
        // (no visible change, still hidden); only the *second* click
        // actually opened it. Tracking state via a class instead fixes it
        // regardless of how the element was hidden to begin with.
        const isOpen = pop.classList.contains('open');
        pop.classList.toggle('open', !isOpen);
        pop.style.display = isOpen ? 'none' : 'block';
        renderLinksList();
    }

    function addLink() {
        const name = document.getElementById('link-name').value.trim();
        const url = document.getElementById('link-url').value.trim();
        if (!name || !url) return;
        links.push({ name, url });
        localStorage.setItem('wiki_links', JSON.stringify(links));
        document.getElementById('link-name').value = ''; document.getElementById('link-url').value = '';
        renderLinksList();
    }

    function removeLink(idx) {
        links.splice(idx, 1);
        localStorage.setItem('wiki_links', JSON.stringify(links));
        renderLinksList();
    }

    function renderLinksList() {
        const list = document.getElementById('pop-links-list');
        list.innerHTML = '';
        links.forEach((l, idx) => {
            const div = document.createElement('div');
            div.style.display = 'flex'; div.style.justifyContent = 'space-between'; div.style.marginBottom = '5px';
            div.innerHTML = `<a href="${l.url}" target="_blank" style="color:var(--text); text-decoration:none; font-weight:bold; max-width:85%; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${l.name}</a>
                             <span onclick="removeLink(${idx})" style="cursor:pointer; color:red; font-weight:bold;">✖</span>`;
            list.appendChild(div);
        });
        updateTicker();
    }

    function updateTicker() {
        const ticker = document.getElementById('footer-ticker');
        ticker.innerHTML = '';
        if (links.length === 0) {
            ticker.innerHTML = `<span>Fügen Sie Ihre Lieblingslinks hinzu, um sie hier durchlaufen zu sehen!</span>`; return;
        }
        const pool = [...links, ...links, ...links];
        pool.forEach(l => {
            const span = document.createElement('span'); span.style.margin = '0 25px';
            span.innerHTML = `<a href="${l.url}" target="_blank" style="color:var(--primary); text-decoration:none; font-weight:bold;">${l.name}</a>`;
            ticker.appendChild(span);
        });
    }

    // Global Click Listener
    document.addEventListener('click', function(event) {
        const linksPop = document.getElementById('links-pop');
        if (linksPop.style.display === 'block' && !linksPop.contains(event.target) && event.target.id !== 'links-toggle-btn') {
            linksPop.style.display = 'none';
        }
    });

    updateTicker();

    // --- Share Button Logic ---
    function toggleSharePopup(e) {
        if (e) e.stopPropagation();
        const popup = document.getElementById('share-popup');
        const isVisible = popup.classList.contains('visible');
        if (isVisible) {
            popup.classList.remove('visible');
            if (window.shareAutoHideTimer) clearTimeout(window.shareAutoHideTimer);
        } else {
            popup.classList.add('visible');
            // Auto-close popup after 4 seconds
            if (window.shareAutoHideTimer) clearTimeout(window.shareAutoHideTimer);
            window.shareAutoHideTimer = setTimeout(() => {
                popup.classList.remove('visible');
            }, 4000);
        }
    }

    // Close popup if clicking outside
    document.getElementById('fs-modal').addEventListener('click', function(e) {
        const popup = document.getElementById('share-popup');
        const shareBtn = document.getElementById('btn-share');
        if (popup.classList.contains('visible') && !popup.contains(e.target) && e.target !== shareBtn && !shareBtn.contains(e.target)) {
            popup.classList.remove('visible');
            if (window.shareAutoHideTimer) clearTimeout(window.shareAutoHideTimer);
        }
    });

    function shareVia(platform) {
        const popup = document.getElementById('share-popup');
        popup.classList.remove('visible');
        if (window.shareAutoHideTimer) clearTimeout(window.shareAutoHideTimer);

        const fileName = window._shareFileName || 'Dokument';
        const fileData = window._shareFileData || '';
        const fileType = window._shareFileType || 'application/octet-stream';
        const msgText = 'Dokument: ' + fileName;

        if (platform === 'whatsapp') {
            window.open('https://api.whatsapp.com/send?text=' + encodeURIComponent(msgText), '_blank');

        } else if (platform === 'telegram') {
            window.open('https://t.me/share/url?url=' + encodeURIComponent(window.location.href) + '&text=' + encodeURIComponent(msgText), '_blank');

        } else if (platform === 'email') {
            window.location.href = 'mailto:?subject=' + encodeURIComponent(fileName) + '&body=' + encodeURIComponent(msgText);

        } else if (platform === 'bluetooth') {
            // Use Web Share API (works on mobile for Bluetooth/NFC/etc.)
            if (fileData && navigator.canShare) {
                try {
                    // Convert base64 data URL to a File object
                    const arr = fileData.split(',');
                    const mime = arr[0].match(/:(.*?);/)[1];
                    const bstr = atob(arr[1]);
                    const n = bstr.length;
                    const u8arr = new Uint8Array(n);
                    for (let i = 0; i < n; i++) u8arr[i] = bstr.charCodeAt(i);
                    const file = new File([u8arr], fileName, { type: mime });

                    if (navigator.canShare({ files: [file] })) {
                        navigator.share({ files: [file], title: fileName })
                            .catch(err => { if (err.name !== 'AbortError') alert('Teilen fehlgeschlagen: ' + err.message); });
                    } else {
                        navigator.share({ title: fileName, text: msgText })
                            .catch(err => { if (err.name !== 'AbortError') alert('Teilen fehlgeschlagen: ' + err.message); });
                    }
                } catch (err) {
                    alert('Bluetooth-Teilen wird von diesem Browser nicht unterstützt.');
                }
            } else if (navigator.share) {
                navigator.share({ title: fileName, text: msgText })
                    .catch(err => { if (err.name !== 'AbortError') alert('Teilen fehlgeschlagen: ' + err.message); });
            } else {
                alert('Teilen wird von diesem Browser nicht unterstützt. Bitte verwenden Sie einen mobilen Browser.');
            }
        }
    }


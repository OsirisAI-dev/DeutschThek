    let db = JSON.parse(localStorage.getItem('offline_wiki_db')) || [];
    let links = JSON.parse(localStorage.getItem('wiki_links')) || [];

    // --- TRANSLATION DICTIONARY ---
    const svgImportBtn = `<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                <path d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z"/>
            </svg>`;
    const svgImportTitle = `<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                <path d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z"/>
            </svg>`;
    const svgSearch = `<svg width="30px" height="30px" style="margin-right: 8px;" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
<circle cx="10" cy="10" r="6" stroke="#000000" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
<path d="M14.5 14.5L19 19" stroke="#000000" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;

    const i18n = {
        EN: {
            importBtn: `${svgImportBtn} IMPORT TEXT`, themeBtn: "🎨 Theme", linksBtn: "🔗 Links",
            importTitle: `${svgImportTitle} Import & Index`, textLabel: "Text Content", sourceLabel: "Source Link",
            saveBtn: "Save to Wiki", searchTitle: `${svgSearch} Wiki Search`, searchPlac: "Search keywords or text...",
            textPlac: "Paste your text here...", popTitle: "Add Link", popBtn: "Add", suggestions: "Suggestions:",
            copy: "📋 Copy", word: "📄 Word", namePlac: "Name",
            exportJson: "Export database (DB)", importJson: "Import database (DB)", resetDb: "Reset database (DB)", deleteMode: "Enable Delete Text"
        },
        FR: {
            importBtn: `${svgImportBtn} IMPORTER TEXTE`, themeBtn: "🎨 Thème", linksBtn: "🔗 Liens",
            importTitle: `${svgImportTitle} Importer & Indexer`, textLabel: "Contenu du texte", sourceLabel: "Lien source",
            saveBtn: "Enregistrer", searchTitle: `${svgSearch} Recherche Wiki`, searchPlac: "Rechercher des mots-clés...",
            textPlac: "Collez votre texte ici...", popTitle: "Ajouter lien", popBtn: "Ajouter", suggestions: "Suggestions :",
            copy: "📋 Copier", word: "📄 Word", namePlac: "Nom",
            exportJson: "Exporter banque de données (DB)", importJson: "Importer banque de données (DB)", resetDb: "Réinitialiser banque de données (DB)", deleteMode: "Activer la suppression du texte"
        },
        DE: {
            importBtn: `${svgImportBtn} TEXT IMPORTIEREN`, themeBtn: "🎨 Design", linksBtn: "🔗 Links",
            importTitle: `${svgImportTitle} Importieren & Indexieren`, textLabel: "Textinhalt", sourceLabel: "Quell-Link",
            saveBtn: "Speichern", searchTitle: `${svgSearch} Wiki-Suche`, searchPlac: "Suchen...",
            textPlac: "Text hier einfügen...", popTitle: "Link hinzufügen", popBtn: "Hinzufügen", suggestions: "Vorschläge:",
            copy: "📋 Kopieren", word: "📄 Word", namePlac: "Name",
            exportJson: "Datenbank Exportieren (DB)", importJson: " Datenbank Importieren (DB)", resetDb: "Datenbank zurücksetzen (DB)", deleteMode: "Textlöschung aktivieren"
        },
        SP: {
            importBtn: `${svgImportBtn} IMPORTAR TEXTO`, themeBtn: "🎨 Tema", linksBtn: "🔗 Enlaces",
            importTitle: `${svgImportTitle} Importar e Indexar`, textLabel: "Contenido del texto", sourceLabel: "Enlace fuente",
            saveBtn: "Guardar", searchTitle: `${svgSearch} Buscar en Wiki`, searchPlac: "Buscar...",
            textPlac: "Pegue su texto aquí...", popTitle: "Añadir enlace", popBtn: "Añadir", suggestions: "Sugerencias:",
            copy: "📋 Copiar", word: "📄 Word", namePlac: "Nombre",
            exportJson: "Exportar (DB)", importJson: "Importar (DB)", resetDb: "Restablecer (DB)", deleteMode: "Habilitar eliminación de texto"
        }
    };

    const lengthMap = {
        EN: { Short: "Short", Medium: "Medium", Long: "Long" },
        FR: { Short: "Court", Medium: "Moyen", Long: "Long" },
        DE: { Short: "Kurz", Medium: "Mittel", Long: "Lang" },
        SP: { Short: "Corto", Medium: "Medio", Long: "Largo" }
    };

    function applyI18n() {
        const lang = langs[lIdx];
        const data = i18n[lang] || i18n['DE'];
        
        document.getElementById('langBtnLabel').textContent = lang;
        document.getElementById('importBtnLabel').textContent = lang === 'DE' ? 'TEXT IMPORTIEREN' : 'IMPORTER TEXTE';
        var _tbl = document.getElementById('themeBtnLabel'); if (_tbl) _tbl.textContent = '';
        document.getElementById('linksBtnLabel').textContent = data.linksBtn;
        
        const importSub = document.getElementById('import-submenu');
        importSub.querySelector('h2').innerHTML = data.importTitle;
        importSub.querySelectorAll('label')[0].innerText = data.textLabel;
        importSub.querySelectorAll('label')[1].innerText = data.sourceLabel;
        document.getElementById('save-btn').innerText = data.saveBtn;
        document.getElementById('delete-mode-label').innerText = data.deleteMode;
        
        document.getElementById('import-text').placeholder = data.textPlac;
        document.getElementById('search-input').placeholder = data.searchPlac;
        document.getElementById('search-title').innerHTML = data.searchTitle;
        
        document.getElementById('pop-title').innerText = data.popTitle;
        document.getElementById('link-name').placeholder = data.namePlac;
        document.getElementById('pop-btn').innerText = data.popBtn;

        var bExp = document.getElementById('btn-export-json');
        if (bExp && bExp.querySelector('span')) bExp.querySelector('span').innerText = data.exportJson;
        var bImp = document.getElementById('btn-import-json');
        if (bImp && bImp.querySelector('span')) bImp.querySelector('span').innerText = data.importJson;
        var bRes = document.getElementById('btn-reset-db');
        if (bRes && bRes.querySelector('span')) bRes.querySelector('span').innerText = data.resetDb;

        updateConnDot();
        renderResults();
        updateTicker(); 
    }

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
    const FONT_TITLE = { FR: 'Changer la police (aléatoire)', DE: 'Schriftart wechseln (zufällig)' };

    (function restoreFont() {
        try {
            const prefs = JSON.parse(localStorage.getItem('osiris_hub_prefs') || '{}');
            if (prefs.font) document.documentElement.style.setProperty('--wiki-font-family', prefs.font);
        } catch(e) {}
    })();

    function randomFont() {
        const current = getComputedStyle(document.documentElement).getPropertyValue('--wiki-font-family').trim();
        const pool = FONT_POOL.filter(f => f !== current);
        const pick = pool[Math.floor(Math.random() * pool.length)];
        document.documentElement.style.setProperty('--wiki-font-family', pick);
        try {
            const prefs = JSON.parse(localStorage.getItem('osiris_hub_prefs') || '{}');
            prefs.font = pick;
            localStorage.setItem('osiris_hub_prefs', JSON.stringify(prefs));
        } catch(e) {}
        document.getElementById('fontBtn').title = FONT_TITLE[langs[lIdx]] || FONT_TITLE.FR;
    }

    // ── Language toggle (FR / DE, synced with osiris_hub_prefs) ──────────
    const wikiLangs = ['DE'];
    function readInitialLang() {
        try {
            const prefs = JSON.parse(localStorage.getItem('osiris_hub_prefs') || '{}');
            if (prefs.lang === 'DE') return 1; // index into wikiLangs
        } catch(e) {}
        // fall back to wiki-specific saved index (legacy FR/EN/DE/SP → map to FR/DE)
        const saved = localStorage.getItem('wiki_lang_idx');
        if (saved !== null) {
            const old = parseInt(saved, 10);
            // old: 0=FR,1=EN,2=DE,3=SP → new: 0=FR,1=DE
            return 0;
        }
        return 0;
    }
    let lIdx = readInitialLang();
    const langs = wikiLangs; // alias for applyI18n compatibility

    function toggleLang() {
        lIdx = (lIdx + 1) % langs.length;
        const lang = langs[lIdx];
        document.getElementById('langBtnLabel').textContent = lang;
        document.getElementById('fontBtn').title = FONT_TITLE[lang] || FONT_TITLE.FR;
        applyI18n();
        // Persist for this app and for hub cross-app sync
        localStorage.setItem('wiki_lang_idx', lIdx);
        try {
            const prefs = JSON.parse(localStorage.getItem('osiris_hub_prefs') || '{}');
            prefs.lang = lang;
            localStorage.setItem('osiris_hub_prefs', JSON.stringify(prefs));
        } catch(e) {}
    }

    // ── Connection dot (mirrors hub) ──────────────────────────────────────
    // Pre-existing gap found while wiring the AI-Text-Gen pipeline: this
    // was called unconditionally at load with no null-check, and this
    // particular Wiki HTML doesn't have a #connDot element (the Library
    // Hub project's connDot markup — see workplan — apparently never got
    // ported over here). That made the throw fatal to the whole script:
    // everything after updateConnDot() below, including the initial
    // renderResults() call, silently never ran. Guarding it here fixes
    // the crash without guessing at where a dot element should visually
    // go in this file's toolbar.
    function updateConnDot() {
        const dot = document.getElementById('connDot');
        if (!dot) return;
        const online = navigator.onLine;
        dot.classList.toggle('is-online', online);
        dot.classList.toggle('is-offline', !online);
        dot.title = online
            ? (langs[lIdx] === 'DE' ? 'Online' : 'En ligne')
            : (langs[lIdx] === 'DE' ? 'Offline' : 'Hors ligne');
    }
    window.addEventListener('online',  updateConnDot);
    window.addEventListener('offline', updateConnDot);
    updateConnDot();

    function toggleImport(e) {
        if(e) e.stopPropagation();
        document.getElementById('import-submenu').classList.toggle('open');
    }

    function toggleLinksPop(e) {
        if(e) e.stopPropagation();
        const pop = document.getElementById('links-pop');
        pop.style.display = pop.style.display === 'none' ? 'block' : 'none';
        renderLinksList();
    }

    function addLink() {
        const name = document.getElementById('link-name').value.trim();
        const url = document.getElementById('link-url').value.trim();
        if (!name || !url) { alert("Both fields are required."); return; }
        links.push({ name, url });
        localStorage.setItem('wiki_links', JSON.stringify(links));
        document.getElementById('link-name').value = '';
        document.getElementById('link-url').value = '';
        renderLinksList();
    }

    function renderLinksList() {
        const list = document.getElementById('pop-links-list');
        list.innerHTML = '';
        links.forEach((l, idx) => {
            const div = document.createElement('div');
            div.style.display = 'flex';
            div.style.justifyContent = 'space-between';
            div.style.alignItems = 'center';
            div.style.marginBottom = '5px';
            
            div.innerHTML = `
                <a href="${l.url}" target="_blank" style="color:var(--text); text-decoration:none; font-weight:bold; max-width:85%; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                    ${l.name}
                </a>
                <span onclick="removeLink(${idx})" style="cursor:pointer; color:red; font-weight:bold; font-size:1.1rem;">✖</span>
            `;
            list.appendChild(div);
        });
        updateTicker();
    }

    function updateTicker() {
        const ticker = document.getElementById('footer-ticker');
        ticker.innerHTML = '';
        const activeLang = langs[lIdx];
        if (links.length === 0) {
            ticker.innerHTML = `<span>Ajoutez vos liens favoris pour les voir défiler ici !</span>`;
            return;
        }
        const pool = [...links, ...links, ...links];
        pool.forEach(l => {
            const span = document.createElement('span');
            span.style.margin = '0 25px';
            span.innerHTML = `<a href="${l.url}" target="_blank" style="color:var(--primary); text-decoration:none; font-weight:bold;">${l.name}</a>`;
            ticker.appendChild(span);
        });
    }

    function autoDetect(text) {
        const wordCount = text.trim().split(/\s+/).length;
        let length = "Short";
        if (wordCount > 500) length = "Long";
        else if (wordCount > 150) length = "Medium";

        const lower = text.toLowerCase();
        let lang = "en"; 
        if (/\b(le|la|les|est|dans)\b/.test(lower)) lang = "fr";
        else if (/\b(der|die|das|und|ist)\b/.test(lower)) lang = "de";
        else if (/\b(el|la|los|es|en)\b/.test(lower)) lang = "sp";

        return { length, lang };
    }

    // MODIFIED: Wrapped localStorage setter in proper try/catch
    function saveEntry() {
        const url = document.getElementById('import-url').value.trim();
        const text = document.getElementById('import-text').value.trim();

        if (!url || !text) { alert("Source link and text content are required."); return; }

        const meta = autoDetect(text);
        const words = text.toLowerCase().match(/\b(\w{6,})\b/g) || [];
        const uniqueKws = [...new Set(words)].slice(0, 5);

        const entry = {
            id: Date.now(),
            url, text, 
            lang: meta.lang, 
            length: meta.length,
            keywords: uniqueKws,
            date: new Date().toLocaleDateString()
        };

        try {
            // Attempt saving to LocalStorage first
            let testDb = JSON.parse(localStorage.getItem('offline_wiki_db')) || [];
            testDb.unshift(entry);
            localStorage.setItem('offline_wiki_db', JSON.stringify(testDb));
            
            // If it succeeds, update the global database array
            db = testDb;

            document.getElementById('import-url').value = '';
            document.getElementById('import-text').value = '';
            document.getElementById('import-submenu').classList.remove('open');
            renderResults();

        } catch (e) {
            // Fallback to IndexedDB if LocalStorage quota is exceeded
            if (e.name === 'QuotaExceededError' || e.code === 22 || e.name === 'NS_ERROR_DOM_QUOTA_REACHED') {
                console.warn("LocalStorage full. Switching to IndexedDB...");
                saveToIndexedDB(entry);
            } else {
                console.error("Error saving entry:", e);
                alert("Failed to save entry.");
            }
        }
    }

    // --- INDEXED DB IMPLEMENTATION ---
    let idb;
    const request = indexedDB.open("OfflineWikiIDB", 1);

    request.onupgradeneeded = (e) => {
        idb = e.target.result;
        if(!idb.objectStoreNames.contains("entries")) {
            idb.createObjectStore("entries", { keyPath: "id" });
        }
    };

    request.onsuccess = (e) => { idb = e.target.result; };
    request.onerror = (e) => { console.error("IndexedDB initialization error:", e); };

    function saveToIndexedDB(entry) {
        const progressContainer = document.getElementById('idb-progress-container');
        const progressBar = document.getElementById('idb-progress-bar');
        const statusText = document.getElementById('idb-status-text');
        
        // Show loading simulation
        progressContainer.style.display = 'block';
        statusText.style.display = 'block';
        let progress = 0;

        const interval = setInterval(() => {
            progress += 10;
            progressBar.style.width = progress + '%';
            
            if (progress >= 100) {
                clearInterval(interval);
                executeIDBSave(entry, progressContainer, progressBar, statusText);
            }
        }, 100); 
    }

    function executeIDBSave(entry, container, bar, text) {
        if (!idb) {
            alert("Database not ready yet. Please try again.");
            resetProgressBar(container, bar, text);
            return;
        }

        try {
            const transaction = idb.transaction(["entries"], "readwrite");
            const store = transaction.objectStore("entries");
            store.add(entry);

            transaction.oncomplete = () => {
                alert("LocalStorage is full. This entry was successfully saved to the Extended Database (database.db) via IndexedDB.");
                document.getElementById('import-url').value = '';
                document.getElementById('import-text').value = '';
                document.getElementById('import-submenu').classList.remove('open');
                
                // Note: renderResults primarily reads from LocalStorage 'db'. 
                // A full hybrid implementation would merge IDB and LocalStorage results here.
                renderResults(); 
                resetProgressBar(container, bar, text);
            };

            transaction.onerror = (e) => {
                console.error("IDB Save error", e);
                alert("Error saving to Extended Database.");
                resetProgressBar(container, bar, text);
            }
        } catch(e) {
            console.error("Transaction Error", e);
            resetProgressBar(container, bar, text);
        }
    }

    function resetProgressBar(container, bar, text) {
        setTimeout(() => {
            container.style.display = 'none';
            text.style.display = 'none';
            bar.style.width = '0%';
        }, 500);
    }
    // --------------------------------

    function removeLink(idx) {
        links.splice(idx, 1);
        localStorage.setItem('wiki_links', JSON.stringify(links));
        renderLinksList();
    }

    function deleteEntry(id, event) {
        if(event) event.stopPropagation();
        if(confirm("Confirmer la suppression / Confirm deletion?")) {
            db = db.filter(i => i.id != id);
            localStorage.setItem('offline_wiki_db', JSON.stringify(db));
            renderResults();
        }
    }

    function toggleExportMenu(e, id) {
        if(e) e.stopPropagation();
        document.querySelectorAll('.export-menu').forEach(m => {
            if(m.id !== 'export-menu-'+id) m.style.display = 'none';
        });
        const menu = document.getElementById('export-menu-'+id);
        menu.style.display = menu.style.display === 'block' ? 'none' : 'block';
    }

    function renderResults() {
        const query = document.getElementById('search-input').value.toLowerCase().trim();
        const container = document.getElementById('results-container');
        const kwContainer = document.getElementById('recent-keywords');
        const activeLang = langs[lIdx];
        const deleteMode = document.getElementById('delete-mode-cb').checked; 
        container.innerHTML = '';

        const allKws = db.flatMap(i => i.keywords);
        const uniqueRecent = [...new Set(allKws)].slice(0, 8);
        kwContainer.innerHTML = uniqueRecent.length ? `<span>${i18n[activeLang].suggestions}</span>` : '';
        uniqueRecent.forEach(kw => {
            const span = document.createElement('span');
            span.className = 'kw-sugg';
            span.textContent = kw;
            span.onclick = () => { document.getElementById('search-input').value = kw; renderResults(); };
            kwContainer.appendChild(span);
        });

        const filtered = db.filter(item => 
            item.text.toLowerCase().includes(query) || 
            item.keywords.some(k => k.toLowerCase().includes(query))
        );

        filtered.forEach(item => {
            const card = document.createElement('div');
            card.className = 'result-card';
            
            let highlighted = item.text;
            let preview = item.text.substring(0, 200) + '...';
            
            if (query) {
                const regex = new RegExp(`(${query})`, 'gi');
                highlighted = item.text.replace(regex, '<mark>$1</mark>');
                preview = preview.replace(regex, '<mark>$1</mark>');
            }

            const translatedLength = lengthMap[activeLang][item.length] || item.length;
            const deleteBtnHtml = deleteMode ? `<span onclick="deleteEntry('${item.id}', event)" style="position:absolute; top:15px; right:15px; color:#dc3545; font-weight:bold; cursor:pointer; font-size:1.2rem; z-index:5;">✖</span>` : '';

            card.innerHTML = `
                ${deleteBtnHtml}
                <div class="result-meta">
                    <strong>[${item.lang.toUpperCase()} - ${translatedLength}]</strong> | ${item.date} | 🔗 <a href="${item.url}" target="_blank" onclick="event.stopPropagation()">${item.url}</a>
                </div>
                <div class="pill-container">${item.keywords.map(k => `<span class="pill">${k}</span>`).join('')}</div>
                <div class="result-preview">${preview}</div>
                <div class="expanded-content">
                    <div>${highlighted}</div>
                    <div class="floating-options" onclick="event.stopPropagation()">
                        <button class="action-btn" onclick="copyText('${item.id}')">${i18n[activeLang].copy}</button>
                        
                        <div style="position:relative; display:inline-block;">
                            <button class="word-btn" onclick="toggleExportMenu(event, '${item.id}')">${i18n[activeLang].word} ▾</button>
                            <div id="export-menu-${item.id}" class="export-menu">
                                <div onclick="exportDoc('${item.id}', 'doc', event)">.doc</div>
                                <div onclick="exportDoc('${item.id}', 'docx', event)">.docx</div>
                            </div>
                        </div>

                    </div>
                </div>
            `;

            card.onclick = () => {
                const wasExpanded = card.classList.contains('expanded');
                document.querySelectorAll('.result-card').forEach(c => c.classList.remove('expanded'));
                if (!wasExpanded) card.classList.add('expanded');
            };
            container.appendChild(card);
        });
    }

    function copyText(id) {
        const item = db.find(i => i.id == id);
        navigator.clipboard.writeText(`${item.text}\n\nSource: ${item.url}`).then(() => alert("Copied!"));
    }

function exportDoc(id, format, event) {
    if(event) event.stopPropagation();
    document.getElementById('export-menu-'+id).style.display = 'none';

    const item = db.find(i => i.id == id);
    
    // Create a short name from the first 15 characters of the text
    // We remove special characters to ensure the filename is valid
    const shortName = item.text.substring(0, 15).replace(/[^a-z0-9]/gi, '_').toLowerCase();
    const fileName = `${shortName}.${format}`;

    const header = "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Wiki Export</title></head><body>";
    const content = `<h2>Wiki Export</h2><p>${item.text.replace(/\n/g, '<br>')}</p><br><p>Source: <a href="${item.url}">${item.url}</a></p></body></html>`;
    const fullHtml = header + content;

    if (format === 'doc') {
        const blob = new Blob(['\ufeff', fullHtml], { type: 'application/msword' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url; 
        link.download = fileName; // Uses the shortened name
        link.click();
    } else if (format === 'docx') {
        if (typeof htmlDocx !== 'undefined') {
            const converted = htmlDocx.asBlob(fullHtml);
            const url = URL.createObjectURL(converted);
            const link = document.createElement("a");
            link.href = url; 
            link.download = fileName; // Uses the shortened name
            link.click();
        } else {
            alert("Erreur: La librairie html-docx.js n'a pas pu être chargée.");
        }
    }
}

    var _tt = document.getElementById('theme-toggle'); if (_tt) _tt.onclick = () => {
        const themes = ['light', 'dark', 'osiris', 'snow', 'grass', 'ocean'];
        let current = document.documentElement.getAttribute('data-theme');
        let nextTheme = themes[(themes.indexOf(current) + 1) % themes.length];
        
        document.documentElement.setAttribute('data-theme', nextTheme);
        localStorage.setItem('wiki_theme', nextTheme); // Save for reboot
        try { window.parent.postMessage({ type: 'THEME_CHANGED', theme: nextTheme }, '*'); } catch (e) {}
    };

    document.addEventListener('click', function(event) {
        const linksPop = document.getElementById('links-pop');
        const linksBtn = document.getElementById('links-toggle-btn');
        if (linksPop.style.display === 'block' && !linksPop.contains(event.target) && event.target !== linksBtn) {
            linksPop.style.display = 'none';
        }

        const importMenu = document.getElementById('import-submenu');
        const importBtn = document.getElementById('import-toggle-btn');
        if (importMenu.classList.contains('open') && !importMenu.contains(event.target) && event.target !== importBtn) {
            importMenu.classList.remove('open');
        }

        document.querySelectorAll('.export-menu').forEach(m => {
            m.style.display = 'none';
        });
    });

    function exportDB() {
        if(db.length === 0) { alert("Database is empty!"); return; }
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(db));
        const downloadAnchorNode = document.createElement('a');
        downloadAnchorNode.setAttribute("href", dataStr);
        downloadAnchorNode.setAttribute("download", "offline_wiki_db.json");
        document.body.appendChild(downloadAnchorNode); 
        downloadAnchorNode.click();
        downloadAnchorNode.remove();
    }

    function importDB(event) {
        const file = event.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = function(e) {
            try {
                const importedData = JSON.parse(e.target.result);
                if(Array.isArray(importedData)) {
                    const existingIds = new Set(db.map(i => i.id));
                    const newEntries = importedData.filter(i => !existingIds.has(i.id));
                    
                    db = [...newEntries, ...db];
                    localStorage.setItem('offline_wiki_db', JSON.stringify(db));
                    renderResults();
                    alert("Database imported successfully!");
                } else {
                    alert("Invalid database format.");
                }
            } catch (err) {
                alert("Error reading file. Make sure it's a valid JSON database.");
            }
        };
        reader.readAsText(file);
        event.target.value = '';
    }

    function resetDB() {
        if(confirm("Are you sure you want to clear the entire text database?")) {
            if(confirm("DOUBLE CONFIRMATION: This action is irreversible. All saved texts will be permanently deleted! Proceed?")) {
                db = [];
                localStorage.removeItem('offline_wiki_db');
                renderResults();
                alert("Database has been reset.");
            }
        }
    }

    // --- INITIALIZATION (Settings survive reboot) ---
    const savedTheme = localStorage.getItem('wiki_theme');
    if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
    }

    // lIdx is already set by readInitialLang() above; just apply.
    applyI18n();

    // Centralized Backup Hub Synchronization Listener
    window.reloadWikiData = function() {
        try {
            db = JSON.parse(localStorage.getItem('offline_wiki_db')) || [];
            links = JSON.parse(localStorage.getItem('wiki_links')) || [];
        } catch(e) {}
        renderResults();
        if (typeof renderLinksList === 'function') renderLinksList();
    };

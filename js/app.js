/* Windows Security Event Log Triage Tool - page logic.
   Connects the upload box, demo buttons, settings and filters to the
   parser and analyser, and draws the report.

   Security note: every value from a CSV is untrusted. This file never uses
   innerHTML or similar with data. Text is always inserted with textContent,
   so something like <script> in an event is shown as harmless characters. */
(function () {
  'use strict';

  var Parser = window.EventCSV;
  var Analyser = window.EventAnalyser;
  var Samples = window.EventSamples || {};

  var STORAGE_KEY = 'wet-settings';
  var MAX_EVENT_ROWS = 250;
  var MAX_ALERT_CARDS = 100;
  var MAX_TIMELINE = 300;

  var state = { text: null, parsed: null, report: null, fileLabel: '', size: 0, encoding: '', isDemo: false, demoLabel: '' };

  function $(id) { return document.getElementById(id); }

  // Build an element safely. Strings and numbers become text nodes.
  function el(tag, props) {
    var node = document.createElement(tag);
    if (props) {
      Object.keys(props).forEach(function (k) {
        var v = props[k];
        if (v === undefined || v === null || v === false) return;
        if (k === 'className') node.className = v;
        else if (k === 'text') node.textContent = String(v);
        else if (k === 'onClick') node.addEventListener('click', v);
        else node.setAttribute(k, String(v));
      });
    }
    for (var i = 2; i < arguments.length; i++) append(node, arguments[i]);
    return node;
  }
  function append(node, child) {
    if (child === undefined || child === null || child === false) return;
    if (Array.isArray(child)) { child.forEach(function (c) { append(node, c); }); return; }
    node.appendChild(typeof child === 'object' ? child : document.createTextNode(String(child)));
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function fmt(n) { return Number(n).toLocaleString('en-GB'); }
  function svgChevron() {
    var ns = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('class', 'chev'); svg.setAttribute('aria-hidden', 'true');
    var path = document.createElementNS(ns, 'path');
    path.setAttribute('d', 'M9 6l6 6-6 6'); path.setAttribute('fill', 'none'); path.setAttribute('stroke', 'currentColor');
    path.setAttribute('stroke-width', '2'); path.setAttribute('stroke-linecap', 'round'); path.setAttribute('stroke-linejoin', 'round');
    svg.appendChild(path);
    return svg;
  }
  function sevBadge(sev) { return el('span', { className: 'sev sev-' + sev, text: sev }); }
  function eventName(id) {
    var c = Analyser.CATALOGUE[id];
    if (c) return c.name;
    var k = Analyser.KNOWN[id];
    return k ? k[0] : 'Not in reference list';
  }

  // ---------- Settings ----------
  var numberInputs = Array.prototype.slice.call(document.querySelectorAll('#settings-form input[type="number"]'));
  var dateSelect = $('s-dates');
  var MINIMUMS = { failures: 2, windowMinutes: 0, sprayAccounts: 2 };

  function loadSettings() {
    var saved = null;
    try { saved = JSON.parse(window.localStorage.getItem(STORAGE_KEY) || 'null'); } catch (e) { saved = null; }
    var s = Object.assign({}, Analyser.DEFAULTS, { dateOrder: 'auto' }, saved && typeof saved === 'object' ? saved : {});
    numberInputs.forEach(function (input) {
      var v = Number(s[input.name]);
      input.value = Number.isFinite(v) && v >= MINIMUMS[input.name] ? Math.floor(v) : Analyser.DEFAULTS[input.name];
    });
    dateSelect.value = ['auto', 'mdy', 'dmy'].indexOf(s.dateOrder) !== -1 ? s.dateOrder : 'auto';
  }
  function readSettings() {
    var s = {};
    numberInputs.forEach(function (input) {
      var v = Number(input.value);
      var valid = input.value !== '' && Number.isFinite(v) && v >= MINIMUMS[input.name];
      input.setAttribute('aria-invalid', valid ? 'false' : 'true');
      s[input.name] = valid ? Math.floor(v) : Analyser.DEFAULTS[input.name];
    });
    s.dateOrder = dateSelect.value;
    return s;
  }
  function saveSettings(s) {
    try { window.localStorage.setItem(STORAGE_KEY, JSON.stringify(s)); } catch (e) { /* storage unavailable: fine */ }
  }

  var rerunTimer = null;
  numberInputs.forEach(function (input) {
    input.addEventListener('input', function () {
      clearTimeout(rerunTimer);
      rerunTimer = setTimeout(function () {
        saveSettings(readSettings());
        if (state.parsed && state.parsed.ok) runAnalysis();
      }, 250);
    });
  });
  dateSelect.addEventListener('change', function () {
    saveSettings(readSettings());
    if (state.text !== null) loadText(state.text, state.fileLabel, state.size, state.isDemo, state.demoLabel, state.encoding, true);
  });
  $('settings-form').addEventListener('submit', function (e) { e.preventDefault(); });
  $('reset-settings').addEventListener('click', function () {
    numberInputs.forEach(function (input) { input.value = Analyser.DEFAULTS[input.name]; input.setAttribute('aria-invalid', 'false'); });
    var dateChanged = dateSelect.value !== 'auto';
    dateSelect.value = 'auto';
    saveSettings(readSettings());
    if (dateChanged && state.text !== null) loadText(state.text, state.fileLabel, state.size, state.isDemo, state.demoLabel, state.encoding, true);
    else if (state.parsed && state.parsed.ok) runAnalysis();
  });

  // ---------- Loading files ----------
  var dropzone = $('dropzone');
  var fileInput = $('file-input');

  fileInput.addEventListener('change', function () {
    if (fileInput.files && fileInput.files[0]) handleFile(fileInput.files[0]);
    fileInput.value = '';
  });
  ['dragenter', 'dragover'].forEach(function (evt) {
    dropzone.addEventListener(evt, function (e) { e.preventDefault(); dropzone.classList.add('is-dragging'); });
  });
  ['dragleave', 'dragend', 'drop'].forEach(function (evt) {
    dropzone.addEventListener(evt, function (e) { e.preventDefault(); dropzone.classList.remove('is-dragging'); });
  });
  dropzone.addEventListener('drop', function (e) {
    var files = e.dataTransfer && e.dataTransfer.files;
    if (files && files.length) handleFile(files[0]);
  });
  // Stop the browser opening a file dropped just outside the box.
  window.addEventListener('dragover', function (e) { e.preventDefault(); });
  window.addEventListener('drop', function (e) { e.preventDefault(); });

  function handleFile(file) {
    var name = String(file.name || 'file');
    var lower = name.toLowerCase();
    if (/\.(evtx|evt)$/.test(lower)) {
      return showError(name, file.size, ['This is a raw Windows event log (.evtx). Version 1 reads CSV exports only. Open the log in Event Viewer (Action > Open Saved Log) and use "Save All Events As..." with the CSV (Comma Separated) type.']);
    }
    if (/\.(xlsx|xls)$/.test(lower)) {
      return showError(name, file.size, ['This is an Excel workbook. In Excel use File > Save As and choose "CSV UTF-8 (Comma delimited)", then upload that file.']);
    }
    var typeOk = /\.(csv|txt)$/.test(lower) || file.type === 'text/csv' || file.type === 'application/vnd.ms-excel';
    if (!typeOk) {
      return showError(name, file.size, ['This does not look like a CSV file. Please choose a .csv file exported from Event Viewer or PowerShell.']);
    }
    if (file.size > Parser.MAX_BYTES) {
      return showError(name, file.size, ['This file is larger than 50 MB. In Event Viewer use "Filter Current Log" to choose fewer Event IDs or a shorter time range, then export again.']);
    }
    if (file.size === 0) return showError(name, 0, ['The file is empty.']);

    var reader = new FileReader();
    reader.onload = function () {
      var decoded;
      try { decoded = Parser.decodeBytes(new Uint8Array(reader.result)); }
      catch (e) { return showError(name, file.size, ['The file could not be read as text.']); }
      loadText(decoded.text, name, file.size, false, '', decoded.encoding);
    };
    reader.onerror = function () { showError(name, file.size, ['The browser could not read this file.']); };
    reader.readAsArrayBuffer(file);
  }

  Array.prototype.forEach.call(document.querySelectorAll('[data-sample]'), function (btn) {
    btn.addEventListener('click', function () {
      var s = Samples[btn.getAttribute('data-sample')];
      if (!s) return;
      loadText(s.csv, s.file, s.csv.length, true, s.label, 'UTF-8');
    });
  });

  function loadText(text, name, size, isDemo, demoLabel, encoding, keepScroll) {
    var parsed;
    try { parsed = Parser.parse(text, { dateOrder: dateSelect.value }); }
    catch (err) { parsed = { ok: false, errors: ['The file could not be parsed. It may be damaged or not a CSV.'], warnings: [], events: [], columns: {}, headers: [] }; }
    state.text = text;
    state.parsed = parsed;
    state.isDemo = isDemo;
    state.fileLabel = name;
    state.size = size;
    state.encoding = encoding || '';
    state.demoLabel = demoLabel || '';
    renderFileStatus(parsed);
    if (parsed.ok) {
      if (!keepScroll) resetFilters();
      runAnalysis();
      $('results').hidden = false;
      if (!keepScroll) $('results').scrollIntoView({ block: 'start' });
    } else {
      state.report = null;
      $('results').hidden = true;
    }
  }

  function showError(name, size, errors) {
    state.text = null;
    state.parsed = null;
    state.report = null;
    state.fileLabel = name; state.size = size; state.isDemo = false; state.encoding = '';
    renderFileStatus({ ok: false, errors: errors, warnings: [], events: [], columns: {}, headers: [] });
    $('results').hidden = true;
  }

  function formatBytes(n) {
    if (!Number.isFinite(n)) return '';
    if (n < 1024) return n + ' bytes';
    if (n < 1024 * 1024) return (Math.round(n / 102.4) / 10) + ' KB';
    return (Math.round(n / 104857.6) / 10) + ' MB';
  }

  var FORMAT_LABELS = { eventviewer: 'Event Viewer CSV export', powershell: 'PowerShell Export-Csv', generic: 'Other CSV layout' };
  var DATE_LABELS = { mdy: 'Month/day/year', dmy: 'Day/month/year' };

  function renderFileStatus(parsed) {
    var box = $('file-status');
    clear(box);
    box.hidden = false;
    var hasWarnings = parsed.warnings && parsed.warnings.length;
    box.className = 'file-status ' + (!parsed.ok ? 'is-error' : hasWarnings ? 'is-warn' : 'is-ok');

    var statusText = !parsed.ok ? 'Could not be analysed' : hasWarnings ? 'Parsed with warnings' : 'Parsed successfully';
    append(box, el('p', { className: 'status-title' }, statusText, state.isDemo ? el('span', { className: 'demo-badge', text: 'Demo Data' }) : null));

    var facts = el('dl', { className: 'status-facts' });
    append(facts, [el('dt', { text: 'File' }), el('dd', { className: 'mono', text: state.fileLabel })]);
    if (state.size) append(facts, [el('dt', { text: 'Size' }), el('dd', { text: formatBytes(state.size) + (state.encoding ? ' · ' + state.encoding : '') })]);
    append(facts, [el('dt', { text: 'Events loaded' }), el('dd', { text: fmt(parsed.events ? parsed.events.length : 0) })]);
    if (parsed.ok) {
      append(facts, [el('dt', { text: 'Format' }), el('dd', { text: FORMAT_LABELS[parsed.format] || 'CSV' })]);
      var t = parsed.timeInfo;
      var dateText = !parsed.timesAvailable ? 'Not available (file order used)'
        : t && t.used ? DATE_LABELS[t.used] + (dateSelect.value === 'auto' ? (t.ambiguous ? ' (assumed, see below)' : ' (detected)') : ' (set in Settings)')
        : 'ISO 8601 (unambiguous)';
      append(facts, [el('dt', { text: 'Dates' }), el('dd', { text: dateText })]);
      if (parsed.newestFirst) append(facts, [el('dt', { text: 'Order' }), el('dd', { text: 'File was newest first; re-sorted oldest first for analysis' })]);
    }
    append(box, facts);

    if (parsed.errors && parsed.errors.length) {
      append(box, el('ul', { className: 'status-list' }, parsed.errors.map(function (m) { return el('li', { text: m }); })));
    }
    if (hasWarnings) {
      append(box, el('p', { className: 'status-sub', text: 'Things that affect the analysis' }));
      append(box, el('ul', { className: 'status-list' }, parsed.warnings.map(function (m) { return el('li', { text: m }); })));
    }
    if (parsed.headers && parsed.headers.length) {
      append(box, el('p', { className: 'status-sub', text: 'Columns recognised' }));
      var chips = el('div', { className: 'chip-row' });
      ['eventId', 'time', 'source', 'task', 'level', 'keywords', 'message', 'user', 'computer'].forEach(function (f) {
        var idx = parsed.columns[f];
        var label = Parser.FIELD_LABELS[f];
        if (idx !== undefined) {
          var from = parsed.headers[idx] ? 'Read from the "' + parsed.headers[idx] + '" column' : 'Read from the unnamed last column (normal for Event Viewer exports)';
          append(chips, el('span', { className: 'chip', title: from, text: label + ' ✓' }));
        } else if (['eventId', 'time', 'message'].indexOf(f) !== -1) {
          append(chips, el('span', { className: 'chip chip-missing', text: label + ': missing' }));
        }
      });
      append(box, chips);
      if (parsed.messageFromUnnamedColumn) append(box, el('p', { className: 'muted small', text: 'The event description was found in the extra unnamed column that Event Viewer adds after "Task Category". Account names and IP addresses are read from that text.' }));
    }
  }

  // ---------- Analysis and report ----------
  function runAnalysis() {
    state.report = Analyser.analyse(state.parsed, readSettings());
    renderReport();
  }

  function renderReport() {
    var r = state.report;
    $('demo-badge').hidden = !state.isDemo;
    var span = r.range && r.range.span ? ' over ' + Analyser.fmtSpan(r.range.span) : '';
    $('results-source').textContent = (state.isDemo ? 'Demo data: ' + state.demoLabel + ' (' + state.fileLabel + ')' : 'File: ' + state.fileLabel) +
      ' · ' + fmt(r.counts.total) + ' events' + span;
    renderNotes(r);
    renderOverview(r);
    renderScore(r);
    populateFilters(r);
    renderFiltered();
    renderBars($('top-accounts'), r.topAccounts.map(function (a) { return { label: a.name, count: a.count, filter: ['f-account', a.name] }; }), 'events');
    $('top-acc-note').textContent = 'Select an account to filter the report.' + (r.hiddenSystem ? ' ' + Analyser.plural(r.hiddenSystem, 'event') + ' for built-in system and computer accounts (such as SYSTEM or names ending in $) are left out.' : '');
    renderBars($('top-failed'), r.topFailed.map(function (a) { return { label: a.name, count: a.count, filter: ['f-account', a.name] }; }), 'failures');
    renderBars($('top-ids'), r.eventIds.map(function (x) { return { label: String(x.id), sub: x.name, count: x.count, filter: ['f-id', String(x.id)], analysed: x.analysed }; }), 'events', true);
    renderCoverage(r);
  }

  function renderFiltered() {
    renderAlerts();
    renderAdmin();
    renderTimeline();
    renderEvents();
  }

  function renderNotes(r) {
    var box = $('analysis-notes');
    clear(box);
    var notes = r.notes.slice();
    if (r.useWindow) notes.unshift('Failed logons are counted within ' + r.settings.windowMinutes + '-minute windows. Set the window to 0 in Settings to count across the whole file.');
    if (!notes.length) return;
    append(box, el('div', { className: 'notes' }, notes.map(function (n) { return el('div', { className: 'callout', text: n }); })));
  }

  function stat(label, value, note) {
    return el('div', { className: 'stat' },
      el('div', { className: 'stat-label', text: label }),
      el('div', { className: 'stat-value', text: value }),
      note ? el('div', { className: 'stat-note', text: note }) : null);
  }

  function renderOverview(r) {
    var c = r.counts, box = $('overview');
    clear(box);
    append(box, [
      stat('Total events', fmt(c.total)),
      stat('Successful logons', fmt(c.success), '4624'),
      stat('Failed logons', fmt(c.failed), '4625'),
      stat('Accounts created', fmt(c.created), '4720'),
      stat('Privilege changes', fmt(c.privilege), '4728 / 4732 group additions'),
      stat('Audit-log clearing', fmt(c.cleared), '1102'),
      stat('Process creation', fmt(c.process), c.process ? '4688' : '4688 not present (often not audited)'),
      stat('Events requiring investigation', fmt(c.flagged), 'Linked to at least one finding'),
      c.deleted ? stat('Accounts deleted', fmt(c.deleted), '4726') : null,
      c.services ? stat('Services installed', fmt(c.services), '7045') : null,
      c.powershell ? stat('PowerShell script blocks', fmt(c.powershell), '4104') : null
    ]);
  }

  function renderScore(r) {
    var box = $('score-panel');
    clear(box);
    var band = r.topBand;
    append(box, el('div', { className: 'score-summary' },
      el('div', { className: 'score-num score-' + (band.level === 'Informational' ? 'None' : band.level), text: r.topScore, 'aria-hidden': 'true' }),
      el('div', { className: 'score-text' },
        el('p', null, el('strong', { text: (r.scores.length ? 'Highest investigation score: ' : 'Investigation score: ') + r.topScore + ' · ' + band.label })),
        el('p', { className: 'muted small', text: r.scores.length
          ? 'Each account (or source) adds up the points for the findings it appears in, each rule counted once. This is an educational prioritisation mechanism, not a mathematical probability of compromise.'
          : 'No rule produced a finding with the current settings. That does not prove nothing happened: it means nothing in this file stood out under these rules.' }))));
    if (!r.scores.length) return;

    var tbody = el('tbody');
    r.scores.forEach(function (s) {
      var breakdown = el('ul', { className: 'breakdown' }, s.contributions.map(function (c) {
        return el('li', null, el('span', { className: 'pts', text: '+' + c.points }), c.name + (c.count > 1 ? ' (' + c.count + ' findings, counted once)' : ''));
      }));
      var isSource = /^Source /.test(s.entity);
      var filter = isSource ? ['f-ip', s.entity.replace(/^Source /, '')] : ['f-account', s.entity];
      var unattributed = s.entity === 'No account recorded';
      append(tbody, el('tr', null,
        el('td', null, unattributed ? el('span', { className: 'muted', text: s.entity })
          : el('button', { type: 'button', className: 'btn-link mono', text: s.entity, 'aria-label': 'Filter report by ' + s.entity, onClick: function () { setFilter(filter[0], filter[1]); } })),
        el('td', null, el('strong', { className: 'score-' + s.band.level, text: s.score })),
        el('td', null, el('span', { className: 'sev sev-' + s.band.level, text: s.band.label })),
        el('td', null, breakdown)));
    });
    append(box, el('div', { className: 'table-wrap score-table-wrap' },
      el('table', { className: 'data-table' },
        el('caption', { className: 'sr-only', text: 'Investigation score per account or source' }),
        el('thead', null, el('tr', null,
          el('th', { scope: 'col', text: 'Account or source' }), el('th', { scope: 'col', text: 'Score' }),
          el('th', { scope: 'col', text: 'Priority' }), el('th', { scope: 'col', text: 'What contributed' }))),
        tbody)));
  }

  // ---------- Filters ----------
  var filterIds = ['f-id', 'f-account', 'f-severity', 'f-ip', 'f-type', 'f-search'];

  function fillSelect(select, allLabel, options) {
    var current = select.value;
    clear(select);
    append(select, el('option', { value: '', text: allLabel }));
    options.forEach(function (o) { append(select, el('option', { value: o.value, text: o.label })); });
    var values = options.map(function (o) { return o.value; });
    select.value = values.indexOf(current) !== -1 ? current : '';
  }
  function counted(values) {
    var m = new Map();
    values.forEach(function (v) { if (v) m.set(v, (m.get(v) || 0) + 1); });
    return Array.from(m.entries()).sort(function (a, b) { return b[1] - a[1] || String(a[0]).localeCompare(String(b[0])); });
  }

  function populateFilters(r) {
    var ev = r.events;
    fillSelect($('f-id'), 'All Event IDs', counted(ev.map(function (e) { return String(e.eventId); })).map(function (x) {
      return { value: x[0], label: x[0] + ' · ' + eventName(Number(x[0])) + ' (' + x[1] + ')' };
    }));
    var accountNames = [];
    ev.forEach(function (e) { if (e.d.accountName) accountNames.push(e.d.accountName); if (e.d.actorName && e.d.actorName !== e.d.accountName) accountNames.push(e.d.actorName); });
    fillSelect($('f-account'), 'All accounts', counted(accountNames).slice(0, 500).map(function (x) { return { value: x[0], label: x[0] + ' (' + x[1] + ')' }; }));
    fillSelect($('f-ip'), 'All source IPs', counted(ev.map(function (e) { return e.d.ip; })).slice(0, 500).map(function (x) { return { value: x[0], label: x[0] + ' (' + x[1] + ')' }; }));
    fillSelect($('f-type'), 'All event types', counted(ev.map(function (e) { return e.d.category; })).map(function (x) { return { value: x[0], label: x[0] + ' (' + x[1] + ')' }; }));
  }

  function resetFilters() { filterIds.forEach(function (id) { $(id).value = ''; }); }
  function setFilter(id, value) {
    var select = $(id);
    select.value = value;
    if (select.value !== value) return;
    renderFiltered();
    $('alerts-title').scrollIntoView({ block: 'start' });
  }
  function currentFilters() {
    return {
      id: $('f-id').value ? Number($('f-id').value) : null, account: $('f-account').value.toLowerCase(), severity: $('f-severity').value,
      ip: $('f-ip').value, type: $('f-type').value, search: $('f-search').value.trim().toLowerCase()
    };
  }
  filterIds.forEach(function (id) {
    $(id).addEventListener(id === 'f-search' ? 'input' : 'change', renderFiltered);
  });
  $('filters').addEventListener('submit', function (e) { e.preventDefault(); });
  $('clear-filters').addEventListener('click', function () { resetFilters(); renderFiltered(); });

  function lc(list) { return list.map(function (x) { return String(x).toLowerCase(); }); }
  function alertMatches(a, f) {
    if (f.id !== null && a.eventIds.indexOf(f.id) === -1) return false;
    if (f.account && lc(a.accounts).indexOf(f.account) === -1) return false;
    if (f.severity && a.severity !== f.severity) return false;
    if (f.ip && a.ips.indexOf(f.ip) === -1) return false;
    if (f.type && a.categories.indexOf(f.type) === -1) return false;
    if (f.search) {
      var hay = [a.name, a.sequence, a.entity].concat(a.accounts, a.ips, a.workstations).concat(a.observed.map(function (o) { return o.join(' '); })).join(' ').toLowerCase();
      if (hay.indexOf(f.search) === -1) return false;
    }
    return true;
  }
  function eventMatches(e, f) {
    if (f.id !== null && e.eventId !== f.id) return false;
    if (f.account && String(e.d.accountName || '').toLowerCase() !== f.account && String(e.d.actorName || '').toLowerCase() !== f.account) return false;
    if (f.severity && e.severity !== f.severity) return false;
    if (f.ip && e.d.ip !== f.ip) return false;
    if (f.type && e.d.category !== f.type) return false;
    if (f.search) {
      var hay = (e.eventId + ' ' + e.d.name + ' ' + (e.d.accountName || '') + ' ' + (e.d.actorName || '') + ' ' + (e.d.ip || '') + ' ' + (e.d.workstation || '') + ' ' + e.timeRaw + ' ' + e.message).toLowerCase();
      if (hay.indexOf(f.search) === -1) return false;
    }
    return true;
  }

  // ---------- Findings ----------
  function rangeText(range) {
    if (!range) return 'Not available';
    if (range.start === range.end) return range.startRaw;
    return range.startRaw + ' to ' + range.endRaw + ' (' + Analyser.fmtSpan(range.span) + ')';
  }

  function renderAlerts() {
    var r = state.report, box = $('alerts');
    if (!r) return;
    clear(box);
    var f = currentFilters();
    var list = r.alerts.filter(function (a) { return alertMatches(a, f); });
    $('alert-count').textContent = list.length === r.alerts.length
      ? Analyser.plural(r.alerts.length, 'finding')
      : 'Showing ' + list.length + ' of ' + Analyser.plural(r.alerts.length, 'finding');

    if (!r.alerts.length) {
      append(box, el('div', { className: 'empty' },
        el('strong', { text: 'No findings with the current settings.' }),
        'Nothing in this file matched a rule. Mostly informational activity is a useful result, not a guarantee: missing auditing, cleared logs or slow, quiet activity can all stay under simple rules.'));
      return;
    }
    if (!list.length) {
      append(box, el('div', { className: 'empty' }, el('strong', { text: 'No findings match these filters.' }), 'Clear the filters to see all findings.'));
      return;
    }
    list.slice(0, MAX_ALERT_CARDS).forEach(function (a, i) { append(box, renderAlert(a, i < 2)); });
    if (list.length > MAX_ALERT_CARDS) {
      append(box, el('div', { className: 'empty', text: 'Showing the first ' + MAX_ALERT_CARDS + ' of ' + fmt(list.length) + ' matching findings. Use the filters to narrow them down.' }));
    }
  }

  function renderAlert(a, open) {
    var details = el('details', open ? { open: '' } : null);
    var who = a.account || a.entity;
    var meta = el('div', { className: 'alert-meta' },
      el('span', null, (a.account ? 'Account ' : '') , el('b', { text: who })),
      el('span', null, 'Event IDs ', el('b', { text: a.eventIds.join(', ') })),
      a.range ? el('span', null, 'When ', el('b', { text: a.range.start === a.range.end ? a.range.startRaw : a.range.startRaw + ' → ' + a.range.endRaw })) : null,
      a.ips.length ? el('span', null, 'Source IP ', el('b', { text: a.ips.slice(0, 3).join(', ') + (a.ips.length > 3 ? ' …' : '') })) : null);
    append(details, el('summary', null,
      el('span', { className: 'alert-title' }, svgChevron(), sevBadge(a.severity), el('span', { text: a.name })),
      el('span', { className: 'alert-points' }, '+' + a.points, el('span', { text: 'score points' })),
      meta));

    var obs = el('dl', { className: 'observed' });
    function row(label, value, pre) { append(obs, [el('dt', { text: label }), el('dd', { className: pre || /\n/.test(String(value)) ? 'pre' : null, text: value })]); }
    row('Alert name', a.name);
    row('Severity', a.severity + ' (investigative priority)');
    row('Event IDs', a.eventIds.join(', '));
    row('Events', a.sequence, true);
    row('Account', a.account || (a.entity !== 'No account recorded' ? a.entity : 'No account recorded in these events'));
    row('Time range', rangeText(a.range));
    row('Source IP', a.ips.length ? a.ips.join(', ') : 'Not recorded');
    if (a.workstations.length) row('Workstation', a.workstations.join(', '));
    a.observed.forEach(function (o) { row(o[0], o[1]); });
    row('Rule threshold', a.threshold);

    append(details, el('div', { className: 'alert-body' },
      el('div', null, el('h4', { text: 'Observed activity' }), obs),
      el('div', null, el('h4', { text: 'Why this matters' }), el('p', { text: a.why })),
      el('div', { className: 'alert-cols' },
        el('div', null, el('h4', { text: 'Possible benign explanation' }), el('ul', null, a.benign.map(function (b) { return el('li', { text: b }); }))),
        el('div', null, el('h4', { text: 'Suggested investigation' }), el('ol', null, a.investigate.map(function (s) { return el('li', { text: s }); })))),
      el('p', { className: 'not-proof', text: 'Severity "' + a.severity + '" reflects investigative priority, not certainty. This finding shows where to look; only investigation can say what actually happened.' })));
    return el('article', { className: 'alert sev-border-' + a.severity, id: a.id, 'aria-label': a.severity + ' finding: ' + a.name + ' for ' + who }, details);
  }

  // ---------- Administrative / privilege activity ----------
  function renderAdmin() {
    var r = state.report;
    var f = currentFilters();
    var linkedBox = $('admin-linked');
    clear(linkedBox);
    var linked = r.admin.linked.filter(function (l) { return !f.account || l.name.toLowerCase() === f.account; });
    if (linked.length) {
      append(linkedBox, el('div', { className: 'linked' },
        el('h4', { text: 'Accounts that appear in more than one of these events' }),
        el('ul', null, linked.map(function (l) { return el('li', null, el('strong', { className: 'mono', text: l.name }), ' ' + l.roles.join(', ') + '.'); })),
        el('p', { text: 'These are linked only because the same account name appears. Check that it really is the same account, then ask whether this chain of actions was expected.' })));
    }
    var tbody = document.querySelector('#admin-table tbody');
    clear(tbody);
    var items = r.admin.items.filter(function (it) { return eventMatches(it.event, f); });
    items.forEach(function (it) {
      append(tbody, el('tr', null,
        el('td', { className: 'mono', text: it.event.timeRaw || '-' }),
        el('td', { className: 'mono', text: it.event.eventId }),
        el('td', { text: it.what }),
        el('td', { className: 'mono', text: it.actor || 'Not recorded' }),
        el('td', null, sevBadge(it.event.severity))));
    });
    if (!items.length) {
      append(tbody, el('tr', null, el('td', { colspan: '5', className: 'muted', text: r.admin.items.length
        ? 'No administrative events match these filters.'
        : 'No account creation, deletion, group change, service install or log clearing events in this file.' })));
    }
  }

  // ---------- Charts ----------
  function renderBars(list, rows, unit, idChart) {
    clear(list);
    var max = rows.length ? rows[0].count : 1;
    rows.forEach(function (row) {
      var name = el('button', { type: 'button', className: 'bar-name', text: row.label, 'aria-label': 'Filter report by ' + row.label + (row.sub ? ' (' + row.sub + ')' : ''), onClick: function () { setFilter(row.filter[0], row.filter[1]); } });
      var fill = el('span', { className: 'bar-fill' + (idChart ? (row.analysed ? ' is-analysed' : ' is-other') : '') });
      fill.style.width = Math.max(2, (row.count / max) * 100) + '%';
      append(list, el('li', { className: 'bar-row' },
        el('span', null, name, row.sub ? el('span', { className: 'bar-sub', text: row.sub }) : null),
        el('span', { className: 'bar-count', text: fmt(row.count) + ' ' + (row.count === 1 ? unit.replace(/s$/, '') : unit) }),
        el('span', { className: 'bar-track', 'aria-hidden': 'true' }, fill)));
    });
    if (!rows.length) append(list, el('li', { className: 'muted small', text: unit === 'failures' ? 'No failed logons in this file.' : 'No data.' }));
  }

  // ---------- Timeline ----------
  function renderTimeline() {
    var r = state.report, list = $('timeline');
    clear(list);
    var f = currentFilters();
    var items = r.timeline.filter(function (t) { return eventMatches(t.event, f); });
    $('timeline-count').textContent = items.length > MAX_TIMELINE ? 'Showing first ' + MAX_TIMELINE + ' of ' + fmt(items.length) : Analyser.plural(items.length, 'event');
    $('timeline-note').textContent = state.parsed.timesAvailable
      ? 'Events linked to a finding, plus all administrative events, oldest first. Uses the filters above.'
      : 'This file has no readable timestamps, so events are shown in file order.';
    items.slice(0, MAX_TIMELINE).forEach(function (t) {
      append(list, el('li', { className: 'tl-item' },
        el('span', { className: 'tl-time', text: t.event.timeRaw || 'No time' }),
        el('span', { className: 'tl-id', text: t.event.eventId }),
        el('span', { className: 'tl-text', text: t.text }),
        sevBadge(t.severity)));
    });
    if (!items.length) append(list, el('li', { className: 'tl-item muted', text: r.timeline.length ? 'No noteworthy events match these filters.' : 'Nothing noteworthy in this file: no findings and no administrative events.' }));
  }

  // ---------- Event explorer ----------
  function renderEvents() {
    var r = state.report;
    var tbody = document.querySelector('#event-table tbody');
    clear(tbody);
    var f = currentFilters();
    var matched = 0;
    var frag = document.createDocumentFragment();
    r.events.forEach(function (e) {
      if (!eventMatches(e, f)) return;
      matched++;
      if (matched > MAX_EVENT_ROWS) return;
      var detail = el('td', { className: 'detail-cell' },
        e.d.details.slice(0, 4).map(function (d) { return el('span', { className: 'detail-line' }, el('b', { text: d[0] + ': ' }), d[1].length > 160 ? d[1].slice(0, 160) + ' …' : d[1]); }),
        e.message ? el('details', null, el('summary', { text: 'Full description' }), el('pre', { text: e.message })) : el('span', { className: 'muted', text: 'No description in file' }));
      frag.appendChild(el('tr', null,
        el('td', { className: 'mono-cell', text: e.timeRaw || '-' }),
        el('td', { className: 'mono-cell', text: e.eventId }),
        el('td', { className: e.d.recognised ? null : 'unrecognised', text: e.d.recognised ? e.d.name : 'Not in reference list' }),
        el('td', { className: 'mono-cell', text: e.d.accountName || '-' }),
        el('td', { className: 'mono-cell', text: e.d.ip || '-' }),
        detail,
        el('td', null, sevBadge(e.severity))));
    });
    tbody.appendChild(frag);
    if (!matched) append(tbody, el('tr', null, el('td', { colspan: '7', className: 'muted', text: 'No events match these filters.' })));
    $('event-count').textContent = matched > MAX_EVENT_ROWS
      ? 'Showing first ' + MAX_EVENT_ROWS + ' of ' + fmt(matched) + ' matching events'
      : Analyser.plural(matched, 'matching event');
  }

  // ---------- Rule coverage ----------
  function renderCoverage(r) {
    var tbody = document.querySelector('#coverage-table tbody');
    clear(tbody);
    r.coverage.forEach(function (c) {
      var status = c.ran ? el('span', { className: 'status-ran', text: 'Ran' })
        : c.noMessage ? el('span', { className: 'status-skipped', text: 'Limited: no event description column' })
        : el('span', { className: 'status-skipped', text: 'Not run: needed events (' + c.needs.join(' / ') + ') are not in this file' });
      append(tbody, el('tr', null,
        el('td', null, el('strong', { text: c.name })),
        el('td', { className: 'mono', text: c.needs.join(', ') }),
        el('td', { text: '+' + c.points + (c.key === 'groupAdd' ? ' (+' + Analyser.PRIV_GROUP_POINTS + ' privileged)' : '') }),
        el('td', null, status),
        el('td', { text: c.ran ? String(c.alerts) : '–' })));
    });
  }

  // ---------- Static reference tables ----------
  function renderReference() {
    var tbody = $('id-reference');
    clear(tbody);
    [4624, 4625, 4688, 4720, 4726, 4728, 4732, 1102, 4104, 7045].forEach(function (id) {
      var c = Analyser.CATALOGUE[id];
      append(tbody, el('tr', null,
        el('td', null, el('strong', { className: 'mono', text: id })),
        el('td', { text: c.name }),
        el('td', { text: c.plain }),
        el('td', { className: 'small', text: c.log }),
        el('td', null, sevBadge(c.severity))));
    });
    var lt = $('logon-types');
    clear(lt);
    Object.keys(Analyser.LOGON_TYPES).forEach(function (k) {
      append(lt, el('li', null, el('b', { text: k }), ' ' + Analyser.LOGON_TYPES[k]));
    });
    var rules = $('rules-reference');
    clear(rules);
    Analyser.RULES.forEach(function (rule, i) {
      append(rules, el('tr', null,
        el('td', null, el('strong', { text: (i + 1) + '. ' + rule.name })),
        el('td', { text: rule.summary }),
        el('td', { text: '+' + rule.points + (rule.key === 'groupAdd' ? ' / +' + Analyser.PRIV_GROUP_POINTS : '') })));
    });
  }

  loadSettings();
  renderReference();
})();

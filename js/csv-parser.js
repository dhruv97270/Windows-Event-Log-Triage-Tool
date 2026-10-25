/* Windows Security Event Log Triage Tool - CSV reader.
   Turns a Windows event export (Event Viewer "Save As > CSV", or PowerShell
   Get-WinEvent | Export-Csv) into a list of events. Everything in the file is
   treated as plain text: nothing in it is ever run or turned into HTML. */
(function (root) {
  'use strict';

  // The same column can be named differently depending on how the file was
  // made. Names are compared after lower-casing and removing spaces and
  // punctuation, so "Event ID", "EventID" and "event_id" all become "eventid".
  // Where two names could match, the first one listed wins.
  var COLUMN_ALIASES = {
    eventId:  ['eventid', 'id', 'eventcode', 'eventnumber', 'evtid'],
    time:     ['dateandtime', 'timecreated', 'datetime', 'timestamp', 'time', 'date', 'timegenerated', 'systemtime', 'eventtime'],
    level:    ['level', 'leveldisplayname', 'severity', 'type', 'entrytype'],
    keywords: ['keywords', 'keywordsdisplaynames', 'keyword', 'audit', 'auditresult'],
    source:   ['source', 'providername', 'provider', 'sourcename', 'eventsource'],
    task:     ['taskcategory', 'taskdisplayname', 'task', 'category', 'categoryname'],
    user:     ['user', 'username', 'account', 'accountname', 'userid', 'targetusername', 'subjectusername'],
    computer: ['computer', 'machinename', 'computername', 'hostname', 'host', 'workstation'],
    logName:  ['logname', 'log', 'channel', 'containerlog'],
    message:  ['message', 'description', 'details', 'eventdata', 'text', 'generaltext']
  };

  var FIELD_LABELS = {
    eventId: 'Event ID', time: 'Date and Time', level: 'Level', keywords: 'Keywords',
    source: 'Source', task: 'Task Category', user: 'User', computer: 'Computer',
    logName: 'Log name', message: 'Message / description'
  };

  var MAX_BYTES = 50 * 1024 * 1024;   // 50 MB: larger files can freeze a browser tab
  var MAX_ROWS = 200000;
  var MAX_FIELD = 500;                // characters kept from a short cell
  var MAX_MESSAGE = 20000;            // characters kept from a message (script blocks can be long)

  function normaliseHeader(name) {
    return String(name).toLowerCase().replace(/[^a-z0-9]/g, '');
  }

  // ---------- Reading the raw bytes ----------
  // Windows tools save text in several encodings. PowerShell 5 can write
  // UTF-16, Event Viewer and Excel may use UTF-8 or the old Windows-1252.
  // We look at the first bytes to choose the right one.
  function decodeBytes(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
    var enc = 'utf-8', offset = 0;
    if (bytes[0] === 0xFF && bytes[1] === 0xFE) { enc = 'utf-16le'; offset = 2; }
    else if (bytes[0] === 0xFE && bytes[1] === 0xFF) { enc = 'utf-16be'; offset = 2; }
    else if (bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF) { enc = 'utf-8'; offset = 3; }
    else {
      // No marker: UTF-16 text has a zero byte in almost every other position.
      var sample = Math.min(bytes.length, 4000), zeroOdd = 0, zeroEven = 0;
      for (var i = 0; i < sample; i++) if (bytes[i] === 0) { if (i % 2) zeroOdd++; else zeroEven++; }
      if (sample > 16 && zeroOdd > sample * 0.3) enc = 'utf-16le';
      else if (sample > 16 && zeroEven > sample * 0.3) enc = 'utf-16be';
    }
    var body = bytes.subarray(offset);
    var text;
    try { text = new TextDecoder(enc, { fatal: enc === 'utf-8' }).decode(body); }
    catch (e) {
      // Not valid UTF-8: most likely an older Windows "ANSI" file.
      enc = 'windows-1252';
      text = new TextDecoder('windows-1252').decode(body);
    }
    return { text: text, encoding: enc.toUpperCase() };
  }

  // Pick the separator by looking at the header line. Windows tools use
  // commas, but some regional settings and spreadsheets use semicolons or tabs.
  function detectDelimiter(text) {
    var firstLine = text.slice(0, 4000).split(/\r\n|\n|\r/)[0] || '';
    var best = ',', bestCount = 0;
    [',', ';', '\t'].forEach(function (d) {
      var count = 0, inQuotes = false;
      for (var i = 0; i < firstLine.length; i++) {
        var ch = firstLine[i];
        if (ch === '"') inQuotes = !inQuotes;
        else if (ch === d && !inQuotes) count++;
      }
      if (count > bestCount) { best = d; bestCount = count; }
    });
    return best;
  }

  // A small, strict CSV reader (RFC 4180 style): handles quoted values,
  // separators and line breaks inside quotes, and "" as an escaped quote.
  // Event descriptions span many lines, so this matters a lot here.
  function splitRows(text, delimiter) {
    var rows = [], row = [], field = '', inQuotes = false, i = 0, n = text.length;
    while (i < n) {
      var ch = text[i];
      if (inQuotes) {
        if (ch === '"') {
          if (text[i + 1] === '"') { field += '"'; i += 2; continue; }
          inQuotes = false; i++; continue;
        }
        field += ch; i++; continue;
      }
      if (ch === '"') { inQuotes = true; i++; continue; }
      if (ch === delimiter) { row.push(field); field = ''; i++; continue; }
      if (ch === '\r' || ch === '\n') {
        row.push(field); rows.push(row); row = []; field = '';
        if (ch === '\r' && text[i + 1] === '\n') i++;
        i++;
        if (rows.length > MAX_ROWS + 2) break;
        continue;
      }
      field += ch; i++;
    }
    var unclosedQuote = inQuotes;
    if (field !== '' || row.length) { row.push(field); rows.push(row); }
    return { rows: rows, unclosedQuote: unclosedQuote };
  }

  function mapColumns(headers) {
    var map = {};
    var used = {};
    var normalised = headers.map(normaliseHeader);
    Object.keys(COLUMN_ALIASES).forEach(function (field) {
      var aliases = COLUMN_ALIASES[field];
      for (var a = 0; a < aliases.length; a++) {
        var idx = normalised.indexOf(aliases[a]);
        if (idx !== -1 && !used[idx]) { map[field] = idx; used[idx] = true; return; }
      }
    });
    return map;
  }

  function cleanShort(value) {
    if (value == null) return '';
    var s = String(value)
      .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
      .replace(/[\u200E\u200F\u202A-\u202E\u2066-\u2069]/g, '')   // invisible direction marks Windows adds to dates
      .replace(/\s+/g, ' ').trim();
    return s.length > MAX_FIELD ? s.slice(0, MAX_FIELD) : s;
  }
  function cleanMessage(value) {
    if (value == null) return '';
    var s = String(value)
      .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
      .replace(/[\u200E\u200F\u202A-\u202E\u2066-\u2069]/g, '')
      .replace(/\r\n?/g, '\n').trim();
    return s.length > MAX_MESSAGE ? s.slice(0, MAX_MESSAGE) + '\n[... trimmed: description longer than ' + MAX_MESSAGE + ' characters]' : s;
  }

  // ---------- Dates and times ----------
  // Event Viewer writes dates using the computer's regional setting, so
  // 03/04/2026 could be 3 April or 4 March. We look across the whole file
  // for a day above 12 to work out the order, and say so when we can't.
  var ISO = /^(\d{4})-(\d{1,2})-(\d{1,2})[T ](\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?\s*(Z|[+-]\d{2}:?\d{2})?$/i;
  var YMD = /^(\d{4})[\/.](\d{1,2})[\/.](\d{1,2})[ ,T]+(\d{1,2}):(\d{2})(?::(\d{2}))?(?:[.,]\d+)?\s*([AaPp]\.?\s?[Mm]\.?)?$/;
  var XYZ = /^(\d{1,2})[\/.\-](\d{1,2})[\/.\-](\d{4})[ ,T]+(\d{1,2}):(\d{2})(?::(\d{2}))?(?:[.,]\d+)?\s*([AaPp]\.?\s?[Mm]\.?)?$/;

  function hour24(h, ampm) {
    h = Number(h);
    if (!ampm) return h;
    var pm = /^p/i.test(ampm);
    if (h === 12) return pm ? 12 : 0;
    return pm ? h + 12 : h;
  }
  function validParts(y, mo, d, h, mi, s) {
    return mo >= 1 && mo <= 12 && d >= 1 && d <= 31 && h >= 0 && h <= 23 && mi >= 0 && mi <= 59 && s >= 0 && s <= 60;
  }
  // Times are kept as "wall clock" milliseconds. They are only compared with
  // each other, never converted to your own time zone.
  function wall(y, mo, d, h, mi, s, ms) {
    if (!validParts(y, mo, d, h, mi, s)) return null;
    return Date.UTC(y, mo - 1, d, h, mi, s, ms || 0);
  }

  /**
   * Work out the date order for a column of time strings.
   * order: 'auto' | 'mdy' | 'dmy'
   */
  function parseTimes(raws, order) {
    var dmyVotes = 0, mdyVotes = 0, sepDot = 0, xyzCount = 0;
    raws.forEach(function (r) {
      var m = XYZ.exec(r);
      if (!m) return;
      xyzCount++;
      var a = Number(m[1]), b = Number(m[2]);
      if (a > 12 && b <= 12) dmyVotes++;
      if (b > 12 && a <= 12) mdyVotes++;
      if (r.indexOf('.') !== -1 && r.indexOf('.') < 6) sepDot++;
    });

    var info = { detected: null, used: null, ambiguous: false, conflicting: false };
    if (xyzCount) {
      if (dmyVotes && mdyVotes) { info.conflicting = true; info.detected = dmyVotes >= mdyVotes ? 'dmy' : 'mdy'; }
      else if (dmyVotes) info.detected = 'dmy';
      else if (mdyVotes) info.detected = 'mdy';
      else { info.ambiguous = true; info.detected = sepDot > xyzCount / 2 ? 'dmy' : 'mdy'; }
    }
    var use = order === 'mdy' || order === 'dmy' ? order : info.detected;
    info.used = xyzCount ? use : null;

    var values = raws.map(function (r) {
      if (!r) return null;
      var m = ISO.exec(r);
      if (m) {
        var ms = m[7] ? Number(String(m[7]).slice(0, 3).padEnd(3, '0')) : 0;
        var t = wall(Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6] || 0), ms);
        if (t !== null && m[8] && !/^z$/i.test(m[8])) {
          var off = m[8].replace(':', '');
          var sign = off[0] === '-' ? -1 : 1;
          t -= sign * (Number(off.slice(1, 3)) * 60 + Number(off.slice(3, 5))) * 60000;
        }
        return t;
      }
      m = YMD.exec(r);
      if (m) return wall(Number(m[1]), Number(m[2]), Number(m[3]), hour24(m[4], m[7]), Number(m[5]), Number(m[6] || 0));
      m = XYZ.exec(r);
      if (m) {
        var a = Number(m[1]), b = Number(m[2]);
        var month = use === 'dmy' ? b : a, day = use === 'dmy' ? a : b;
        return wall(Number(m[3]), month, day, hour24(m[4], m[7]), Number(m[5]), Number(m[6] || 0));
      }
      // Last resort: let the browser try (handles things like "Sat Oct 24 2026 09:15:02").
      var guess = Date.parse(r);
      if (!isNaN(guess) && /\d{4}/.test(r) && /\d:\d\d/.test(r)) {
        var g = new Date(guess);
        return Date.UTC(g.getFullYear(), g.getMonth(), g.getDate(), g.getHours(), g.getMinutes(), g.getSeconds());
      }
      return null;
    });
    return { values: values, info: info };
  }

  function toEventId(value) {
    var m = /^\s*(\d{1,5})\b/.exec(String(value || ''));
    if (!m) return null;
    var n = Number(m[1]);
    return n >= 0 && n <= 65535 ? n : null;
  }

  /**
   * Parse CSV text. Never throws for bad input: problems are reported in
   * `errors` (analysis stops) and `warnings` (analysis continues).
   * options.dateOrder: 'auto' | 'mdy' | 'dmy'
   */
  function parse(text, options) {
    options = options || {};
    var result = {
      ok: false, events: [], columns: {}, headers: [], missing: [],
      errors: [], warnings: [], skippedRows: 0, totalRows: 0,
      format: 'generic', delimiter: ',', timesAvailable: false, timeInfo: null,
      messageFromUnnamedColumn: false, newestFirst: false
    };

    if (typeof text !== 'string') {
      result.errors.push('The file could not be read as text.');
      return result;
    }
    if (text.length > MAX_BYTES) {
      result.errors.push('This file is larger than 50 MB. In Event Viewer use "Filter Current Log" to pick fewer events or a shorter time range, then export again.');
      return result;
    }
    text = text.replace(/^\uFEFF/, '');
    if (!text.trim()) {
      result.errors.push('The file is empty.');
      return result;
    }
    if (/^ElfFile\u0000|^ElfChnk/.test(text.slice(0, 8)) || /\u0000/.test(text.slice(0, 4096))) {
      result.errors.push('This looks like a binary file, for example a raw .evtx log, not a CSV. In Event Viewer, open the log and use "Save All Events As..." or "Save Filtered Log File As..." and choose CSV (Comma Separated).');
      return result;
    }

    // Windows PowerShell 5.1 adds a "#TYPE ..." line above the headings
    // unless -NoTypeInformation is used. Skip it.
    var typeLine = /^#TYPE[^\r\n]*(\r\n|\n|\r)/.exec(text);
    if (typeLine) { text = text.slice(typeLine[0].length); result.format = 'powershell'; }

    result.delimiter = detectDelimiter(text);
    var split = splitRows(text, result.delimiter);
    var rows = split.rows.filter(function (r) { return r.some(function (c) { return String(c).trim() !== ''; }); });
    if (split.unclosedQuote) {
      result.warnings.push('The file ends inside an unclosed quotation mark, so the last event may be incomplete.');
    }
    if (rows.length < 1) {
      result.errors.push('No rows were found in the file.');
      return result;
    }

    var headers = rows[0].map(cleanShort);
    result.headers = headers;
    var columns = mapColumns(headers);

    // Event Viewer's own CSV export puts the event description in an extra
    // column that has no heading. Find it.
    var width = headers.length;
    if (columns.message === undefined) {
      var blank = headers.indexOf('');
      var longer = rows.slice(1, 50).some(function (r) { return r.length > width; });
      if (blank !== -1) { columns.message = blank; result.messageFromUnnamedColumn = true; }
      else if (longer) { columns.message = width; result.messageFromUnnamedColumn = true; }
    }
    result.columns = columns;

    var norm = headers.map(normaliseHeader);
    if (norm.indexOf('dateandtime') !== -1 && norm.indexOf('eventid') !== -1) result.format = 'eventviewer';
    else if (norm.indexOf('timecreated') !== -1 && (norm.indexOf('id') !== -1 || norm.indexOf('providername') !== -1)) result.format = 'powershell';

    if (Object.keys(columns).length === 0) {
      result.errors.push('None of the column headings were recognised. An Event Viewer CSV normally starts with headings such as "Level" (or "Keywords"), "Date and Time", "Source", "Event ID" and "Task Category".');
      return result;
    }
    if (columns.eventId === undefined) {
      result.missing.push('eventId');
      result.errors.push('This CSV does not contain an Event ID column, so the events cannot be identified. Event Viewer exports call it "Event ID" and PowerShell exports call it "Id". Check that the first row of the file holds the column headings.');
      return result;
    }

    ['time', 'message'].forEach(function (f) { if (columns[f] === undefined) result.missing.push(f); });
    if (columns.time === undefined) {
      result.warnings.push('This CSV does not appear to contain a date and time column. Events are analysed in the order they appear in the file, the failed logon time window is switched off, and the timeline cannot be shown.');
    }
    if (columns.message === undefined) {
      result.warnings.push('This CSV does not appear to contain the event description (message). Account names, source IP addresses, logon types and group names are written inside the description, so most correlation rules will have very little to work with.' + (columns.user !== undefined ? ' The User column will be used for account names where it has a value.' : ''));
    }

    var dataRows = rows.slice(1);
    if (dataRows.length > MAX_ROWS) {
      result.warnings.push('Only the first ' + MAX_ROWS.toLocaleString('en-GB') + ' events were loaded.');
      dataRows = dataRows.slice(0, MAX_ROWS);
    }
    result.totalRows = dataRows.length;

    function cell(row, field) {
      var idx = columns[field];
      if (idx === undefined) return '';
      if (field === 'message') {
        // If the description was not quoted, commas would split it across extra cells.
        var parts = idx === width - 1 || idx === width ? row.slice(idx) : [row[idx]];
        return cleanMessage(parts.join(result.delimiter));
      }
      return cleanShort(row[idx]);
    }

    var events = [];
    var badIds = 0;
    dataRows.forEach(function (row, i) {
      var idRaw = cell(row, 'eventId');
      var eventId = toEventId(idRaw);
      if (eventId === null) {
        if (idRaw) badIds++;
        result.skippedRows++;
        return;
      }
      events.push({
        row: i + 2,              // line number in a spreadsheet (heading is row 1)
        order: events.length,    // position in the file
        eventId: eventId,
        timeRaw: cell(row, 'time'),
        ts: null,
        level: cell(row, 'level'),
        keywords: cell(row, 'keywords'),
        source: cell(row, 'source'),
        task: cell(row, 'task'),
        user: cell(row, 'user'),
        computer: cell(row, 'computer'),
        logName: cell(row, 'logName'),
        message: cell(row, 'message')
      });
    });

    if (result.skippedRows) {
      result.warnings.push(result.skippedRows + ' row' + (result.skippedRows === 1 ? ' was' : 's were') + ' skipped because ' +
        (badIds ? 'the Event ID was not a number or was blank.' : 'they had no Event ID.'));
    }
    if (!events.length) {
      result.errors.push('The headings were recognised but no rows with a valid Event ID were found.');
      return result;
    }

    // Timestamps
    if (columns.time !== undefined) {
      var parsedTimes = parseTimes(events.map(function (e) { return e.timeRaw; }), options.dateOrder || 'auto');
      var good = 0;
      events.forEach(function (e, i) { e.ts = parsedTimes.values[i]; if (e.ts !== null) good++; });
      result.timeInfo = parsedTimes.info;
      result.timesAvailable = good > 0 && good >= events.length * 0.9;
      if (good < events.length && good > 0) {
        result.warnings.push((events.length - good) + ' event' + (events.length - good === 1 ? '' : 's') + ' had a date and time that could not be read.' +
          (result.timesAvailable ? ' They are placed by their position in the file.' : ' Too many to rely on, so time-based analysis is switched off.'));
      }
      if (!good) {
        var forced = options.dateOrder === 'mdy' || options.dateOrder === 'dmy';
        result.warnings.push('The dates in this file could not be read, so events are analysed in file order and the failed logon time window is switched off.' +
          (forced ? ' The "Date format" setting is forcing ' + (options.dateOrder === 'dmy' ? 'day/month/year' : 'month/day/year') + ', which does not fit these dates. Try "Detect automatically".' : ''));
      }
      var ti = parsedTimes.info;
      if (result.timesAvailable && ti.used && options.dateOrder !== 'mdy' && options.dateOrder !== 'dmy') {
        if (ti.ambiguous) {
          result.warnings.push('Every date in this file has a day of 12 or less, so it is impossible to tell 03/04 (3 April) from 03/04 (4 March). The tool assumed ' +
            (ti.used === 'dmy' ? 'day/month/year' : 'month/day/year') + '. If that is wrong, change "Date format" in the settings.');
        } else if (ti.conflicting) {
          result.warnings.push('Some dates look like day/month/year and others like month/day/year. The tool used ' + (ti.used === 'dmy' ? 'day/month/year' : 'month/day/year') +
            ' because most dates matched it. Times may be out of order.');
        }
      }
    }

    // Event Viewer lists the newest event first. Analysis needs oldest first.
    if (result.timesAvailable) {
      var up = 0, down = 0;
      for (var k = 1; k < events.length; k++) {
        var a = events[k - 1].ts, b = events[k].ts;
        if (a === null || b === null) continue;
        if (b > a) up++; else if (b < a) down++;
      }
      result.newestFirst = down > up;
      // Fill any unreadable times from their neighbours so ordering stays sensible.
      var last = null;
      var seq = result.newestFirst ? events.slice().reverse() : events;
      seq.forEach(function (e) { if (e.ts === null) { e.ts = last; e.tsEstimated = true; } else last = e.ts; });
      events.sort(function (x, y) {
        var tx = x.ts === null ? -Infinity : x.ts, ty = y.ts === null ? -Infinity : y.ts;
        if (tx !== ty) return tx - ty;
        return result.newestFirst ? y.order - x.order : x.order - y.order;
      });
    } else {
      // Without times we cannot know the order for certain. Event Viewer's
      // default is newest first, so we reverse its own export format.
      if (result.format === 'eventviewer' || result.format === 'powershell') {
        events.reverse();
        result.newestFirst = true;
      }
    }
    events.forEach(function (e, i) { e.seq = i; });

    result.events = events;
    result.ok = true;
    return result;
  }

  var api = {
    parse: parse, decodeBytes: decodeBytes, parseTimes: parseTimes, normaliseHeader: normaliseHeader,
    FIELD_LABELS: FIELD_LABELS, COLUMN_ALIASES: COLUMN_ALIASES, MAX_BYTES: MAX_BYTES
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.EventCSV = api;
})(this);

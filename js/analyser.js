/* Windows Security Event Log Triage Tool - the analysis "brain".
   1. Reads the useful details (account, source IP, logon type, group...) out
      of each event's description text.
   2. Runs simple, explainable rules and correlations.
   3. Builds the numbers for the dashboard.
   It never touches the page, so it can be tested on its own. */
(function (root) {
  'use strict';

  var DEFAULTS = { failures: 5, windowMinutes: 10, sprayAccounts: 4 };
  var SEVERITIES = ['High', 'Medium', 'Low', 'Informational'];
  var SEV_RANK = { High: 3, Medium: 2, Low: 1, Informational: 0 };

  // ---------- Event ID catalogue ----------
  // "analysed" IDs have their details extracted and feed the rules.
  var CATALOGUE = {
    4624: { name: 'Successful logon', category: 'Authentication', severity: 'Informational', log: 'Security',
      plain: 'An account logged on successfully. On its own this is normal: it becomes interesting as context, for example right after many failures.' },
    4625: { name: 'Failed logon', category: 'Authentication', severity: 'Low', log: 'Security',
      plain: 'Someone tried to log on and it failed. One failure is usually a typo; many in a row deserve a look.' },
    4688: { name: 'Process created', category: 'Process activity', severity: 'Informational', log: 'Security',
      plain: 'A program started. Shows which program, who started it, its parent program and (if enabled) the full command line. Off by default.' },
    4720: { name: 'User account created', category: 'Account management', severity: 'Medium', log: 'Security',
      plain: 'A new user account was created. Often routine IT work, but attackers create accounts to keep access.' },
    4726: { name: 'User account deleted', category: 'Account management', severity: 'Low', log: 'Security',
      plain: 'A user account was deleted. Usually routine clean-up, but can also be someone covering tracks.' },
    4728: { name: 'Member added to global security group', category: 'Group membership', severity: 'Medium', log: 'Security',
      plain: 'An account was added to a domain-wide (global) security group, which can grant new access across the network.' },
    4732: { name: 'Member added to local security group', category: 'Group membership', severity: 'Medium', log: 'Security',
      plain: 'An account was added to a group on this computer, such as the local Administrators group.' },
    1102: { name: 'Security audit log cleared', category: 'Audit and logging', severity: 'High', log: 'Security',
      plain: 'Someone cleared the Security log, deleting its history. Sometimes maintenance, but also a classic way to hide evidence.' },
    4104: { name: 'PowerShell script block logged', category: 'PowerShell', severity: 'Informational', log: 'Microsoft-Windows-PowerShell/Operational',
      plain: 'PowerShell recorded the script or command it ran. Script block logging gives valuable visibility into commands and scripts executed on the endpoint.' },
    7045: { name: 'Service installed', category: 'Services', severity: 'Low', log: 'System',
      plain: 'A new Windows service was installed. Normal when installing software, but services are also a common way to make malware start automatically.' }
  };
  // Recognised by name only, so beginners see what they are without extra rules.
  var KNOWN = {
    4634: ['Account logged off', 'Authentication'], 4647: ['User initiated logoff', 'Authentication'],
    4648: ['Logon using explicit credentials', 'Authentication'], 4672: ['Special privileges assigned to new logon', 'Authentication'],
    4740: ['User account locked out', 'Account management'], 4722: ['User account enabled', 'Account management'],
    4723: ['User tried to change own password', 'Account management'], 4724: ['Password reset attempted', 'Account management'],
    4725: ['User account disabled', 'Account management'], 4738: ['User account changed', 'Account management'],
    4767: ['User account unlocked', 'Account management'], 4729: ['Member removed from global security group', 'Group membership'],
    4733: ['Member removed from local security group', 'Group membership'], 4756: ['Member added to universal security group', 'Group membership'],
    4798: ['Local group membership enumerated', 'Account management'], 4799: ['Security group membership enumerated', 'Group membership'],
    4776: ['Credential validation (NTLM)', 'Authentication'], 4768: ['Kerberos ticket (TGT) requested', 'Authentication'],
    4769: ['Kerberos service ticket requested', 'Authentication'], 4771: ['Kerberos pre-authentication failed', 'Authentication'],
    4689: ['Process exited', 'Process activity'], 4697: ['Service installed (Security log)', 'Services'],
    4719: ['System audit policy changed', 'Audit and logging'], 4616: ['System time changed', 'Other'],
    4608: ['Windows is starting up', 'Other'], 4609: ['Windows is shutting down', 'Other'],
    5379: ['Credential Manager credentials read', 'Other'], 4907: ['Auditing settings on object changed', 'Audit and logging'],
    4103: ['PowerShell module logging', 'PowerShell'], 4698: ['Scheduled task created', 'Other'],
    5140: ['Network share accessed', 'Other'], 4800: ['Workstation locked', 'Other'], 4801: ['Workstation unlocked', 'Other']
  };

  var LOGON_TYPES = {
    2: 'Interactive (at the keyboard)', 3: 'Network (e.g. file share)', 4: 'Batch (scheduled task)', 5: 'Service',
    7: 'Unlock', 8: 'Network cleartext', 9: 'New credentials (runas /netonly)', 10: 'Remote interactive (RDP)', 11: 'Cached interactive'
  };

  // Common NTSTATUS codes found in 4625 "Sub Status" / "Status".
  var FAILURE_CODES = {
    '0xc000006a': 'Wrong password for a valid user name',
    '0xc0000064': 'User name does not exist',
    '0xc000006d': 'Bad user name or password',
    '0xc0000234': 'Account is locked out',
    '0xc0000072': 'Account is disabled',
    '0xc000006f': 'Logon outside allowed hours',
    '0xc0000070': 'Logon from a workstation that is not allowed',
    '0xc0000071': 'Password has expired',
    '0xc0000193': 'Account has expired',
    '0xc0000224': 'User must change password at next logon',
    '0xc0000133': 'Clocks between computers are out of sync',
    '0xc000015b': 'Logon type not granted to this user',
    '0xc0000413': 'Authentication firewall blocked the logon'
  };

  // Groups whose members gain wide or administrative control.
  var PRIVILEGED_GROUPS = [
    'administrators', 'domain admins', 'enterprise admins', 'schema admins', 'account operators', 'backup operators',
    'server operators', 'print operators', 'remote desktop users', 'remote management users', 'group policy creator owners',
    'dnsadmins', 'hyper-v administrators', 'key admins', 'enterprise key admins', 'cert publishers', 'administrators (built-in)'
  ];

  var SYSTEM_ACCOUNTS = ['system', 'local service', 'network service', 'anonymous logon', 'font driver host', 'window manager', 'iusr'];

  // ---------- Small helpers ----------
  function plural(n, word, many) { return n + ' ' + (n === 1 ? word : (many || word + 's')); }
  function uniq(list) { var s = []; list.forEach(function (x) { if (x && s.indexOf(x) === -1) s.push(x); }); return s; }
  function blank(v) { return v === undefined || v === null || v === '' || v === '-' || /^null sid$/i.test(v) || /^s-1-0-0$/i.test(v); }
  function val(v) { return blank(v) ? null : String(v).trim(); }
  function maxSev(a, b) { return (SEV_RANK[a] || 0) >= (SEV_RANK[b] || 0) ? a : b; }

  // ---------- Reading the description text ----------
  // A Windows event description looks like:
  //   An account failed to log on.
  //
  //   Account For Which Logon Failed:
  //       Account Name:   jsmith
  // A line ending in ":" with nothing after it starts a section. A blank line
  // (or a line that is not indented) ends it.
  var SECTION_WORDS = ['Subject', 'New Logon', 'Account For Which Logon Failed', 'Logon Information', 'Failure Information',
    'Network Information', 'Process Information', 'Detailed Authentication Information', 'New Account', 'Target Account',
    'Member', 'Group', 'Attributes', 'Creator Subject', 'Target Subject', 'Additional Information', 'Changed Attributes'];
  var FIELD_WORDS = ['Security ID', 'Account Name', 'Account Domain', 'Domain Name', 'Logon ID', 'Logon Type', 'Workstation Name',
    'Source Network Address', 'Source Port', 'Failure Reason', 'Status', 'Sub Status', 'Process Name', 'Process ID', 'Group Name',
    'Group Domain', 'New Process Name', 'Creator Process Name', 'Process Command Line', 'Logon Process', 'Authentication Package',
    'Caller Process Name', 'Elevated Token', 'Token Elevation Type', 'SAM Account Name', 'Privileges', 'Service Name', 'Service File Name',
    'Service Type', 'Service Start Type', 'Service Account', 'ScriptBlock ID', 'Path'];

  function parseMessage(message) {
    var out = { summary: '', sections: {}, top: {}, all: [] };
    if (!message) return out;
    var text = message;
    // Some exports squash the description onto one line. Put line breaks
    // back before the labels we know so the sections can still be found.
    if (text.indexOf('\n') === -1 && text.length > 60) {
      SECTION_WORDS.forEach(function (w) { text = text.split(' ' + w + ': ').join('\n' + w + ':\n'); });
      SECTION_WORDS.forEach(function (w) { text = text.replace(new RegExp('\\s' + w + ':\\s', 'g'), '\n' + w + ':\n'); });
      FIELD_WORDS.forEach(function (w) { text = text.replace(new RegExp('\\s(' + w + '):', 'g'), '\n\t$1:'); });
    }
    var lines = text.split('\n');
    var indented = /\n[\t ]+\S/.test(text);
    var section = '';
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (!line.trim()) { section = ''; continue; }
      if (!out.summary) { out.summary = line.trim(); }
      var m = /^(\s*)([A-Za-z][A-Za-z0-9 ()\/\-'.]{0,60}?)\s*:\s*(.*)$/.exec(line);
      if (!m) continue;
      var lead = m[1], key = m[2].trim().toLowerCase(), value = m[3].trim();
      if (value === '' && !lead) { section = key; out.sections[key] = out.sections[key] || {}; continue; }
      if (indented && !lead) section = '';
      var target = section ? out.sections[section] : out.top;
      if (target[key] === undefined) target[key] = value;
      out.all.push({ section: section, key: key, value: value });
    }
    return out;
  }

  function get(pm, sections, key) {
    for (var i = 0; i < sections.length; i++) {
      var s = sections[i] === '' ? pm.top : pm.sections[sections[i]];
      if (s && s[key] !== undefined && !blank(s[key])) return s[key];
    }
    return null;
  }
  function getAnywhere(pm, key) {
    if (!blank(pm.top[key])) return pm.top[key];
    for (var i = 0; i < pm.all.length; i++) if (pm.all[i].key === key && !blank(pm.all[i].value)) return pm.all[i].value;
    return null;
  }

  // ---------- Account identity ----------
  // The same account can be written as "temp-admin", "WS-LAB-01\temp-admin",
  // "CN=temp-admin,OU=Staff,DC=lab" or as a SID. These keys let us match them.
  function nameFrom(value) {
    var v = val(value);
    if (!v) return null;
    var cn = /^CN=([^,]+)/i.exec(v);
    if (cn) return cn[1].trim();
    if (/^S-1-\d/i.test(v)) return null;
    if (v.indexOf('\\') !== -1) return v.split('\\').pop().trim() || null;
    if (v.indexOf('@') > 0) return v.split('@')[0];
    return v;
  }
  function identityKeys(account) {
    var keys = [];
    if (!account) return keys;
    [account.name, account.sid].forEach(function (v) {
      var x = val(v);
      if (!x) return;
      if (/^S-1-\d/i.test(x)) keys.push('sid:' + x.toLowerCase());
      var n = nameFrom(x);
      if (n) keys.push('name:' + n.toLowerCase());
    });
    return uniq(keys);
  }
  function account(pm, section, opts) {
    opts = opts || {};
    var s = section === '' ? pm.top : pm.sections[section];
    if (!s) return null;
    var name = val(s['account name']) || (opts.sam ? val(get(pm, ['attributes'], 'sam account name')) : null);
    var sid = val(s['security id']);
    var domain = val(s['account domain']) || val(s['domain name']);
    // Domain group changes write the member as "CN=Full Name,OU=...". The
    // Security ID usually holds the shorter logon name, so prefer that.
    var display = name && /^CN=/i.test(name) && nameFrom(sid) ? nameFrom(sid) : nameFrom(name) || nameFrom(sid);
    if (!display && !sid) return null;
    return { name: display || sid, raw: name, sid: sid, domain: domain };
  }
  function isSystemAccount(name) {
    if (!name) return true;
    var n = String(name).toLowerCase();
    return /\$$/.test(n) || SYSTEM_ACCOUNTS.indexOf(n) !== -1 || /^(dwm|umfd)-\d+$/.test(n) || /^s-1-5-(18|19|20)$/.test(n);
  }
  function isPrivilegedGroup(name) {
    if (!name) return { privileged: false };
    var n = String(name).toLowerCase().split('\\').pop().trim();
    if (PRIVILEGED_GROUPS.indexOf(n) !== -1) return { privileged: true, reason: '"' + name + '" is a built-in group with administrative or remote access rights.' };
    if (/admin/.test(n)) return { privileged: true, reason: 'The group name contains "admin", which usually means elevated rights.' };
    return { privileged: false };
  }
  function cleanIp(v) {
    var x = val(v);
    if (!x) return null;
    if (x === '::1' || x === '127.0.0.1' || x === '::ffff:127.0.0.1') return x;
    return x.replace(/^::ffff:/i, '');
  }

  // ---------- PowerShell clues ----------
  // A short, explainable list. Not malware detection: just "this text is
  // hard for a human to read, so take a closer look".
  function decodeEncodedCommand(b64) {
    try {
      if (typeof atob !== 'function' && typeof Buffer === 'undefined') return null;
      var bin = typeof atob === 'function' ? atob(b64) : Buffer.from(b64, 'base64').toString('binary');
      var out = '';
      for (var i = 0; i + 1 < bin.length; i += 2) out += String.fromCharCode(bin.charCodeAt(i) | (bin.charCodeAt(i + 1) << 8));
      if (!out || /[\u0000-\u0008\u000E-\u001F]/.test(out)) return null;
      return out.length > 2000 ? out.slice(0, 2000) + ' ...' : out;
    } catch (e) { return null; }
  }
  function powershellClues(text) {
    var clues = [];
    var decoded = null;
    if (!text) return { clues: clues, decoded: decoded };
    var enc = /(?:^|\s)-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+([A-Za-z0-9+\/=]{20,})/i.exec(text);
    if (enc) {
      clues.push('Uses -EncodedCommand, which hides the real command as Base64 text.');
      decoded = decodeEncodedCommand(enc[1]);
    }
    if (/FromBase64String/i.test(text)) clues.push('Decodes Base64 text at run time (FromBase64String).');
    if (!enc && /[A-Za-z0-9+\/]{120,}={0,2}/.test(text)) clues.push('Contains a very long Base64-looking string.');
    var ticks = (text.match(/`[a-zA-Z]/g) || []).length;
    if (ticks >= 8) clues.push('Contains ' + ticks + ' backtick escapes inside words, a common way to break up keywords.');
    var chars = (text.match(/\[char\]\s*\d+/gi) || []).length;
    if (chars >= 5) clues.push('Builds text from ' + chars + ' character codes ([char]NN).');
    if (clues.length && /\b(IEX|Invoke-Expression)\b/i.test(text)) clues.push('Runs the resulting text as code (Invoke-Expression / IEX).');
    if (/-w(indowstyle)?\s+hidden/i.test(text) && clues.length) clues.push('Runs with a hidden window.');
    return { clues: clues, decoded: decoded };
  }

  var USER_WRITABLE = /\\(users|appdata|temp|tmp|programdata|public|downloads|perflogs)\\/i;
  function serviceClues(path) {
    var clues = [];
    if (!path) return clues;
    if (USER_WRITABLE.test(path)) clues.push('The program lives in a folder ordinary users can write to (' + (USER_WRITABLE.exec(path)[1]) + '), not Program Files or Windows.');
    if (/(cmd(\.exe)?\s+\/c|powershell|pwsh|mshta|rundll32|regsvr32|wscript|cscript)/i.test(path)) clues.push('The service runs a command interpreter or script host rather than a normal service program.');
    return clues;
  }

  // ---------- Per-event details ----------
  function enrich(e) {
    var pm = parseMessage(e.message);
    var cat = CATALOGUE[e.eventId];
    var known = KNOWN[e.eventId];
    var d = {
      name: cat ? cat.name : known ? known[0] : 'Event ' + e.eventId,
      category: cat ? cat.category : known ? known[1] : 'Other',
      analysed: !!cat, recognised: !!(cat || known),
      baseSeverity: cat ? cat.severity : 'Informational',
      summary: pm.summary,
      account: null, actor: null, ip: null, workstation: null, logonType: null, details: []
    };
    function add(label, value) { if (!blank(value)) d.details.push([label, String(value)]); }

    switch (e.eventId) {
      case 4624:
      case 4625: {
        var target = account(pm, e.eventId === 4624 ? 'new logon' : 'account for which logon failed');
        d.account = target;
        d.actor = account(pm, 'subject');
        var lt = get(pm, ['logon information', ''], 'logon type') || getAnywhere(pm, 'logon type');
        d.logonType = lt && /^\d+$/.test(lt) ? Number(lt) : null;
        d.ip = cleanIp(get(pm, ['network information'], 'source network address') || getAnywhere(pm, 'source network address'));
        d.workstation = val(get(pm, ['network information'], 'workstation name') || getAnywhere(pm, 'workstation name'));
        add('Logon type', d.logonType !== null ? d.logonType + ' - ' + (LOGON_TYPES[d.logonType] || 'Other') : null);
        add('Source IP', d.ip);
        add('Workstation', d.workstation);
        if (e.eventId === 4625) {
          var sub = get(pm, ['failure information', ''], 'sub status') || getAnywhere(pm, 'sub status');
          var st = get(pm, ['failure information', ''], 'status') || getAnywhere(pm, 'status');
          var code = (sub && sub !== '0x0' ? sub : st || '').toLowerCase();
          d.failureCode = code || null;
          d.failureReason = FAILURE_CODES[code] || val(get(pm, ['failure information', ''], 'failure reason') || getAnywhere(pm, 'failure reason'));
          add('Failure reason', d.failureReason ? d.failureReason + (code ? ' (' + code + ')' : '') : null);
        } else {
          add('Authentication', get(pm, ['detailed authentication information'], 'authentication package') || getAnywhere(pm, 'authentication package'));
          add('Elevated token', get(pm, ['logon information'], 'elevated token'));
        }
        add('Process', get(pm, ['process information'], 'process name') || get(pm, ['process information'], 'caller process name'));
        break;
      }
      case 4720:
        d.account = account(pm, 'new account', { sam: true });
        d.actor = account(pm, 'subject');
        break;
      case 4726:
        d.account = account(pm, 'target account');
        d.actor = account(pm, 'subject');
        break;
      case 4728:
      case 4732: {
        d.account = account(pm, 'member');
        d.actor = account(pm, 'subject');
        var g = pm.sections.group || {};
        var gname = val(g['group name']) || nameFrom(g['account name']) || nameFrom(g['security id']);
        d.group = gname;
        d.groupDomain = val(g['group domain']) || val(g['account domain']);
        d.privileged = isPrivilegedGroup(gname);
        add('Group', gname ? (d.groupDomain ? d.groupDomain + '\\' : '') + gname : null);
        if (d.privileged.privileged) add('Privileged group', 'Yes. ' + d.privileged.reason);
        break;
      }
      case 1102:
        d.actor = account(pm, 'subject');
        d.account = d.actor;
        break;
      case 4688: {
        d.actor = account(pm, 'creator subject') || account(pm, 'subject');
        d.account = account(pm, 'target subject') || d.actor;
        if (d.account && blank(d.account.raw) && !d.account.sid) d.account = d.actor;
        d.process = val(get(pm, ['process information'], 'new process name') || getAnywhere(pm, 'new process name'));
        d.parent = val(get(pm, ['process information'], 'creator process name') || getAnywhere(pm, 'creator process name'));
        d.commandLine = val(get(pm, ['process information'], 'process command line') || getAnywhere(pm, 'process command line'));
        add('Process', d.process);
        add('Parent process', d.parent);
        add('Command line', d.commandLine);
        var pc = powershellClues(d.commandLine);
        d.psClues = pc.clues; d.psDecoded = pc.decoded;
        break;
      }
      case 4104: {
        var lines = String(e.message || '').split('\n');
        var start = /scriptblock text/i.test(lines[0] || '') ? 1 : 0;
        var endIdx = lines.length;
        for (var i = start; i < lines.length; i++) if (/^\s*ScriptBlock ID:/i.test(lines[i])) { endIdx = i; break; }
        d.script = lines.slice(start, endIdx).join('\n').trim();
        d.scriptPath = val(getAnywhere(pm, 'path'));
        add('Script path', d.scriptPath);
        var c = powershellClues(d.script);
        d.psClues = c.clues; d.psDecoded = c.decoded;
        break;
      }
      case 7045:
        d.service = val(getAnywhere(pm, 'service name'));
        d.serviceFile = val(getAnywhere(pm, 'service file name'));
        d.serviceStart = val(getAnywhere(pm, 'service start type'));
        d.serviceAccount = val(getAnywhere(pm, 'service account'));
        add('Service name', d.service);
        add('Program', d.serviceFile);
        add('Start type', d.serviceStart);
        add('Runs as', d.serviceAccount);
        d.serviceClues = serviceClues(d.serviceFile);
        break;
      default:
        d.account = account(pm, 'new logon') || account(pm, 'target account') || account(pm, 'member') || account(pm, 'subject');
        d.ip = cleanIp(getAnywhere(pm, 'source network address'));
    }

    // Fall back to the User column when the description had no account.
    if (!d.account && e.user && !/^s-1-/i.test(e.user) && !blank(e.user)) d.account = { name: nameFrom(e.user), raw: e.user, sid: null, domain: null };
    if (!d.actor && e.user && (e.eventId === 4104 || e.eventId === 7045) && !blank(e.user)) d.actor = { name: nameFrom(e.user) || e.user, raw: e.user, sid: /^s-1-/i.test(e.user) ? e.user : null };
    d.accountName = d.account ? d.account.name : null;
    d.actorName = d.actor ? d.actor.name : null;
    d.systemAccount = isSystemAccount(d.accountName);
    if (d.actor && d.actorName && (e.eventId === 4720 || e.eventId === 4726 || e.eventId === 4728 || e.eventId === 4732)) add('Performed by', (d.actor.domain ? d.actor.domain + '\\' : '') + d.actorName);
    e.d = d;
    return e;
  }

  // ---------- Rules ----------
  var RULES = [
    { key: 'failures', name: 'Repeated failed logons', ids: [4625], points: 10, summary: 'Counts 4625 failures per account, inside the time window if one is set.' },
    { key: 'successAfter', name: 'Possible password guessing followed by success', ids: [4625, 4624], points: 20, summary: 'A 4624 success for the same account after reaching the failure threshold.' },
    { key: 'spray', name: 'Failed logons across many accounts', ids: [4625], points: 15, summary: 'One source IP failing to log on to several different accounts (password spraying pattern).' },
    { key: 'newPriv', name: 'New account granted privileges', ids: [4720, 4728, 4732], points: 30, summary: 'A 4720 account creation followed by a 4728 or 4732 group addition for the same account.' },
    { key: 'created', name: 'User account created', ids: [4720], points: 5, summary: 'Each 4720 that was not already part of the correlation above.' },
    { key: 'groupAdd', name: 'Member added to security group', ids: [4728, 4732], points: 10, summary: 'Each 4728 / 4732. Privileged groups score +25 and are rated High.' },
    { key: 'deleted', name: 'User account deleted', ids: [4726], points: 5, summary: 'Each 4726. Rated Medium if the account was also created in this file.' },
    { key: 'logCleared', name: 'Security audit log cleared', ids: [1102], points: 30, summary: 'Every 1102 event.' },
    { key: 'service', name: 'New service installed', ids: [7045], points: 10, summary: 'Each 7045. Rated Medium if the program path looks unusual.' },
    { key: 'powershell', name: 'Encoded or obfuscated PowerShell', ids: [4104, 4688], points: 15, summary: 'A 4104 script block or 4688 command line with clues such as -EncodedCommand.' }
  ];
  var PRIV_GROUP_POINTS = 25;

  function fmtSpan(ms) {
    if (ms === null || ms === undefined || !isFinite(ms)) return null;
    var s = Math.round(ms / 1000);
    if (s < 60) return plural(s, 'second');
    var m = Math.round(s / 60);
    if (m < 120) return plural(m, 'minute');
    var h = Math.round(m / 6) / 10;
    if (h < 48) return h + ' hours';
    return Math.round(h / 24) + ' days';
  }
  function countList(values) {
    var m = new Map();
    values.forEach(function (v) { if (v !== null && v !== undefined && v !== '') m.set(v, (m.get(v) || 0) + 1); });
    return Array.from(m.entries()).sort(function (a, b) { return b[1] - a[1] || String(a[0]).localeCompare(String(b[0])); });
  }
  function describeCounts(values, empty) {
    var c = countList(values);
    if (!c.length) return empty || 'Not recorded';
    return c.slice(0, 6).map(function (x) { return x[0] + (c.length > 1 || x[1] > 1 ? ' (' + x[1] + ')' : ''); }).join(', ') + (c.length > 6 ? ', and ' + (c.length - 6) + ' more' : '');
  }
  function sequenceText(events, max) {
    max = max || 12;
    var ids = events.map(function (e) { return e.eventId; });
    if (ids.length <= max) return ids.join(' → ');
    return ids.slice(0, 4).join(' → ') + ' → … (' + (ids.length - 6) + ' more) … → ' + ids.slice(-2).join(' → ');
  }
  function timeRange(events) {
    var withT = events.filter(function (e) { return e.ts !== null; });
    if (!withT.length) return null;
    var first = withT[0], last = withT[withT.length - 1];
    return { start: first.ts, end: last.ts, startRaw: first.timeRaw, endRaw: last.timeRaw, span: last.ts - first.ts };
  }

  // Largest group of events inside any window of `windowMs` (sliding).
  function bestWindow(events, windowMs) {
    if (!windowMs) return events.slice();
    var best = [], j = 0;
    for (var i = 0; i < events.length; i++) {
      while (events[i].ts - events[j].ts > windowMs) j++;
      if (i - j + 1 > best.length) best = events.slice(j, i + 1);
    }
    return best;
  }

  function analyse(parsed, settings) {
    var t = Object.assign({}, DEFAULTS, settings || {});
    var events = parsed.events.map(function (e) { return enrich(Object.assign({}, e)); });
    var useWindow = parsed.timesAvailable && t.windowMinutes > 0;
    var windowMs = useWindow ? t.windowMinutes * 60000 : 0;
    var alerts = [];
    var notes = [];
    if (t.windowMinutes > 0 && !parsed.timesAvailable) notes.push('The failed logon time window is switched off because this file has no readable timestamps. Failures are counted across the whole file.');

    var byId = {};
    events.forEach(function (e) { (byId[e.eventId] = byId[e.eventId] || []).push(e); });
    function evs(id) { return byId[id] || []; }

    function makeAlert(a) {
      a.eventIds = uniq(a.events.map(function (e) { return e.eventId; })).sort();
      a.range = timeRange(a.events);
      a.ips = a.ips || uniq(a.events.map(function (e) { return e.d.ip; }));
      a.workstations = a.workstations || uniq(a.events.map(function (e) { return e.d.workstation; }));
      a.categories = uniq(a.events.map(function (e) { return e.d.category; }));
      a.accounts = uniq([a.account].concat(a.events.map(function (e) { return e.d.accountName; })).concat(a.events.map(function (e) { return e.d.actorName; })));
      a.entity = a.entity || a.account || 'No account recorded';
      alerts.push(a);
      return a;
    }

    // --- Failed logons, grouped by account ---
    var failByAccount = new Map();
    evs(4625).forEach(function (e) {
      var n = e.d.accountName;
      if (!n) return;
      var k = n.toLowerCase();
      if (!failByAccount.has(k)) failByAccount.set(k, { name: n, events: [] });
      failByAccount.get(k).events.push(e);
    });
    var successByAccount = new Map();
    evs(4624).forEach(function (e) {
      var n = e.d.accountName;
      if (!n) return;
      var k = n.toLowerCase();
      if (!successByAccount.has(k)) successByAccount.set(k, []);
      successByAccount.get(k).push(e);
    });

    var flaggedFailAccounts = {};
    failByAccount.forEach(function (info, key) {
      var burst = bestWindow(info.events, windowMs);
      if (burst.length < t.failures) return;
      flaggedFailAccounts[key] = true;
      var successes = successByAccount.get(key) || [];
      var lastFail = burst[burst.length - 1];
      var followed = successes.some(function (s) { return s.seq > lastFail.seq; });
      var observed = [
        ['Failed logons', String(info.events.length) + (useWindow && burst.length !== info.events.length ? ' in total, ' + burst.length + ' within ' + t.windowMinutes + ' minutes' : '')],
        ['Source IP', describeCounts(burst.map(function (e) { return e.d.ip; }))],
        ['Workstation', describeCounts(burst.map(function (e) { return e.d.workstation; }))],
        ['Logon type', describeCounts(burst.map(function (e) { return e.d.logonType !== null ? e.d.logonType + ' (' + (LOGON_TYPES[e.d.logonType] || 'Other') + ')' : null; }))],
        ['Failure reason', describeCounts(burst.map(function (e) { return e.d.failureReason; }))],
        ['Followed by a successful logon', followed ? 'Yes (see the related alert)' : 'No successful logon for this account appears afterwards in this file']
      ];
      var tr = timeRange(burst);
      if (tr && tr.span !== null) observed.splice(1, 0, ['Time between first and last', fmtSpan(tr.span)]);
      var reasons = burst.map(function (e) { return e.d.failureCode; });
      var benign = ['The user forgot or mistyped their password, or Caps Lock was on.',
        'An application, mapped drive, phone or service is still using an old password and keeps retrying.',
        'A password was changed recently and a device has not caught up yet.'];
      if (reasons.indexOf('0xc0000064') !== -1) benign.push('Some failures are for a user name that does not exist, which can be a simple typo in the user name.');
      makeAlert({
        rule: 'failures', name: 'Repeated failed logons', severity: 'Medium', points: 10, account: info.name,
        events: burst, sequence: sequenceText(burst),
        observed: observed,
        why: 'Repeated authentication failures may indicate password guessing, but could also be caused by a legitimate user entering the wrong password or an application using outdated credentials.',
        benign: benign,
        investigate: ['Identify the source system (IP address and workstation name) and who owns it.', 'Review the affected account: is it a person, a service account or a disabled account?',
          'Check whether the failures were followed by a successful logon.', 'Determine whether other accounts were targeted from the same source.', 'Review MFA, VPN or endpoint telemetry if available.'],
        threshold: t.failures + ' failures' + (useWindow ? ' within ' + t.windowMinutes + ' minutes' : ' in the file')
      });
    });

    // --- Failures followed by success (same account) ---
    successByAccount.forEach(function (successes, key) {
      var fails = (failByAccount.get(key) || { events: [] }).events;
      if (!fails.length) return;
      var prevSeq = -1;
      for (var i = 0; i < successes.length; i++) {
        var s = successes[i];
        var before = fails.filter(function (f) {
          if (f.seq >= s.seq || f.seq <= prevSeq) return false;
          if (windowMs && s.ts !== null && f.ts !== null && s.ts - f.ts > windowMs) return false;
          return true;
        });
        prevSeq = s.seq;
        if (before.length < t.failures) continue;
        var failIps = uniq(before.map(function (f) { return f.d.ip; }));
        var failWs = uniq(before.map(function (f) { return f.d.workstation; }));
        var sameIp = s.d.ip && failIps.indexOf(s.d.ip) !== -1;
        var sameWs = !s.d.ip && s.d.workstation && failWs.indexOf(s.d.workstation) !== -1;
        var strong = sameIp || sameWs;
        var gap = s.ts !== null && before[before.length - 1].ts !== null ? s.ts - before[before.length - 1].ts : null;
        var seqEvents = before.concat([s]);
        makeAlert({
          rule: 'successAfter', name: 'Possible password guessing followed by success',
          severity: strong ? 'High' : 'Medium', points: 20, account: s.d.accountName,
          events: seqEvents, sequence: sequenceText(seqEvents),
          observed: [
            ['Failed logins', String(before.length)],
            ['Successful login', 'Yes' + (s.timeRaw ? ', at ' + s.timeRaw : '')],
            ['Time from last failure to success', gap !== null ? fmtSpan(gap) : 'Unknown'],
            ['Failure source IP', describeCounts(before.map(function (f) { return f.d.ip; }))],
            ['Success source IP', s.d.ip || 'Not recorded'],
            ['Same source', sameIp ? 'Yes, the success came from the same IP address as the failures' : sameWs ? 'Yes, the same workstation name' : 'No or unknown, so the link is weaker'],
            ['Success logon type', s.d.logonType !== null ? s.d.logonType + ' (' + (LOGON_TYPES[s.d.logonType] || 'Other') + ')' : 'Not recorded']
          ],
          why: 'Multiple failed login attempts followed by a successful login can indicate that a password was eventually guessed.' +
            (strong ? ' Here the success came from the same source as the failures, which makes the link stronger.' : ' The success came from a different or unknown source, so these may be unrelated, which is why this is rated Medium.'),
          benign: ['The legitimate user may simply have entered the wrong password several times before getting it right.',
            'A device kept retrying an old password until the user updated it.'],
          investigate: ['Verify the source IP and whether it is expected for this user.', 'Check whether the device belongs to the user.',
            'Review what happened after the successful login (processes started, files accessed, accounts created).',
            'Look for authentication attempts against other accounts from the same source.', 'Review endpoint or MFA telemetry where available.'],
          threshold: t.failures + ' failures before the success' + (useWindow ? ', within ' + t.windowMinutes + ' minutes' : '')
        });
        break; // one alert per account keeps the report readable
      }
    });

    // --- One source, many accounts (password spraying pattern) ---
    var failByIp = new Map();
    evs(4625).forEach(function (e) {
      var ip = e.d.ip;
      if (!ip || !e.d.accountName) return;
      if (!failByIp.has(ip)) failByIp.set(ip, []);
      failByIp.get(ip).push(e);
    });
    failByIp.forEach(function (list, ip) {
      var best = [], bestAccounts = [];
      var j = 0;
      for (var i = 0; i < list.length; i++) {
        while (windowMs && list[i].ts - list[j].ts > windowMs) j++;
        var slice = list.slice(j, i + 1);
        var accts = uniq(slice.map(function (e) { return e.d.accountName.toLowerCase(); }));
        if (accts.length > bestAccounts.length) { best = slice; bestAccounts = accts; }
      }
      if (bestAccounts.length < t.sprayAccounts) return;
      var names = uniq(best.map(function (e) { return e.d.accountName; }));
      makeAlert({
        rule: 'spray', name: 'Failed logons across many accounts', severity: 'Medium', points: 15,
        account: null, entity: 'Source ' + ip, events: best, sequence: sequenceText(best),
        observed: [
          ['Source IP', ip],
          ['Different accounts tried', String(names.length)],
          ['Accounts', names.slice(0, 12).join(', ') + (names.length > 12 ? ', ...' : '')],
          ['Failed logons', String(best.length)],
          ['Workstation', describeCounts(best.map(function (e) { return e.d.workstation; }))]
        ],
        why: 'One source failing against several different accounts looks like password spraying: trying a few common passwords against many users to avoid lockouts. The accounts are linked only because the failures came from the same IP address.',
        benign: ['A shared computer, terminal server or kiosk where several people mistyped their passwords.', 'A misconfigured application or script that logs in with several service accounts.',
          'A NAT gateway or VPN concentrator, where many real users share one IP address.'],
        investigate: ['Identify what the source IP is (workstation, server, VPN, external address).', 'Check whether any of these accounts then logged on successfully.',
          'Compare with lockout events (4740) and with logs from other servers.', 'Block or monitor the source if it is not expected.'],
        threshold: t.sprayAccounts + ' different accounts from one source' + (useWindow ? ' within ' + t.windowMinutes + ' minutes' : '')
      });
    });

    // --- Account created, then added to a group (same account) ---
    var groupEvents = evs(4728).concat(evs(4732)).sort(function (a, b) { return a.seq - b.seq; });
    var correlatedGroupSeqs = {}, correlatedCreateSeqs = {};
    evs(4720).forEach(function (c) {
      var keys = identityKeys(c.d.account);
      if (!keys.length) return;
      var adds = groupEvents.filter(function (g) {
        if (g.seq <= c.seq) return false;
        var gk = identityKeys(g.d.account);
        return gk.some(function (k) { return keys.indexOf(k) !== -1; });
      });
      if (!adds.length) return;
      correlatedCreateSeqs[c.seq] = true;
      adds.forEach(function (g) { correlatedGroupSeqs[g.seq] = true; });
      var priv = adds.filter(function (g) { return g.d.privileged && g.d.privileged.privileged; });
      var seqEvents = [c].concat(adds);
      var steps = seqEvents.map(function (e) {
        return e.eventId + ' - ' + (e.eventId === 4720 ? 'Account created' : 'Added to ' + (e.eventId === 4728 ? 'global' : 'local') + ' group "' + (e.d.group || 'unknown') + '"') + (e.timeRaw ? ' (' + e.timeRaw + ')' : '');
      });
      var gap = adds[0].ts !== null && c.ts !== null ? adds[0].ts - c.ts : null;
      var matchedBy = identityKeys(adds[0].d.account).filter(function (k) { return keys.indexOf(k) !== -1; })[0] || '';
      makeAlert({
        rule: 'newPriv', name: 'New account granted privileges', severity: priv.length ? 'High' : 'Medium', points: 30,
        account: c.d.accountName, events: seqEvents, sequence: seqEvents.map(function (e) { return e.eventId; }).join(' → '),
        observed: [
          ['Sequence', steps.join('\n')],
          ['Created by', c.d.actorName || 'Not recorded'],
          ['Group change made by', describeCounts(adds.map(function (g) { return g.d.actorName; }))],
          ['Privileged group', priv.length ? 'Yes: ' + uniq(priv.map(function (g) { return g.d.group; })).join(', ') : 'No (the group names do not look privileged)'],
          ['Time from creation to group change', gap !== null ? fmtSpan(gap) : 'Unknown'],
          ['Matched on', matchedBy.indexOf('sid:') === 0 ? 'Security ID (SID)' : 'Account name']
        ],
        why: 'Creating an account and quickly granting it elevated privileges can be legitimate administration, but it may also indicate persistence (an attacker giving themselves a way back in) or privilege escalation.',
        benign: ['An administrator set up a new starter or a new admin account and added it to the right groups.', 'A software installer or deployment script created its own service account.'],
        investigate: ['Confirm whether the account creation was authorised (ticket, change request, HR record).', 'Identify the administrator responsible and check their own logon activity.',
          'Review activity performed by the new account.', 'Check whether the account is still required, and disable it if not.'],
        threshold: 'Same account in a 4720 and a later 4728 / 4732'
      });
    });

    // --- Single account events not already covered ---
    var createdKeys = {};
    evs(4720).forEach(function (c) { identityKeys(c.d.account).forEach(function (k) { createdKeys[k] = c; }); });
    evs(4720).forEach(function (c) {
      if (correlatedCreateSeqs[c.seq]) return;
      makeAlert({
        rule: 'created', name: 'User account created', severity: 'Medium', points: 5, account: c.d.accountName, events: [c], sequence: '4720',
        observed: [['New account', c.d.accountName || 'Not recorded'], ['Created by', c.d.actorName || 'Not recorded']],
        why: 'A new user account was created. This may be completely legitimate administrative activity, but new accounts are also a way for an attacker to keep access, so creation should be verified.',
        benign: ['A new starter, contractor or test account set up by IT.', 'An application installer creating its own account.'],
        investigate: ['Confirm the account was requested and approved.', 'Check who created it and whether that person normally does this.', 'Watch for this account being added to groups or logging on.'],
        threshold: 'Every 4720'
      });
    });
    groupEvents.forEach(function (g) {
      if (correlatedGroupSeqs[g.seq]) return;
      var priv = g.d.privileged && g.d.privileged.privileged;
      makeAlert({
        rule: 'groupAdd', name: priv ? 'Member added to privileged group' : 'Member added to security group', severity: priv ? 'High' : 'Medium',
        points: priv ? PRIV_GROUP_POINTS : 10, account: g.d.accountName, events: [g], sequence: String(g.eventId),
        observed: [['Member', g.d.accountName || 'Not recorded'], ['Group', g.d.group || 'Not recorded'], ['Group type', g.eventId === 4728 ? 'Global (domain) security group' : 'Local security group on this computer'],
          ['Privileged', priv ? 'Yes. ' + g.d.privileged.reason : 'No'], ['Changed by', g.d.actorName || 'Not recorded']],
        why: priv ? 'Adding an account to a privileged group gives it powerful rights over this computer or the domain. This is a common step in privilege escalation, so it deserves a check even though IT staff do it legitimately.'
          : 'Group membership controls what an account can reach. A change like this is usually routine, but it is worth confirming it was expected.',
        benign: ['A planned access request, approved through the normal process.', 'An administrator granting temporary rights for a support task.'],
        investigate: ['Confirm there is a request or ticket for this change.', 'Check who made the change and whether they normally manage this group.', 'Review what the account did after gaining membership.'],
        threshold: 'Every 4728 / 4732'
      });
    });
    evs(4726).forEach(function (e) {
      var keys = identityKeys(e.d.account);
      var created = keys.map(function (k) { return createdKeys[k]; }).filter(Boolean)[0];
      var shortLived = created && created.seq < e.seq;
      makeAlert({
        rule: 'deleted', name: shortLived ? 'Short-lived account deleted' : 'User account deleted', severity: shortLived ? 'Medium' : 'Low', points: 5,
        account: e.d.accountName, events: shortLived ? [created, e] : [e], sequence: shortLived ? '4720 → 4726' : '4726',
        observed: [['Deleted account', e.d.accountName || 'Not recorded'], ['Deleted by', e.d.actorName || 'Not recorded'],
          ['Created in this file', shortLived ? 'Yes, at ' + (created.timeRaw || 'an earlier point') : 'No']],
        why: shortLived ? 'This account was created and deleted within the same set of logs. That can be a test, but an account that exists only briefly can also be a sign someone used it and then tried to remove the evidence.'
          : 'A user account was deleted. This is usually routine clean-up, but deleting accounts can also be part of suspicious account manipulation.',
        benign: ['A leaver process or routine clean-up.', 'A test account removed after testing.'],
        investigate: ['Confirm the deletion was requested.', 'Check what the account did before it was deleted.', 'Check who deleted it.'],
        threshold: 'Every 4726'
      });
    });

    // --- Log cleared ---
    evs(1102).forEach(function (e) {
      makeAlert({
        rule: 'logCleared', name: 'Security audit log cleared', severity: 'High', points: 30, account: e.d.actorName, events: [e], sequence: '1102',
        observed: [['Cleared by', e.d.actorName ? (e.d.actor.domain ? e.d.actor.domain + '\\' : '') + e.d.actorName : 'Not recorded'], ['When', e.timeRaw || 'Unknown']],
        why: 'This event means the Windows Security audit log was cleared. This can happen during legitimate maintenance, but because attackers may clear logs to remove evidence, it should normally be investigated.',
        benign: ['An administrator cleared a full log during maintenance or troubleshooting.', 'A lab or test machine being reset.'],
        investigate: ['Ask the person whose account cleared the log whether they did it, and why.', 'Look at what happened just before the clear: those events may now be missing here.',
          'Check copies of the logs elsewhere (a SIEM or log forwarder) for the missing period.', 'Review other activity by the same account.'],
        threshold: 'Every 1102'
      });
    });

    // --- Services ---
    evs(7045).forEach(function (e) {
      var clues = e.d.serviceClues || [];
      makeAlert({
        rule: 'service', name: 'New service installed', severity: clues.length ? 'Medium' : 'Low', points: 10, account: e.d.actorName,
        entity: e.d.actorName || 'No account recorded', events: [e], sequence: '7045',
        observed: [['Service name', e.d.service || 'Not recorded'], ['Program', e.d.serviceFile || 'Not recorded'], ['Start type', e.d.serviceStart || 'Not recorded'],
          ['Runs as', e.d.serviceAccount || 'Not recorded'], ['Things worth a look', clues.length ? clues.join(' ') : 'None of the simple checks matched']],
        why: 'Creation of a new Windows service can be legitimate software installation, or potentially persistence-related activity: a service can start a program automatically every time the computer boots, often with high privileges.',
        benign: ['Installing or updating software (drivers, antivirus, backup agents, printer tools).', 'IT management tools pushing an agent.'],
        investigate: ['Check whether software was being installed at that time.', 'Look up the program path and confirm it is signed and expected.', 'Check which account was logged on when the service appeared.'],
        threshold: 'Every 7045'
      });
    });

    // --- PowerShell clues ---
    evs(4104).concat(evs(4688)).sort(function (a, b) { return a.seq - b.seq; }).forEach(function (e) {
      if (!e.d.psClues || !e.d.psClues.length) return;
      var observed = [['Where', e.eventId === 4104 ? 'PowerShell script block (4104)' : 'Process command line (4688)']];
      if (e.eventId === 4688) observed.push(['Process', e.d.process || 'Not recorded'], ['Parent process', e.d.parent || 'Not recorded']);
      observed.push(['Clues', e.d.psClues.join('\n')]);
      var text = e.eventId === 4104 ? e.d.script : e.d.commandLine;
      observed.push(['Text (shortened)', text ? (text.length > 400 ? text.slice(0, 400) + ' ...' : text) : 'Not recorded']);
      if (e.d.psDecoded) observed.push(['Decoded -EncodedCommand', e.d.psDecoded]);
      makeAlert({
        rule: 'powershell', name: 'Encoded or obfuscated PowerShell', severity: 'Medium', points: 15, account: e.d.accountName || e.d.actorName,
        events: [e], sequence: String(e.eventId), observed: observed,
        why: 'PowerShell script block logging can provide valuable visibility into commands and scripts executed on the endpoint. PowerShell itself is a normal admin tool; what stands out here is that the text is written in a way that is hard for a human to read, which attackers use to hide what a command does.',
        benign: ['Management tools (for example software deployment or device management agents) often send encoded commands.', 'Some installers and admin scripts use Base64 to avoid problems with quotes and special characters.'],
        investigate: ['Decode the command and read what it actually does.', 'Check which account and parent process ran it.', 'Look for network connections or files created around the same time.'],
        threshold: 'Any of the listed clues'
      });
    });

    // ---------- Sort alerts ----------
    alerts.sort(function (a, b) {
      return (SEV_RANK[b.severity] - SEV_RANK[a.severity]) || ((a.range ? a.range.start : 0) - (b.range ? b.range.start : 0)) || a.events[0].seq - b.events[0].seq;
    });
    alerts.forEach(function (a, i) { a.id = 'alert-' + (i + 1); });

    // Mark each event with the strongest alert that refers to it.
    var flaggedSeqs = {};
    alerts.forEach(function (a) {
      a.events.forEach(function (e) {
        flaggedSeqs[e.seq] = flaggedSeqs[e.seq] ? maxSev(flaggedSeqs[e.seq], a.severity) : a.severity;
      });
    });
    events.forEach(function (e) {
      e.alertSeverity = flaggedSeqs[e.seq] || null;
      e.severity = e.alertSeverity ? maxSev(e.alertSeverity, e.d.baseSeverity) : e.d.baseSeverity;
    });

    // ---------- Investigation score ----------
    var entities = new Map();
    alerts.forEach(function (a) {
      var key = a.entity.toLowerCase();
      if (!entities.has(key)) entities.set(key, { entity: a.entity, contributions: new Map(), score: 0 });
      var ent = entities.get(key);
      var label = a.name;
      var c = ent.contributions.get(label);
      if (!c) ent.contributions.set(label, { name: label, points: a.points, count: 1 });
      else { c.count++; c.points = Math.max(c.points, a.points); }
    });
    var scores = Array.from(entities.values()).map(function (ent) {
      var contributions = Array.from(ent.contributions.values()).sort(function (a, b) { return b.points - a.points; });
      var score = contributions.reduce(function (s, c) { return s + c.points; }, 0);
      return { entity: ent.entity, score: score, contributions: contributions, band: scoreBand(score) };
    }).sort(function (a, b) { return b.score - a.score || a.entity.localeCompare(b.entity); });

    // ---------- Administrative / privilege activity (Rule 5) ----------
    var adminIds = [4720, 4726, 4728, 4732, 7045, 1102];
    var adminItems = events.filter(function (e) { return adminIds.indexOf(e.eventId) !== -1; }).map(function (e) {
      var what = e.eventId === 4720 ? 'Created account ' + (e.d.accountName || '(unknown)')
        : e.eventId === 4726 ? 'Deleted account ' + (e.d.accountName || '(unknown)')
        : e.eventId === 4728 || e.eventId === 4732 ? 'Added ' + (e.d.accountName || '(unknown)') + ' to ' + (e.d.group || 'a group') + (e.d.privileged && e.d.privileged.privileged ? ' (privileged)' : '')
        : e.eventId === 7045 ? 'Installed service ' + (e.d.service || '(unknown)')
        : 'Cleared the Security log';
      return { event: e, what: what, actor: e.d.actorName, target: e.eventId === 1102 || e.eventId === 7045 ? null : e.d.accountName, severity: e.severity };
    });
    // Accounts that appear in more than one admin event, as the actor or the
    // target, or that also had a password guessing alert. Linked by name only.
    var involvement = new Map();
    function involve(name, text) {
      if (!name || isSystemAccount(name)) return;
      var k = name.toLowerCase();
      if (!involvement.has(k)) involvement.set(k, { name: name, roles: [] });
      var r = involvement.get(k).roles;
      if (r.indexOf(text) === -1) r.push(text);
    }
    adminItems.forEach(function (it) {
      var id = it.event.eventId;
      if (it.actor) involve(it.actor, id === 1102 ? 'cleared the Security log' : id === 4720 ? 'created account ' + (it.target || '?') : id === 4726 ? 'deleted account ' + (it.target || '?') : id === 7045 ? 'installed a service' : 'changed membership of ' + (it.event.d.group || 'a group'));
      if (it.target) involve(it.target, id === 4720 ? 'was created' : id === 4726 ? 'was deleted' : 'was added to ' + (it.event.d.group || 'a group'));
    });
    alerts.filter(function (a) { return a.rule === 'successAfter'; }).forEach(function (a) { involve(a.account, 'logged on after repeated failures'); });
    var linked = Array.from(involvement.values()).filter(function (x) { return x.roles.length > 1; });

    // ---------- Dashboard numbers ----------
    var flaggedCount = Object.keys(flaggedSeqs).length;
    var counts = {
      total: events.length,
      success: evs(4624).length, failed: evs(4625).length, created: evs(4720).length, deleted: evs(4726).length,
      privilege: evs(4728).length + evs(4732).length, cleared: evs(1102).length, process: evs(4688).length,
      powershell: evs(4104).length, services: evs(7045).length, flagged: flaggedCount,
      unrecognised: events.filter(function (e) { return !e.d.recognised; }).length
    };

    function topAccounts(list, filterFn) {
      var c = countList(list.filter(filterFn || function () { return true; }).map(function (e) { return e.d.accountName; }).filter(function (n) { return n && !isSystemAccount(n); }));
      return c.slice(0, 10).map(function (x) { return { name: x[0], count: x[1] }; });
    }
    var hiddenSystem = events.filter(function (e) { return e.d.accountName && isSystemAccount(e.d.accountName); }).length;

    var idCounts = countList(events.map(function (e) { return e.eventId; })).slice(0, 12).map(function (x) {
      var id = Number(x[0]);
      return { id: id, count: x[1], name: CATALOGUE[id] ? CATALOGUE[id].name : KNOWN[id] ? KNOWN[id][0] : 'Not in this tool\'s reference list', analysed: !!CATALOGUE[id] };
    });

    var timeline = events.filter(function (e) { return e.alertSeverity || adminIds.indexOf(e.eventId) !== -1; }).map(function (e) {
      return { event: e, severity: e.severity, text: e.d.name + (e.d.accountName ? ': ' + e.d.accountName : '') + (e.eventId === 4728 || e.eventId === 4732 ? ' → ' + (e.d.group || 'group') : '') + (e.d.ip ? ' from ' + e.d.ip : '') };
    });

    var allRange = timeRange(events);

    // Which rules could run on this file.
    var hasMessage = parsed.columns && parsed.columns.message !== undefined;
    var present = {};
    events.forEach(function (e) { present[e.eventId] = true; });
    var coverage = RULES.map(function (r) {
      var missing = r.ids.filter(function (id) { return !present[id]; });
      var ran = r.key === 'successAfter' ? !!(present[4625] && present[4624]) : r.key === 'newPriv' ? !!(present[4720] && (present[4728] || present[4732]))
        : r.key === 'groupAdd' ? !!(present[4728] || present[4732]) : r.key === 'powershell' ? !!(present[4104] || present[4688]) : missing.length < r.ids.length;
      return { key: r.key, name: r.name, points: r.points, ran: ran && (hasMessage || r.key === 'logCleared' || r.key === 'service' || r.key === 'created'),
        needs: r.ids, alerts: alerts.filter(function (a) { return a.rule === r.key; }).length, noMessage: !hasMessage };
    });

    return {
      settings: t, useWindow: useWindow, events: events, alerts: alerts, scores: scores,
      topScore: scores.length ? scores[0].score : 0, topBand: scoreBand(scores.length ? scores[0].score : 0),
      admin: { items: adminItems, linked: linked }, counts: counts,
      topAccounts: topAccounts(events), topFailed: topAccounts(evs(4625)), hiddenSystem: hiddenSystem,
      eventIds: idCounts, timeline: timeline, range: allRange, coverage: coverage, notes: notes
    };
  }

  function scoreBand(score) {
    if (score >= 50) return { level: 'High', label: 'Investigate first' };
    if (score >= 20) return { level: 'Medium', label: 'Worth investigating' };
    if (score > 0) return { level: 'Low', label: 'Review when convenient' };
    return { level: 'Informational', label: 'Nothing stood out' };
  }

  var api = {
    analyse: analyse, parseMessage: parseMessage, enrich: enrich, powershellClues: powershellClues, identityKeys: identityKeys,
    isPrivilegedGroup: isPrivilegedGroup, DEFAULTS: DEFAULTS, RULES: RULES, CATALOGUE: CATALOGUE, KNOWN: KNOWN,
    LOGON_TYPES: LOGON_TYPES, FAILURE_CODES: FAILURE_CODES, SEVERITIES: SEVERITIES, PRIV_GROUP_POINTS: PRIV_GROUP_POINTS, plural: plural, fmtSpan: fmtSpan
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.EventAnalyser = api;
})(this);

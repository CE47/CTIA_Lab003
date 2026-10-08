/* CTI Casefile — Scenario definition
 * Pure data. Loaded as a classic script so the app also works from file://
 * (fetch() of JSON would be blocked by CORS on a local disk).
 *
 * Source of truth for content: ../new.scenario (beginner-phishing-harvest-001)
 */
(function () {
  window.CTI_SCENARIOS = window.CTI_SCENARIOS || [];

  window.CTI_SCENARIOS.push({
    id: 'beginner-phishing-harvest-001',
    title: 'The Patient Attacker',
    difficulty: 'Beginner',
    seed: 106,
    caseRef: 'CASE 003',
    host: 'sec-win-01',
    host_ip: '10.0.4.10',
    log_sources: ['auth', 'network'],

    mission: {
      brief: 'Investigate workstation sec-win-01.',
      objective: 'Determine how an external attacker obtained valid access to this workstation.',
      client: 'Internal Security Operations — Tier 1 Escalation Desk'
    },

    narrative:
      "A user clicked a link in a phishing email and entered their corporate credentials on a fake login page. " +
      "Minutes later the attacker used those stolen credentials to authenticate to the user's workstation " +
      'from an external IP, then made outbound connections back to the phishing infrastructure.',

    /* ---------------------------------------------------------------
     * Strings the engine reads from the scenario, so no fact about this
     * case is written into app.js. Every value here comes from new.scenario;
     * the evidence, stream and questions that follow are built on it.
     * --------------------------------------------------------------- */
    engine: {
      /* stage 2 — the record stream banner */
      stream: {
        window: '08:00–08:45',
        files: ['secwin1-events.evtx', 'proxy-flows.log']
      },

      /* stage 5 / 6 — section headings and the progress checklist labels */
      sections: {
        behaviour: 'name the behaviour',
        second: 'read the credential trail',
        trail: 'assemble the credential trail',
        attack: 'map it to attack',
        attackAlso: 'supporting techniques',
        iocs: 'keep the intelligence'
      },

      /* stage 1 — the three questions the analyst carries into the data */
      carryQuestions: [
        'Which account was targeted, and has that account ever signed in from that source address before?',
        'What does the workstation do between the first outbound connection and the successful logon?',
        'Why is the same external address contacted again after the attacker has already got in?'
      ],

      /* stage 3 — what the cadence of the sequence means */
      cadenceNote:
        'The cadence is the story: browser up at 08:00, contact with the phishing host at 08:01, the stolen ' +
        'credential tested at 08:03 and used at 08:04, and a second connection to the same address at 08:06 — ' +
        'harvest, use, then return, inside seven minutes.',

      /* ledger wording, so the analyst journal reads in the case\u2019s own terms */
      awards: {
        evidence:
          'Reviewed the full evidence set: three alerts plus user and baseline reference data',
        timeline:
          'Identified the pattern: credential captured on a phishing page, then reused from outside the estate',
        triageContext:
          'Kept the routine browser launch as context rather than evidence — it anchors the timeline without ' +
          'proving credential theft',
        board:
          'Correlated the full chain: phishing site → captured password → external logon as jdoe → callback to ' +
          'the phishing infrastructure',
        attack: 'Mapped the initial access to ATT&CK T1566.002 Phishing: Spearphishing Link',
        attackAlso:
          'Identified the supporting techniques: T1056.003 Input Capture: Web Portal Capture and T1078 Valid Accounts',
        host: 'Scoped the incident to host sec-win-01'
      },

      /* stage 5 — the collapsed trail card, and its journal entry */
      trailRows: [
        { k: 'Subject', v: 'jdoe', flag: '— credentials entered on a page the user believed was Microsoft' },
        { k: 'Capture', v: '198.51.100.42:443', flag: '— fake login page, domain registered 4 days earlier' },
        { k: 'Use', v: '4625 → 4624', flag: '— same credential, tested then used from 203.0.113.45' },
        { k: 'Trail', v: 'jdoe 08:01:12 → 198.51.100.42 → 4625 08:03:40 → 4624 08:04:25 → 198.51.100.42 08:06:58' }
      ],
      trailLabel: 'REVEAL THE FULL TRAIL',
      journalDecode:
        'Assembled the credential trail — phishing page reached at 08:01:12, credential tested at 08:03:40, ' +
        'successful logon from 203.0.113.45 at 08:04:25, callback to 198.51.100.42 at 08:06:58',

      /* stage 6 — the live assessment preview */
      reportPreview: {
        rows: [
          { label: 'Host', value: 'sec-win-01 (10.0.4.10)', code: true },
          { label: 'Victim account', value: 'jdoe', code: true },
          { label: 'Capture', value: '198.51.100.42:443', code: true },
          { label: 'Use', value: '1 failed (4625) then 1 successful (4624) logon from 203.0.113.45', code: true },
          { label: 'Callback', value: '2 outbound connections to 198.51.100.42 — before and after the logon', code: true },
          { label: 'TTP', value: 'Phishing: Spearphishing Link T1566.002 — initial access', code: false }
        ],
        note:
          'Assemble your justification in the fields above. The assessment is only defensible if the reasoning ' +
          'is visible.'
      }
    },

    /* ---------------------------------------------------------------
     * STAGE 2 — TRIAGE
     * The student tags each event as signal / context / noise.
     * tags: 'signal' | 'context' | 'noise'
     * --------------------------------------------------------------- */
    events: [
      {
        id: 'ev-4688-edge',
        ts: '08:00:41',
        code: 4688,
        kind: 'event',
        host: 'sec-win-01',
        actor: 'jdoe',
        text: 'Process created: msedge.exe (Microsoft Edge). Parent: explorer.exe. Creator: jdoe.',
        tags: 'context',
        why:
          'Starting a browser is the most ordinary event on a workstation, and this is the user\u2019s own session. ' +
          'It anchors the timeline \u2014 but it is not evidence. The user is the delivery mechanism here, not the intruder.'
      },
      {
        id: 'ev-net-phish',
        ts: '08:01:12',
        code: 'NET',
        kind: 'net',
        host: 'sec-win-01',
        text: 'Outbound connection 10.0.4.10 \u2192 198.51.100.42:443 (HTTPS). Destination domain registered 4 days ago.',
        tags: 'signal',
        why:
          'First contact with the phishing infrastructure. The tell is not the port \u2014 it is the destination: a ' +
          'domain days old, never seen before, not on a corporate allowlist.'
      },
      {
        id: 'ev-4625-ext',
        ts: '08:03:40',
        code: 4625,
        kind: 'event',
        host: 'sec-win-01',
        text: 'Failed logon. Account "jdoe". Source 203.0.113.45 (external). Status 0xC000006D \u2014 bad password.',
        tags: 'signal',
        why:
          'The credential is being tested before it is used. An unknown external address guessing a named ' +
          'corporate account is not somebody mistyping a password \u2014 it is the first moment the stolen ' +
          'credential is proven to work for the attacker.'
      },
      {
        id: 'ev-4624-ext',
        ts: '08:04:25',
        code: 4624,
        kind: 'event',
        host: 'sec-win-01',
        actor: 'jdoe',
        text: 'Successful logon. Account "jdoe". Source 203.0.113.45 (external). Logon type 10.',
        tags: 'signal',
        why:
          'The account is in use from an address that appears nowhere in its history. Everything this user does ' +
          'from 08:04 is now happening on the attacker\u2019s infrastructure, not in the office.'
      },
      {
        id: 'ev-net-callback',
        ts: '08:06:58',
        code: 'NET',
        kind: 'net',
        host: 'sec-win-01',
        text: 'Outbound connection 10.0.4.10 \u2192 198.51.100.42:443 (HTTPS). Same destination as 08:01:12, after the external logon.',
        tags: 'signal',
        why:
          'Getting in was not the end of the operation. Reconnecting to the phishing host two minutes after the ' +
          'logon is the attacker collecting what that access unlocked \u2014 session material, or the next stage.'
      },

      /* ---------- noise: baseline user activity ---------- */
      { id: 'ev-n01', ts: '08:00:28', code: 4624, kind: 'event', host: 'FIN-WS-08', actor: 'asmith', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n02', ts: '08:02:03', code: 4634, kind: 'event', host: 'FIN-WS-08', actor: 'asmith', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n03', ts: '08:02:44', code: 4672, kind: 'event', host: 'HR-LT-03', actor: 'mchen', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n04', ts: '08:03:18', code: 4624, kind: 'event', host: 'OPS-WS-09', actor: 'kpatel', text: 'Successful logon. Logon type 2. Source 10.0.4.20.', tags: 'noise' },
      { id: 'ev-n05', ts: '08:05:03', code: 4634, kind: 'event', host: 'FIN-WS-08', actor: 'asmith', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n06', ts: '08:05:27', code: 4624, kind: 'event', host: 'ENG-WS-02', actor: 'rneuman', text: 'Successful logon. Logon type 2. Source 10.0.4.21.', tags: 'noise' },
      { id: 'ev-n07', ts: '08:06:40', code: 4634, kind: 'event', host: 'HR-LT-03', actor: 'mchen', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n08', ts: '08:07:44', code: 4672, kind: 'event', host: 'OPS-WS-09', actor: 'kpatel', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n09', ts: '08:08:15', code: 'NET', kind: 'net', host: 'ENG-WS-02', text: 'Outbound connection 10.0.4.21 \u2192 10.0.4.12:443 (HTTPS). Corporate proxy, allowlisted.', tags: 'noise' },
      { id: 'ev-n10', ts: '08:09:12', code: 4624, kind: 'event', host: 'SALES-LT-11', actor: 'mchen', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n11', ts: '08:10:26', code: 4634, kind: 'event', host: 'OPS-WS-09', actor: 'kpatel', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n12', ts: '08:11:39', code: 4672, kind: 'event', host: 'HR-LT-03', actor: 'rneuman', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n13', ts: '08:12:03', code: 'NET', kind: 'net', host: 'FIN-WS-08', text: 'Outbound connection 10.0.4.11 \u2192 93.184.216.34:443 (HTTPS). Software update mirror, allowlisted.', tags: 'noise' },
      { id: 'ev-n14', ts: '08:14:22', code: 4624, kind: 'event', host: 'HR-LT-03', actor: 'rneuman', text: 'Successful logon. Logon type 2. Source 10.0.4.20.', tags: 'noise' },
      { id: 'ev-n15', ts: '08:16:37', code: 4634, kind: 'event', host: 'ENG-WS-02', actor: 'kpatel', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n16', ts: '08:17:09', code: 4672, kind: 'event', host: 'SALES-LT-11', actor: 'asmith', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n17', ts: '08:19:28', code: 4624, kind: 'event', host: 'ENG-WS-02', actor: 'mchen', text: 'Successful logon. Logon type 2. Source 10.0.4.21.', tags: 'noise' },
      { id: 'ev-n18', ts: '08:21:46', code: 4634, kind: 'event', host: 'SALES-LT-11', actor: 'rneuman', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n19', ts: '08:24:03', code: 4624, kind: 'event', host: 'OPS-WS-09', actor: 'rneuman', text: 'Successful logon. Logon type 2. Source 10.0.4.20.', tags: 'noise' },
      { id: 'ev-n20', ts: '08:26:12', code: 4672, kind: 'event', host: 'FIN-WS-08', actor: 'mchen', text: 'Special privileges assigned to new logon.', tags: 'noise' }
    ],

    /* ---------------------------------------------------------------
     * STAGE 1 — EVIDENCE INBOX
     * --------------------------------------------------------------- */
    evidence: [
      {
        id: 'al-net-newdomain',
        ref: 'ALERT-01',
        severity: 'medium',
        title: 'Browser connection to newly registered domain',
        blurb: 'Browser on sec-win-01 (10.0.4.10) opened an HTTPS connection to 198.51.100.42, a domain registered less than 7 days ago and not on the corporate allowlist.',
        detail:
          'Proxy record \u2014 outbound HTTPS from 10.0.4.10 to 198.51.100.42:443 at 08:01:12, initiated by ' +
          'msedge.exe. The allowlist carries only domains older than 30 days, and this one is four days old. ' +
          'HTTPS hides the content of the page, not the fact that it was visited.',
        hint: 'Ask: how old is the domain, who registered it, and what does a browser do with a page like that?'
      },
      {
        id: 'al-4624-ext',
        ref: 'ALERT-02',
        severity: 'high',
        title: 'Successful logon from new external IP',
        blurb: "User 'jdoe' authenticated to sec-win-01 from source IP 203.0.113.45. Previous logons for this user came only from the 10.0.4.x range.",
        detail:
          'Security Events 4625 and 4624 \u2014 a failed attempt and then a success for the same account from the ' +
          'same source, 45 seconds apart. The account has no history of interactive logon from outside the ' +
          'corporate range, and the successful logon type is 10 (RemoteInteractive), the type a remote desktop ' +
          'session produces.',
        hint: 'Ask: has this account ever been seen from this network before, and why was it tried once and failed first?'
      },
      {
        id: 'al-net-callback',
        ref: 'ALERT-03',
        severity: 'high',
        title: 'Outbound connection to phishing IP after authentication',
        blurb: 'sec-win-01 (10.0.4.10) opened an outbound HTTPS connection to 198.51.100.42 shortly after the suspicious external login.',
        detail:
          'Proxy record \u2014 the same destination as 08:01:12, contacted again at 08:06:58, after the external ' +
          'logon succeeded. A workstation does not re-visit a credential-capture page on its own. A human ' +
          'inside the attacker\u2019s session does, to fetch whatever the access unlocked.',
        hint: 'Ask: why come back to the phishing infrastructure after the logon already worked?'
      },
      {
        id: 'ev-user',
        ref: 'EVID-04',
        severity: 'info',
        title: 'Account information — jdoe',
        blurb: 'Directory record for the account that authenticated from the external address.',
        detail:
          'jdoe — J. Doe, Finance Analyst, 14 months in post. Group membership: Domain Users, Finance-Read. ' +
          'Interactive logon history for the last 90 days: 10.0.4.x only, always logon type 2 from the office ' +
          'floor. Multi-factor authentication is not enabled for this account. Last password change 212 days ' +
          'ago \u2014 unchanged across the period.',
        hint: 'Ask: is there any reason this account would authenticate from a public network, and how is it protected?'
      },
      {
        id: 'ev-baseline',
        ref: 'EVID-05',
        severity: 'info',
        title: 'Baseline activity — other hosts this hour',
        blurb: 'Reference traffic for the estate during the same window.',
        detail:
          'In this hour, 4 baseline users generated 20 logon, logoff, privilege and proxy events across ' +
          'FIN-WS-08, HR-LT-03, ENG-WS-02, OPS-WS-09 and SALES-LT-11. All outbound connections from those ' +
          'hosts went to the corporate proxy or the allowlisted update mirror. No other host contacted ' +
          '198.51.100.42, and no other account authenticated from 203.0.113.45.',
        hint: 'Ask: is sec-win-01 an isolated case, or does the rest of the estate show the same pattern?'
      }
    ],

    alerts: [
      { name: 'Browser connection to newly registered domain', severity: 'medium' },
      { name: 'Successful logon from new external IP', severity: 'high' },
      { name: 'Outbound connection to phishing IP after authentication', severity: 'high' }
    ],

    /* ---------------------------------------------------------------
     * STAGE 3 — TIMELINE
     * --------------------------------------------------------------- */
    timeline: [
      { t: 'T+0', ts: '08:00:41', label: 'Process', detail: "process_created (4688): msedge.exe launched by 'jdoe' on sec-win-01", net: null },
      { t: 'T+1', ts: '08:01:12', label: 'Network', detail: 'outbound HTTPS 10.0.4.10 \u2192 198.51.100.42:443 \u2014 phishing site, domain registered 4 days ago', net: '10.0.4.10 \u2192 198.51.100.42:443' },
      { t: 'T+3', ts: '08:03:40', label: 'Failed logon', detail: "failed_logon (4625) for 'jdoe' from 203.0.113.45 \u2014 status 0xC000006D", net: null },
      { t: 'T+4', ts: '08:04:25', label: 'Logon', detail: "successful_logon (4624) for 'jdoe' on sec-win-01 from 203.0.113.45", net: '203.0.113.45 \u2192 sec-win-01' },
      { t: 'T+6', ts: '08:06:58', label: 'Network', detail: 'outbound HTTPS 10.0.4.10 \u2192 198.51.100.42:443 \u2014 attacker callback after authentication', net: '10.0.4.10 \u2192 198.51.100.42:443' }
    ],

    timelineQuestion: {
      id: 'q-timeline',
      prompt: 'What pattern do you see in this sequence?',
      options: [
        { id: 'a', label: 'Routine browsing followed by a remote help-desk session and a software check-in' },
        { id: 'b', label: 'A user working from home on a hotel network, with the laptop talking to a new CDN edge' },
        { id: 'c', label: 'A phishing page captures a credential, the attacker tests and reuses it to log on from outside the estate, then calls back to the phishing infrastructure — inside seven minutes' },
        { id: 'd', label: 'A compromised workstation beaconing to a command-and-control server on a timer' }
      ],
      correct: ['c'],
      xp: 10,
      explain:
        'The order matters more than any single record. The outbound connection to the phishing host came first, ' +
        'the credential was then tried from an external address and succeeded, and the same phishing host was ' +
        'contacted again once the attacker was inside. Cause, effect, then collection \u2014 that sequence is ' +
        'credential theft, not remote working and not beaconing.'
    },

    /* ---------------------------------------------------------------
     * STAGE 4 — CORRELATION BOARD
     * --------------------------------------------------------------- */
    boardNodes: [
      { id: 'n-phish', label: '198.51.100.42', sub: 'phishing site', x: 8, y: 8 },
      { id: 'n-creds', label: 'stolen password', sub: 'captured on fake page', x: 8, y: 62 },
      { id: 'n-host', label: 'sec-win-01', sub: 'victim workstation', x: 40, y: 36 },
      { id: 'n-src', label: '203.0.113.45', sub: 'attacker source', x: 72, y: 8 },
      { id: 'n-user', label: 'jdoe', sub: 'compromised account', x: 72, y: 62 }
    ],
    boardLinks: [
      { from: 'n-host', to: 'n-phish', label: 'visits', correct: true },
      { from: 'n-phish', to: 'n-creds', label: 'harvests', correct: true },
      { from: 'n-creds', to: 'n-user', label: 'harvested from', correct: true },
      { from: 'n-src', to: 'n-creds', label: 'authenticates with', correct: true },
      { from: 'n-src', to: 'n-user', label: 'authenticates as', correct: true },
      { from: 'n-phish', to: 'n-host', label: 'patches', correct: false },
      { from: 'n-user', to: 'n-src', label: 'creates', correct: false }
    ],
    boardXp: 10,

    /* ---------------------------------------------------------------
     * STAGE 5 — ANALYSIS: behaviour, ATT&CK, IoCs
     * --------------------------------------------------------------- */
    behaviourQuestions: [
      {
        id: 'q-persist',
        prompt: 'How would you classify a phishing email that leads a user to submit credentials on a fake login page?',
        options: [
          { id: 'a', label: 'Initial Access — the user\u2019s own workstation delivers the attacker into the estate for them' },
          { id: 'b', label: 'Reconnaissance — gathering information about the host' },
          { id: 'c', label: 'Impact — destructive action against data' },
          { id: 'd', label: 'A hygiene problem rather than an incident — the user should simply be told to be more careful' }
        ],
        correct: ['a'],
        xp: 10,
        explain:
          'Phishing is the access event. Nothing had to be exploited on the host \u2014 the user performed the ' +
          'attacker\u2019s authentication step for them, from a device already inside the perimeter, on an ' +
          'allowlisted network. Everything that follows is built on top of that entry point.'
      },
      {
        id: 'q-ps',
        prompt: 'Why does the failed logon at 08:03:40 matter, forty-five seconds before the successful one?',
        options: [
          { id: 'a', label: 'It shows the account password expired and forced a change' },
          { id: 'b', label: 'It shows the attacker validating a stolen credential before relying on it \u2014 a test that also tells them when to try again' },
          { id: 'c', label: 'It shows the workstation has two network cards and the wrong one was used' },
          { id: 'd', label: 'It shows jdoe forgot the password and logged in twice from the office' }
        ],
        correct: ['b'],
        xp: 10,
        explain:
          'A single failure immediately before a success from the same external address is credential testing, ' +
          'not a mistyped password by a legitimate user. It converts a guess into a confirmed credential: the ' +
          'attacker learned something from the failure, adjusted, and the next attempt worked. That is also why ' +
          'the failed logon is evidence of theft rather than noise to be discarded.'
      }
    ],

    decodedCommand: {
      encoded: 'jdoe 08:01:12 → 198.51.100.42 → 4625 08:03:40 → 4624 08:04:25 → 198.51.100.42 08:06:58',
      decoded: 'credentials submitted to the phishing host (HTTPS 198.51.100.42:443) → tested from 203.0.113.45 (4625) → accepted (4624) → callback to 198.51.100.42:443',
      note:
        'The event IDs read as one chain: a page captures a password, the password is tested, the password is ' +
        'accepted, and the attacker returns to the page that gave it to them. That sequence \u2014 not the ' +
        'suspicious IP on its own \u2014 is the credential-theft finding.'
    },

    attack: {
      /* the engine renders primary.prompt and alsoPresent.prompt as the question text */
      primary: {
        prompt: 'Which technique best explains how the attacker got in?',
        options: [
          { id: 'a', label: 'Phishing: Spearphishing Link', meta: 'T1566.002 · Initial Access / Credential Access' },
          { id: 'b', label: 'Exploitation of Remote Services', meta: 'T1210 · Initial Access' },
          { id: 'c', label: 'OS Credential Dumping', meta: 'T1003 · Credential Access' },
          { id: 'd', label: 'Data from Information Repositories', meta: 'T1213 · Collection' }
        ],
        correct: ['a'],
        xp: 10,
        explain:
          'The user followed a link from an email into a fake page and typed the password there. Nothing was ' +
          'exploited and nothing was dumped from memory \u2014 the credential was handed over through the browser. ' +
          'That is Spearphishing Link, T1566.002, and every later event in this case is downstream of it.'
      },
      alsoPresent: {
        prompt: 'Two other techniques are genuinely present in this activity. Select both.',
        options: [
          { id: 'a', label: 'Valid Accounts', meta: 'T1078 · Defense Evasion / Persistence / Initial Access' },
          { id: 'b', label: 'Input Capture: Web Portal Capture', meta: 'T1056.003 · Credential Access' },
          { id: 'c', label: 'OS Credential Dumping', meta: 'T1003 · Credential Access' },
          { id: 'd', label: 'Indicator Removal', meta: 'T1070 · Defense Evasion' }
        ],
        correct: ['a', 'b'],
        xp: 10,
        explain:
          'The fake login page is a credential-capture form: Input Capture: Web Portal Capture (T1056.003). ' +
          'Using the stolen username and password to authenticate as jdoe is Valid Accounts (T1078) \u2014 the ' +
          'attacker had valid credentials and used them exactly as instructed. Neither technique requires the ' +
          'password to be cracked or stolen from the machine.'
      }
    },

    iocs: {
      prompt: 'Which of these would you preserve as indicators or investigative pivots?',
      options: [
        { id: 'i1', label: '198.51.100.42', role: 'indicator' },
        { id: 'i2', label: '203.0.113.45', role: 'indicator' },
        { id: 'i3', label: 'sec-win-01', role: 'context' },
        { id: 'i4', label: 'jdoe', role: 'context' },
        { id: 'i5', label: 'credential capture page', role: 'behaviour' },
        { id: 'i6', label: 'Event 4625', role: 'context' },
        { id: 'i7', label: 'interactive logon from a new external IP', role: 'behaviour' },
        { id: 'i8', label: 'callback to the phishing host after logon', role: 'behaviour' }
      ],
      correct: ['indicator', 'behaviour', 'context'],
      xp: 10,
      explain:
        'Two of these eight are things you would act on today: the phishing address 198.51.100.42 (block it at ' +
        'the proxy and in DNS) and the attacker source 203.0.113.45 (block and hunt). The behaviours \u2014 ' +
        'credential capture on a lookalike page, interactive logon from a source the account has never used, and ' +
        'a callback to infrastructure seen minutes earlier \u2014 are worth detections of their own. ' +
        'sec-win-01, jdoe and Event 4625 are context: they scope the incident and drive the next pivots, but they ' +
        'are not indicators of compromise.'
    },

    /* ---------------------------------------------------------------
     * STAGE 6 — REPORT
     * --------------------------------------------------------------- */
    report: {
      host: {
        prompt: 'Which host is compromised?',
        options: [
          { id: 'a', label: 'sec-win-01' },
          { id: 'b', label: 'SALES-LT-11' },
          { id: 'c', label: 'HR-LT-03' },
          { id: 'd', label: '10.0.4.20' }
        ],
        correct: ['a'],
        xp: 10,
        explain:
          'Only sec-win-01 shows the whole chain: the connection to the phishing host, the external logon for ' +
          'jdoe and the callback. The other hosts were busy in the same hour but produced nothing but routine ' +
          'traffic, and 10.0.4.20 is an internal address, not a host name.'
      },
      what: {
        prompt: 'What happened?',
        options: [
          { id: 'a', label: 'A phishing email led jdoe to submit credentials on a fake login page. The attacker reused that password to log on to sec-win-01 from an external address (203.0.113.45) and then reconnected to the phishing infrastructure to collect what the access unlocked.' },
          { id: 'b', label: 'jdoe worked from a hotel network while travelling, and the laptop contacted an unfamiliar content-delivery address.' },
          { id: 'c', label: 'A browser update installed an unwanted add-on that made two outbound connections.' },
          { id: 'd', label: 'A scheduled software check-in failed once and succeeded on the retry from the same address.' }
        ],
        correct: ['a'],
        xp: 10,
        explain:
          'The finding is the chain, not the single event: credentials captured on a page the user trusted, ' +
          'then replayed by an attacker from their own infrastructure, followed by a callback to the same ' +
          'phishing host. Any statement that leaves out the credential capture, or that describes it as ' +
          'travelling or as a routine connection, is not the incident.'
      },
      why: {
        prompt: 'Why is it suspicious? Select every reason that holds.',
        options: [
          { id: 'a', label: 'The account has never authenticated from 203.0.113.45 \u2014 all 90 days of its history is 10.0.4.x' },
          { id: 'b', label: 'It was preceded forty-five seconds earlier by a failed logon for the same account from the same address' },
          { id: 'c', label: 'The workstation had just opened a connection to 198.51.100.42, a domain registered four days earlier' },
          { id: 'd', label: 'The host reconnected to that same phishing address two and a half minutes after the logon succeeded' },
          { id: 'e', label: 'Users sometimes connect from outside the office' },
          { id: 'f', label: 'HTTPS traffic cannot be inspected, so nothing here can be concluded' }
        ],
        correct: ['a', 'b', 'c', 'd'],
        xp: 10,
        explain:
          'Each of the four reasons is an anomaly measured against this account\u2019s own history or against the ' +
          'sequence itself: a source the account has never used, a test-then-succeed pattern, a destination ' +
          'registered days earlier, and a callback after the intrusion succeeded. The last two options are not ' +
          'reasons \u2014 people do work remotely, and the fact that a connection is encrypted says nothing about ' +
          'whether it should have been made.'
      },
      confidence: {
        prompt: 'Analyst confidence in this assessment',
        options: [
          { id: 'a', label: 'Low' },
          { id: 'b', label: 'Medium' },
          { id: 'c', label: 'High' }
        ],
        correct: ['c'],
        xp: 10,
        explain:
          'Three independent artifacts — proxy, authentication and directory history — agree, and they agree in ' +
          'an order that only credential theft explains. The remaining gap is whether anything was taken after ' +
          'the logon, and that gap does not reduce confidence in the access itself.'
      },
      actions: {
        prompt: 'Recommended next actions. Select the three that follow from this assessment.',
        options: [
          { id: 'a', label: 'Reset jdoe\u2019s password and revoke active sessions, cached credentials and tokens for that account' },
          { id: 'b', label: 'Block 198.51.100.42 and 203.0.113.45 at the proxy, firewall and DNS resolver' },
          { id: 'c', label: 'Hunt the estate for other hosts that resolved, contacted or submitted credentials to 198.51.100.42' },
          { id: 'd', label: 'Reimage every workstation in the finance department as a precaution' },
          { id: 'e', label: 'Block all outbound port 443 across the estate until the investigation closes' },
          { id: 'f', label: 'Disable the browser on all endpoints until users are trained' }
        ],
        correct: ['a', 'b', 'c'],
        xp: 10,
        explain:
          'Credential theft leaves two live problems: the password itself and the sessions already created with ' +
          'it, so the reset must come with session and token revocation. The two external addresses must be ' +
          'blocked and the estate swept for other hosts that touched them. Estate-wide measures that are not ' +
          'tied to this evidence — reimaging a department, blocking all of port 443, disabling browsers — are ' +
          'disproportionate and destroy the evidence trail that is still needed.'
      }
    },

    reasoning: {
      prompt: 'Which three pieces of evidence most strongly support your assessment? Select exactly three.',
      options: [
        { id: 'r1', label: 'Outbound connection to 198.51.100.42 \u2014 a domain registered 4 days earlier \u2014 three minutes before the logon (NET)', key: true },
        { id: 'r2', label: 'Failed 4625 then successful 4624 for jdoe from 203.0.113.45, 45 seconds apart', key: true },
        { id: 'r3', label: 'The same phishing address contacted again at 08:06:58, after the attacker was already logged in', key: true },
        { id: 'r4', label: 'jdoe is a Domain Users account with no elevated rights', key: false },
        { id: 'r5', label: 'Four other users were active on the estate during the same hour', key: false },
        { id: 'r6', label: 'msedge.exe was launched by the user at the start of the hour', key: false },
        { id: 'r7', label: 'The workstation connects to the corporate proxy every morning', key: false }
      ],
      correctCount: 3,
      xp: 10,
      explain:
        'No single record proves credential theft. A new domain could be an advert, an external logon could be ' +
        'travelling, a browser launch could be anyone\u2019s morning. What makes this defensible is the order they ' +
        'appear in and the fact that each one points at the same pair of external addresses: the host reaches the ' +
        'phishing page, the captured credential is tested and accepted from outside, and the phishing page is ' +
        'contacted again once the attacker is inside. Three artifacts that only make sense together.'
    },

    /* mirrored verbatim from new.scenario — the dotted keys are kept as written
       there, because this block is the record of what the case is actually made of */
    ground_truth: {
      outbound_connections_to_phishing_ip: 2,
      'failed_logons_for_jdoe_from_203.0.113.45': 1,
      'successful_logons_for_jdoe_from_203.0.113.45': 1,
      attacker_ip: '203.0.113.45',
      phishing_site_ip: '198.51.100.42',
      target_host: 'sec-win-01',
      event_ids_present: [4624, 4625, 4688]
    },

    ranking: [
      { min: 90, rank: 'Lead Intelligence Analyst', note: 'You produced defensible intelligence, not just correct answers.' },
      { min: 75, rank: 'Threat Intelligence Analyst', note: 'Strong correlation and a defensible judgment.' },
      { min: 55, rank: 'Junior CTI Investigator', note: 'You found the behaviour and explained it. Tighten the correlation and the reporting.' },
      { min: 0, rank: 'Case Officer Trainee', note: 'Re-run the case. Start with the failed logon at 08:03:40 and work backwards to the page that caused it.' }
    ],

    assist: {
      nudge: { label: 'Nudge', mult: 0.85, text: 'Ignore anything on port 443 that is allowlisted, and look at the two connections that are not. What happened between them?' },
      hint: { label: 'Analyst Hint', mult: 0.7, text: 'One event delivers the page, one event proves the password is now an attacker\u2019s, and one event shows they came back. Which is which?' },
      explain: { label: 'Explain', mult: 0.5, text: 'jdoe reached 198.51.100.42 at 08:01:12 and entered credentials on a lookalike page. The attacker tested that password from 203.0.113.45 (4625), succeeded 45 seconds later (4624), and reconnected to 198.51.100.42 at 08:06:58 to collect what the access unlocked. That is Spearphishing Link, T1566.002 \u2014 initial access \u2014 with Input Capture: Web Portal Capture (T1056.003) and Valid Accounts (T1078) alongside. Neither IP is an indicator on its own; the chain is the finding.' }
    }
  });
})();

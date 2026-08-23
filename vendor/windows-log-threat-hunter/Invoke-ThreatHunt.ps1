<#
.SYNOPSIS
    Windows Log Threat Hunter. Scans local Windows event logs for
    suspicious command-line / process patterns and maps hits to MITRE ATT&CK.

.DESCRIPTION
    Read-only defensive tooling. It never executes anything it finds; it only
    reads the event logs already on this machine, applies a JSON rule pack
    (rules/rules.json), and reports findings to the console plus optional
    HTML/JSON reports.

    Event sources (whatever is available on the host):
      - PowerShell Operational  (Event ID 4104, script-block logging)
      - Security                (Event ID 4688, process creation). Needs admin,
                                 plus "Audit Process Creation" and, for command
                                 lines, the "Include command line" policy
      - Sysmon Operational      (Event ID 1) if Sysmon is installed

    Use -Source Demo to run against bundled sample data (samples/sample-events.json)
    so you can see the engine work with zero setup and no admin rights.

.PARAMETER Source
    Auto (default) | PowerShell | Security | Sysmon | Demo

.PARAMETER Hours
    How far back to look in real logs. Default 24.

.PARAMETER MaxEvents
    Max events to pull per log. Default 5000.

.PARAMETER MinSeverity
    Only show findings at/above this level: Low | Medium | High. Default Low.

.PARAMETER SortBy
    Ordering of results: Severity (most dangerous first, default) | Time (newest first).

.PARAMETER RulesPath
    Path to the rule pack. Default: rules/rules.json next to this script.

.PARAMETER Html
    Optional path to write a self-contained HTML report.

.PARAMETER Json
    Optional path to write findings as JSON.

.EXAMPLE
    .\Invoke-ThreatHunt.ps1 -Source Demo -Html reports\demo.html

.EXAMPLE
    .\Invoke-ThreatHunt.ps1 -Hours 48

.NOTES
    Windows Log Threat Hunter
    Author    : Baris Burak Turgut
    Copyright : (c) 2026 Baris Burak Turgut
    License   : MIT (see LICENSE)
#>
[CmdletBinding()]
param(
    [ValidateSet('Auto', 'PowerShell', 'Security', 'Sysmon', 'Demo')]
    [string]$Source = 'Auto',
    [int]$Hours = 24,
    [int]$MaxEvents = 5000,
    [ValidateSet('Low', 'Medium', 'High')]
    [string]$MinSeverity = 'Low',
    [ValidateSet('Severity', 'Time')]
    [string]$SortBy = 'Severity',
    [string]$RulesPath,
    [string]$Html,
    [string]$Json
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $RulesPath) { $RulesPath = Join-Path $scriptRoot 'rules\rules.json' }

$sevRank = @{ 'Test' = 0; 'Low' = 1; 'Medium' = 2; 'High' = 3 }

# Known-benign automation on this host: the hunter's own run, its launcher, and
# the automation-host preamble that PowerShell script-block logging records when
# a script is invoked with -ExecutionPolicy Bypass. Re-labelled 'Test' instead
# of a threat, so the hunter never flags itself. This is allowlisting known-good.
$SelfPattern = '(?i)(Invoke-ThreatHunt\.ps1|\$PSDefaultParameterValues|SessionState\.LanguageMode)'

function Write-Banner {
    Write-Host ''
    Write-Host '  Windows Log Threat Hunter' -ForegroundColor Cyan
    Write-Host '  read-only - maps local log activity to MITRE ATT&CK' -ForegroundColor DarkGray
    Write-Host '  by Baris Burak Turgut' -ForegroundColor DarkGray
    Write-Host ''
}

# --- Normalize a raw WinEvent into a flat object the rule engine understands ---
function ConvertTo-NormalizedEvent {
    param($WinEvent, [string]$SourceName)
    $data = @{}
    try {
        $xml = [xml]$WinEvent.ToXml()
        foreach ($d in $xml.Event.EventData.Data) {
            if ($d.Name) { $data[$d.Name] = [string]$d.'#text' }
        }
    } catch { }

    $cmd = ''
    $img = ''
    $parent = ''
    $user = ''

    switch ($SourceName) {
        'PowerShell' {
            $cmd = $data['ScriptBlockText']
            $img = 'powershell.exe'
        }
        'Security' {
            $cmd = $data['CommandLine']
            $img = $data['NewProcessName']
            $parent = $data['ParentProcessName']
            $user = $data['SubjectUserName']
            if (-not $cmd) { $cmd = $img }
        }
        'Sysmon' {
            $cmd = $data['CommandLine']
            $img = $data['Image']
            $parent = $data['ParentImage']
            $user = $data['User']
        }
    }

    # Script-block events carry no user name in their payload, only the SID that
    # wrote them. Without this every 4104 finding is attributed to nobody, and a
    # tool that groups by account has nothing to group on.
    if (-not $user -and $WinEvent.UserId) {
        try { $user = $WinEvent.UserId.Translate([System.Security.Principal.NTAccount]).Value }
        catch { $user = $WinEvent.UserId.Value }
    }

    return [PSCustomObject]@{
        Source      = $SourceName
        EventId     = $WinEvent.Id
        TimeCreated = $WinEvent.TimeCreated
        User        = $user
        Image       = $img
        ParentImage = $parent
        CommandLine = $cmd
    }
}

# --- Collect events from a given real log ---
function Get-EventsFromLog {
    param([string]$LogName, [int]$EventId, [string]$SourceName, [datetime]$Start, [int]$Max)
    $result = @()
    try {
        $filter = @{ LogName = $LogName; Id = $EventId; StartTime = $Start }
        $raw = Get-WinEvent -FilterHashtable $filter -MaxEvents $Max -ErrorAction Stop
        foreach ($e in $raw) {
            $norm = ConvertTo-NormalizedEvent -WinEvent $e -SourceName $SourceName
            if ($norm.CommandLine) { $result += $norm }
        }
        Write-Host ("  [+] {0}: {1} event(s)" -f $SourceName, $result.Count) -ForegroundColor DarkGray
    } catch {
        if ($_.Exception.Message -match 'No events were found') {
            Write-Host ("  [ ] {0}: no matching events" -f $SourceName) -ForegroundColor DarkGray
        } else {
            Write-Host ("  [!] {0}: unavailable ({1})" -f $SourceName, $_.Exception.Message) -ForegroundColor DarkYellow
        }
    }
    return $result
}

function Get-DemoEvents {
    param([string]$Root)
    $path = Join-Path $Root 'samples\sample-events.json'
    if (-not (Test-Path $path)) { throw "Sample data not found at $path" }
    $items = Get-Content $path -Raw | ConvertFrom-Json
    $out = @()
    foreach ($i in $items) {
        $out += [PSCustomObject]@{
            Source      = 'DEMO'
            EventId     = $i.EventId
            TimeCreated = $i.TimeCreated
            User        = $i.User
            Image       = $i.Image
            ParentImage = $i.ParentImage
            CommandLine = $i.CommandLine
        }
    }
    Write-Host ("  [+] DEMO: {0} sample event(s)" -f $out.Count) -ForegroundColor DarkGray
    return $out
}

# --- Rule engine: every condition (field/pattern) must match (logical AND) ---
function Test-Rule {
    param($Rule, $Event)
    foreach ($c in $Rule.conditions) {
        $value = [string]$Event.$($c.field)
        if (-not $value) { return $false }
        if ($value -notmatch $c.pattern) { return $false }
    }
    return $true
}

# ------------------------------- main -------------------------------
Write-Banner

if (-not (Test-Path $RulesPath)) { throw "Rule pack not found: $RulesPath" }
$rules = Get-Content $RulesPath -Raw | ConvertFrom-Json
Write-Host ("  Loaded {0} detection rule(s) from {1}" -f $rules.Count, (Split-Path $RulesPath -Leaf)) -ForegroundColor DarkGray

$start = (Get-Date).AddHours(-1 * $Hours)
$events = @()

Write-Host ''
Write-Host '  Collecting events...' -ForegroundColor Cyan

if ($Source -eq 'Demo') {
    $events += Get-DemoEvents -Root $scriptRoot
} else {
    if ($Source -eq 'Auto' -or $Source -eq 'PowerShell') {
        $events += Get-EventsFromLog -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId 4104 -SourceName 'PowerShell' -Start $start -Max $MaxEvents
    }
    if ($Source -eq 'Auto' -or $Source -eq 'Security') {
        $events += Get-EventsFromLog -LogName 'Security' -EventId 4688 -SourceName 'Security' -Start $start -Max $MaxEvents
    }
    if ($Source -eq 'Auto' -or $Source -eq 'Sysmon') {
        $events += Get-EventsFromLog -LogName 'Microsoft-Windows-Sysmon/Operational' -EventId 1 -SourceName 'Sysmon' -Start $start -Max $MaxEvents
    }
}

if ($events.Count -eq 0) {
    Write-Host ''
    Write-Host '  No events collected.' -ForegroundColor Yellow
    Write-Host '  Tip: run with  -Source Demo  to try the engine on bundled sample data,' -ForegroundColor Yellow
    Write-Host '       or run as Administrator / enable PowerShell script-block logging' -ForegroundColor Yellow
    Write-Host '       to gather real telemetry.' -ForegroundColor Yellow
    # A caller that asked for a report still gets one; a tool downstream should
    # see an empty hunt, not a missing file it has to guess about.
    if ($Json) {
        ConvertTo-Json -InputObject @() -Depth 5 | Out-File -FilePath $Json -Encoding utf8
        Write-Host ('  JSON report -> {0}' -f $Json) -ForegroundColor Green
    }
    return
}

# --- Evaluate every event against every rule ---
$findings = @()
foreach ($ev in $events) {
    foreach ($rule in $rules) {
        if (Test-Rule -Rule $rule -Event $ev) {
            if ($sevRank[$rule.severity] -ge $sevRank[$MinSeverity]) {
                $findings += [PSCustomObject]@{
                    Severity    = $rule.severity
                    RuleId      = $rule.id
                    Rule        = $rule.name
                    Attack      = $rule.attack
                    # ISO-8601 string, not the DateTime object. ConvertTo-Json
                    # renders a DateTime as /Date(1787406739178)/ - Microsoft's
                    # own JSON date format, which nothing outside .NET parses.
                    # ISO also sorts lexically, so the HTML sort still works.
                    # Demo events arrive from JSON already as strings.
                    Time        = $(if ($ev.TimeCreated -is [datetime]) {
                                        $ev.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss')
                                    } else { [string]$ev.TimeCreated })
                    Source      = $ev.Source
                    User        = $ev.User
                    CommandLine = $ev.CommandLine
                    Why         = $rule.description
                }
            }
        }
    }
}

# Re-label the tool's own launches as 'Test' (self-activity allowlist)
foreach ($f in $findings) {
    if ([string]$f.CommandLine -match $SelfPattern) {
        $f.Severity = 'Test'
        $f.Rule = 'Known-benign automation (test)'
        $f.Attack = 'n/a'
        $f.Why = "Self-run of the Threat-Hunter or an automation-host preamble launched with -ExecutionPolicy Bypass, recorded by script-block logging. Benign, shown for transparency - not a threat."
    }
}

if ($SortBy -eq 'Time') {
    # Chronological: most recent first
    $findings = $findings | Sort-Object Time -Descending
} else {
    # Triage order: most dangerous first, then oldest-to-newest within a level
    $findings = $findings | Sort-Object @{ Expression = { $sevRank[$_.Severity] }; Descending = $true }, Time
}

# --- Console report ---
Write-Host ''
Write-Host ('  Scanned {0} event(s), {1} finding(s)' -f $events.Count, $findings.Count) -ForegroundColor Cyan
Write-Host ''

if ($findings.Count -eq 0) {
    Write-Host '  No suspicious patterns matched. Clean (for the loaded rule pack).' -ForegroundColor Green
} else {
    foreach ($f in $findings) {
        $color = 'Gray'
        if ($f.Severity -eq 'High') { $color = 'Red' }
        elseif ($f.Severity -eq 'Medium') { $color = 'Yellow' }
        elseif ($f.Severity -eq 'Low') { $color = 'DarkCyan' }
        elseif ($f.Severity -eq 'Test') { $color = 'DarkGreen' }

        Write-Host ('  [{0}] {1}  ({2})' -f $f.Severity.ToUpperInvariant(), $f.Rule, $f.Attack) -ForegroundColor $color
        Write-Host ('        time : {0}  src: {1}  user: {2}' -f $f.Time, $f.Source, $f.User) -ForegroundColor DarkGray
        $line = [string]$f.CommandLine
        if ($line.Length -gt 160) { $line = $line.Substring(0, 157) + '...' }
        Write-Host ('        cmd  : {0}' -f $line) -ForegroundColor DarkGray
        Write-Host ''
    }

    # Severity summary
    $high = @($findings | Where-Object { $_.Severity -eq 'High' }).Count
    $med = @($findings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $low = @($findings | Where-Object { $_.Severity -eq 'Low' }).Count
    $test = @($findings | Where-Object { $_.Severity -eq 'Test' }).Count
    Write-Host ('  Summary:  High {0}   Medium {1}   Low {2}   (+ {3} test / self-run, ignored)' -f $high, $med, $low, $test) -ForegroundColor Cyan
}

# --- JSON report ---
# -InputObject, not the pipeline: piping unrolls the array, so a hunt that
# matched once writes a bare object and a hunt that matched nothing writes an
# empty file. Anything reading this back expects an array either way.
if ($Json) {
    ConvertTo-Json -InputObject @($findings) -Depth 5 | Out-File -FilePath $Json -Encoding utf8
    Write-Host ('  JSON report -> {0}' -f $Json) -ForegroundColor Green
}

# --- HTML report ---
if ($Html) {
    $rows = ''
    foreach ($f in $findings) {
        $sevClass = 'sev-' + $f.Severity.ToLower()
        $enc = {
            param($s)
            $s = [string]$s
            $s = $s.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;')
            return $s
        }
        $rank = $sevRank[$f.Severity]
        if ($f.Time -is [datetime]) { $timeSort = $f.Time.ToString('yyyy-MM-ddTHH:mm:ss') }
        else { $timeSort = [string]$f.Time }
        $rows += ('<tr class="{0}"><td class="sev" data-sort="{7}">{1}</td><td>{2}</td><td class="mono">{3}</td><td class="small" data-sort="{8}">{4}</td><td class="mono">{5}</td><td class="why">{6}</td></tr>' -f `
                $sevClass, $f.Severity, (& $enc $f.Rule), (& $enc $f.Attack), (& $enc $f.Time), (& $enc $f.CommandLine), (& $enc $f.Why), $rank, $timeSort)
    }
    $generated = Get-Date
    $reportHtml = @"
<!doctype html><html><head><meta charset="utf-8"><title>Windows Log Threat-Hunt Report</title>
<style>
  body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:32px}
  h1{font-size:20px;margin:0 0 4px} .sub{color:#94a3b8;margin:0 0 6px} .hint{color:#64748b;font-size:12px;margin:0 0 18px}
  table{border-collapse:collapse;width:100%;background:#1e293b;border-radius:8px;overflow:hidden}
  th,td{padding:10px 12px;text-align:left;vertical-align:top;border-bottom:1px solid #334155}
  th{background:#334155;font-size:12px;text-transform:uppercase;letter-spacing:.04em;cursor:pointer;user-select:none}
  th:hover{background:#3f4d63} th.active{color:#e2e8f0} th .arw{opacity:.7;font-size:10px}
  td.sev{font-weight:700} .mono{font-family:Consolas,monospace} .small{font-size:12px;color:#cbd5e1;white-space:nowrap}
  td.why{color:#94a3b8;max-width:340px} .mono td, td.mono{word-break:break-all}
  tr.sev-high td.sev{color:#f87171} tr.sev-medium td.sev{color:#fbbf24} tr.sev-low td.sev{color:#38bdf8} tr.sev-test td.sev{color:#4ade80}
  .foot{color:#64748b;margin-top:20px;font-size:12px}
</style></head><body>
<h1>Windows Log Threat-Hunt Report</h1>
<p class="sub">$($findings.Count) finding(s) across $($events.Count) event(s) &middot; generated $generated</p>
<p class="hint">Tip: click any column header to sort &middot; click again to reverse. Try <b>Time</b> for newest-first.</p>
<table id="findings"><thead><tr><th>Severity</th><th>Rule</th><th>ATT&amp;CK</th><th>Time</th><th>Command line</th><th>Why it matters</th></tr></thead>
<tbody>$rows</tbody></table>
<p class="foot">Read-only defensive tooling. Findings are pattern matches, not confirmed compromise &mdash; verify in context.<br>Windows Log Threat Hunter &mdash; created by <b>Baris Burak Turgut</b> &middot; &copy; 2026 Baris Burak Turgut &middot; provided &ldquo;as is&rdquo;, without warranty; no liability for use.</p>
<script>
(function(){
  var table=document.getElementById('findings');
  if(!table||!table.tHead){return;}
  var tbody=table.tBodies[0];
  var headers=table.tHead.rows[0].cells;
  var state={col:0,dir:-1};
  function isNum(v){return v!==''&&!isNaN(Number(v));}
  function val(row,col){var td=row.cells[col];var d=td.getAttribute('data-sort');return d!==null?d:td.textContent.trim();}
  function paint(){
    for(var i=0;i<headers.length;i++){
      var h=headers[i];var base=h.getAttribute('data-label');
      if(base===null){base=h.textContent;h.setAttribute('data-label',base);}
      if(i===state.col){h.innerHTML=base+' <span class="arw">'+(state.dir>0?'&#9650;':'&#9660;')+'</span>';h.className='active';}
      else{h.innerHTML=base;h.className='';}
    }
  }
  function sortCol(col){
    if(state.col===col){state.dir=-state.dir;}
    else{state.col=col;state.dir=(col===0||col===3)?-1:1;}
    var rows=Array.prototype.slice.call(tbody.rows);
    rows.sort(function(a,b){
      var va=val(a,col),vb=val(b,col),cmp;
      if(isNum(va)&&isNum(vb)){cmp=Number(va)-Number(vb);}
      else{cmp=va<vb?-1:(va>vb?1:0);}
      return cmp*state.dir;
    });
    for(var i=0;i<rows.length;i++){tbody.appendChild(rows[i]);}
    paint();
  }
  for(var i=0;i<headers.length;i++){(function(idx){headers[idx].addEventListener('click',function(){sortCol(idx);});})(i);}
  paint();
})();
</script>
</body></html>
"@
    $reportHtml | Out-File -FilePath $Html -Encoding utf8
    Write-Host ('  HTML report -> {0}' -f $Html) -ForegroundColor Green
}

Write-Host ''

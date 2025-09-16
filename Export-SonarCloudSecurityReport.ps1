param(
  [Parameter(Mandatory=$true)][string]$ProjectKey,
  [Parameter(Mandatory=$true)][string]$Organization,
  [Parameter(Mandatory=$true)][string]$Token,
  [string]$OutFile = "SonarCloud-Executive-Report.html",
  [string]$Branch,
  [switch]$IncludeResolved
)

$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$baseUrl = "https://sonarcloud.io"

# -------------------------
# Helpers / Infrastructure
# -------------------------
$pair = "${Token}:"
$basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
$headers = @{ Authorization = "Basic $basic" }

function Invoke-SonarApi {
  param([string]$PathAndQuery,[switch]$NeedsOrg)
  $uri = "$baseUrl$PathAndQuery"
  if ($NeedsOrg) {
    $sep = '?'; if ($PathAndQuery -like '*?*') { $sep = '&' }
    $uri = $uri + $sep + "organization=" + [uri]::EscapeDataString($Organization)
  }
  try { return Invoke-RestMethod -Headers $headers -Method GET -Uri $uri }
  catch { Write-Host "Call failed: $uri" -ForegroundColor Yellow; throw }
}

function EscHtml([string]$s){ if($null -eq $s){""} else { $s -replace "&","&amp;" -replace "<","&lt;" -replace ">","&gt;" } }
function HtmlUrl([string]$u){ if($null -eq $u){""} else { $u -replace "&","&amp;" } }

# Consistent issue-search query builder
function Build-IssuesQuery {
  param([string]$TypesCsv, [string]$FacetKey)
  if ([string]::IsNullOrWhiteSpace($TypesCsv)) { $TypesCsv = "BUG,VULNERABILITY,CODE_SMELL" }
  $q = "componentKeys=$([uri]::EscapeDataString($ProjectKey))&types=$TypesCsv"
  if (-not $IncludeResolved) { $q += "&resolved=false" }
  if ($Branch) { $q += "&branch=$([uri]::EscapeDataString($Branch))" }
  if ($FacetKey) { $q += "&ps=1&facets=$FacetKey" }
  return $q
}

function Get-AllIssues {
  param([string]$BaseQuery,[int]$PageSize=500,[int]$MaxPages=20)
  $all = @(); $page = 1
  while ($page -le $MaxPages) {
    $resp = Invoke-SonarApi "$BaseQuery&ps=$PageSize&p=$page" -NeedsOrg
    if ($resp -and $resp.issues) { $all += $resp.issues } else { break }
    $total = 0
    if ($resp.paging -and $resp.paging.total) { $total = [int]$resp.paging.total }
    if ($total -gt 0 -and $all.Count -ge $total) { break }
    if ($resp.issues.Count -lt $PageSize) { break }
    $page++
  }
  $all
}

function Get-FacetValuesFor {
  param([string]$FacetKey)
  try {
    $resp = Invoke-SonarApi "/api/issues/search?$(Build-IssuesQuery 'VULNERABILITY' $FacetKey)" -NeedsOrg
  } catch {
    Write-Host "Facet '$FacetKey' not supported (skipping)." -ForegroundColor DarkYellow
    return @()
  }
  $result = @()
  if ($resp -and $resp.facets) {
    foreach ($f in $resp.facets) {
      if ($f.property -eq $FacetKey -and $f.values) {
        foreach ($v in $f.values) {
          $name = "(no label)"; if ($v.text) { $name = $v.text } elseif ($v.val) { $name = $v.val }
          $result += [PSCustomObject]@{ Name=$name; Val=$v.val; Count=[int]$v.count }
        }
      }
    }
  }
  $result | Sort-Object -Property Count -Descending
}

# Accepts 1 / 1.0 / "A" ... and maps to A..E
function RatingLetter($v) {
  if ($null -eq $v) { return '' }
  $s = "$v".Trim()
  switch ($s.ToUpper()) {
    'A' {return 'A'} 'B' {return 'B'} 'C' {return 'C'} 'D' {return 'D'} 'E' {return 'E'}
    default {
      try {
        $n = [double]$s
        if     ($n -lt 1.5) { return 'A' }
        elseif ($n -lt 2.5) { return 'B' }
        elseif ($n -lt 3.5) { return 'C' }
        elseif ($n -lt 4.5) { return 'D' }
        else                { return 'E' }
      } catch { return '' }
    }
  }
}
function SizeBucket([int]$loc) { if ($loc -lt 1000) { 'S' } elseif ($loc -lt 10000) { 'M' } elseif ($loc -lt 100000) { 'L' } else { 'XL' } }
function FmtNum([string]$v) { if ($null -eq $v -or $v -eq '') { return '-' } try { return ([double]$v).ToString('#,0.##') } catch { return $v } }

# -------------------------
# Metrics / Data
# -------------------------
Write-Host ">> Fetching project metrics..."
$metricKeys = @(
  'bugs','vulnerabilities','code_smells',
  'security_hotspots',
  'reliability_rating','security_rating','sqale_rating','sqale_debt_ratio',
  'duplicated_lines_density','duplicated_blocks',
  'coverage','tests','ncloc'
) -join ','

$measuresResp = Invoke-SonarApi "/api/measures/component?component=$([uri]::EscapeDataString($ProjectKey))&metricKeys=$metricKeys" -NeedsOrg
$measures = @{}
if ($measuresResp.component -and $measuresResp.component.measures) {
  foreach ($m in $measuresResp.component.measures) { $measures[$m.metric] = $m.value }
}

# Quality Gate + last analysis date
$qualityStatus = "-"
try {
  $branchQuery = ''
  if ($Branch) { $branchQuery = '&branch=' + [uri]::EscapeDataString($Branch) }
  $qg = Invoke-SonarApi "/api/qualitygates/project_status?projectKey=$([uri]::EscapeDataString($ProjectKey))$branchQuery" -NeedsOrg
  if ($qg.projectStatus.status) { $qualityStatus = $qg.projectStatus.status } # OK / ERROR
} catch {}

$analysisDate = (Get-Date).ToString('yyyy-MM-dd')
try {
  $pa = Invoke-SonarApi "/api/project_analyses/search?project=$([uri]::EscapeDataString($ProjectKey))" -NeedsOrg
  if ($pa.analyses -and $pa.analyses[0] -and $pa.analyses[0].date) {
    $analysisDate = ([DateTime]$pa.analyses[0].date).ToString('yyyy-MM-dd')
  }
} catch {}

Write-Host ">> Fetching issues (severity matrix, top rules, breakdown)..."
$issuesAll = Get-AllIssues "/api/issues/search?$(Build-IssuesQuery 'BUG,VULNERABILITY,CODE_SMELL' '')"

# Severity matrix by type
$sevOrder = @('BLOCKER','CRITICAL','MAJOR','MINOR','INFO')
$sevMatrix = @{}
foreach ($s in $sevOrder) { $sevMatrix[$s] = @{ BUG=0; VULNERABILITY=0; CODE_SMELL=0 } }
foreach ($it in $issuesAll) {
  $s = $it.severity; $t = $it.type
  if ($sevMatrix.ContainsKey($s) -and $sevMatrix[$s].ContainsKey($t)) { $sevMatrix[$s][$t]++ }
}

# Open totals by type (after filters)
$openBugs  = 0; $openVulns = 0; $openSmells = 0
foreach($s in $sevOrder){ $openBugs += $sevMatrix[$s]['BUG']; $openVulns += $sevMatrix[$s]['VULNERABILITY']; $openSmells += $sevMatrix[$s]['CODE_SMELL'] }

# Accepted Issues (FALSE-POSITIVE / WONTFIX)
function Get-IssuesTotal([string]$Query){
  try {
    $resp = Invoke-SonarApi "/api/issues/search?$Query" -NeedsOrg
    if ($resp.paging -and $resp.paging.total) { return [int]$resp.paging.total }
  } catch {}
  return 0
}
$accQuery = "componentKeys=$([uri]::EscapeDataString($ProjectKey))&types=BUG,VULNERABILITY,CODE_SMELL&resolved=true&resolutions=FALSE-POSITIVE,WONTFIX"
if ($Branch) { $accQuery += "&branch=$([uri]::EscapeDataString($Branch))" }
$acceptedIssues = Get-IssuesTotal $accQuery

# Top Common Issues (by rule)
$ruleCounts = @{}; $ruleTypes  = @{}
foreach ($it in $issuesAll) {
  if ($it.rule) {
    if ($ruleCounts.ContainsKey($it.rule)) { $ruleCounts[$it.rule]++ } else { $ruleCounts[$it.rule] = 1 }
    if (-not $ruleTypes.ContainsKey($it.rule)) { $ruleTypes[$it.rule] = $it.type }
  }
}
$entries = $ruleCounts.GetEnumerator() | Sort-Object -Property Value -Descending
$topRules = @(); $ix=0; foreach ($e in $entries){ $topRules += $e; $ix++; if($ix -ge 30){ break } }

# Rule display names
$ruleNames = @{}
foreach ($r in $topRules) {
  $nm = $null
  try {
    $rk = [uri]::EscapeDataString($r.Key)
    $rshow = Invoke-SonarApi "/api/rules/show?key=$rk" -NeedsOrg
    if ($rshow -and $rshow.rule -and $rshow.rule.name) { $nm = $rshow.rule.name }
  } catch {}
  if (-not $nm) { $nm = $r.Key }
  $ruleNames[$r.Key] = $nm
}

# Facets (for VULNERABILITY only)
Write-Host ">> Fetching categories (CWE / OWASP)..."
$cweDist  = Get-FacetValuesFor "cwe"
$owasp21  = Get-FacetValuesFor "owaspTop10-2021"
$owasp17  = Get-FacetValuesFor "owaspTop10-2017"
$owaspM24 = Get-FacetValuesFor "owaspTop10Mobile-2024"  # may not exist; OK

# KPI helpers
$bugs   = [int]($measures['bugs']            | ForEach-Object {$_})
$vulns  = [int]($measures['vulnerabilities'] | ForEach-Object {$_})
$smells = [int]($measures['code_smells']     | ForEach-Object {$_})
$hot    =        ($measures['security_hotspots'])
$relR   = RatingLetter $measures['reliability_rating']
$secR   = RatingLetter $measures['security_rating']
$mntR   = RatingLetter $measures['sqale_rating']
$debt   = $measures['sqale_debt_ratio']
$dupPct = $measures['duplicated_lines_density']
$dupBlk = $measures['duplicated_blocks']
$cvg    = $measures['coverage']
$tests  = $measures['tests']
$loc    = [int]($measures['ncloc'] | ForEach-Object {$_})
$size   = SizeBucket $loc

# -------------------------
# Styles & visual components
# -------------------------
$style = @"
<style>
  :root{
    --bg:#0f172a; --card:#111827; --border:#1f2937; --muted:#94a3b8; --ink:#e5e7eb;
    --ok:#22c55e; --err:#ef4444; --warn:#f59e0b; --brand:#ff6f3d; --link:#93c5fd;
  }
  *{box-sizing:border-box}
  body{font-family: Inter, "Segoe UI", Roboto, Arial, Helvetica, sans-serif; margin:0; background:var(--bg); color:var(--ink); -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale;}
  a{color:var(--link);text-decoration:none}
  .wrap{max-width:1100px;margin:28px auto;padding:0 18px}
  .muted{color:var(--muted)}
  .pill{background:#0b1220;color:#e2e8f0;padding:2px 8px;border-radius:999px;font-weight:700;border:1px solid var(--border)}

  .doc-page{background:var(--card);border:1px solid var(--border);border-radius:14px;overflow:hidden;box-shadow:0 10px 24px rgba(0,0,0,.25), 0 2px 8px rgba(0,0,0,.18);margin-bottom:18px}
  .doc-head{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;background:#0b1220;border-bottom:1px solid var(--border)}
  .doc-title{font-weight:900;font-size:18px;color:#e5e7eb;letter-spacing:.2px}
  .doc-sub{color:#94a3b8;font-size:13px;margin-left:8px}
  .doc-body{padding:16px}
  .brand{font-size:22px;font-weight:800;color:#e5e7eb;letter-spacing:.2px}
  .brand:before{content:""; display:inline-block; width:10px;height:10px;border-radius:50%;background:var(--brand); margin-right:8px; transform:translateY(-1px);}

  .grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
  .card{background:var(--card); border:1px solid var(--border); border-radius:14px; padding:16px; box-shadow:0 10px 24px rgba(0,0,0,.15), 0 2px 8px rgba(0,0,0,.12);}
  .card-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px}
  .kpi-big{font-size:34px; font-weight:900; line-height:1; margin:6px 0 2px; font-variant-numeric: tabular-nums; color:#f8fafc;}

  /* A/B/C/D/E grade bubble */
  .grade{width:28px;height:28px;border-radius:999px;display:inline-flex;align-items:center;justify-content:center;
         font-weight:900;color:#fff;letter-spacing:.2px;box-shadow:0 0 0 3px rgba(0,0,0,.15), inset 0 0 0 5px rgba(255,255,255,.06)}
  .gA{background:#22c55e}.gB{background:#84cc16}.gC{background:#f59e0b}.gD{background:#ef4444}.gE{background:#991b1b}

  /* Quality Gate banner */
  .qg-card{padding:0;border-radius:14px;overflow:hidden;border:1px solid #064e3b;background:linear-gradient(135deg,#064e3b,#065f46)}
  .qg-card.err{border-color:#7f1d1d;background:linear-gradient(135deg,#7f1d1d,#991b1b)}
  .qg-inner{padding:16px;display:flex;align-items:center;gap:14px}
  .qg-icon{width:36px;height:36px;border-radius:50%;display:grid;place-items:center;font-weight:900;color:#052e2a;background:#22c55e}
  .qg-card.err .qg-icon{background:#fecaca;color:#7f1d1d}
  .qg-text{font-size:28px;font-weight:900;color:#ecfdf5}
  .qg-sub{color:#cbd5e1;font-size:12px;margin-top:4px}

  table{width:100%;border-collapse:collapse;font-size:14px}
  th,td{padding:11px 10px;border-bottom:1px solid var(--border);vertical-align:top}
  th{background:#0b1220;text-align:left;font-weight:700;color:#cbd5e1}
  tbody tr:hover{background:rgba(148,163,184,.06)}

  .sev-chip{display:inline-block;border-radius:999px;padding:2px 10px 3px;font-weight:800;color:#fff;font-size:12px}
  .sev-BLOCKER{background:#991b1b}.sev-CRITICAL{background:#dc2626}.sev-MAJOR{background:#c2410c}.sev-MINOR{background:#6b7280}.sev-INFO{background:#6b7280}
  .type-badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700}
  .t-bug{background:#7f1d1d;color:#fee2e2;border:1px solid #9f2525}
  .t-vuln{background:#7c2d12;color:#ffedd5;border:1px solid #9a3412}
  .t-smell{background:#1e1b4b;color:#eef2ff;border:1px solid #3730a3}

  .meter{position:relative;height:10px;background:#0b1220;border:1px solid var(--border);border-radius:999px;margin-top:12px;overflow:hidden}
  .meter > span{display:block;height:100%;background:linear-gradient(90deg,#60a5fa,#22c55e);border-radius:999px;box-shadow:0 0 12px rgba(96,165,250,.35)}

  .footer-note{font-size:12px;color:var(--muted);margin-top:8px}

  /* Overview page */
  .q-grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
  .q-card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:16px}
  .q-label{color:var(--muted);font-weight:700;margin-bottom:6px}
  .q-big{font-size:28px;font-weight:900;line-height:1;margin:8px 0;color:#f8fafc}
  .q-sub{color:var(--muted)}
  .q-sep{height:1px;background:var(--border);margin:14px 0}

  /* donuts */
  .donut{width:58px;height:58px;border-radius:50%;display:inline-grid;place-items:center;
         background:conic-gradient(var(--c) calc(var(--p)*1%), #1f2937 0);position:relative;margin-right:10px}
  .donut:after{content:"";position:absolute;inset:6px;background:#0f172a;border-radius:50%}
  .donut > span{position:relative;font-size:12px;font-weight:800;color:#e5e7eb}

  @media print{
    :root{ --bg:#fff; --card:#fff; --border:#e5e7eb; --ink:#111; --muted:#6b7280; }
    body{background:#fff;color:#111}
    .doc-page{box-shadow:none}
    th{background:#f3f4f6;color:#334155}
  }
</style>
"@

function MeterHtml([double]$pct){
  if ($pct -lt 0) { $pct = 0 }
  if ($pct -gt 100) { $pct = 100 }
  $pct = [math]::Round($pct,2)
  "<div class='meter'><span style='width:$pct%'></span></div>"
}

# Colored donut (good coverage = high; good duplication = low)
function DonutHtml([double]$pct,[string]$kind){
  if ($pct -lt 0) { $pct = 0 } elseif ($pct -gt 100) { $pct = 100 }
  $color = "#22c55e"
  if ($kind -eq "coverage") {
    if     ($pct -lt 50) { $color = "#ef4444" }
    elseif ($pct -lt 80) { $color = "#f59e0b" }
    else                 { $color = "#22c55e" }
  } else {
    if     ($pct -le 5)  { $color = "#22c55e" }
    elseif ($pct -le 10) { $color = "#f59e0b" }
    else                 { $color = "#ef4444" }
  }
  $pct = [math]::Round($pct,1)
  "<div class='donut' style='--p:$pct;--c:$color'><span>$pct%</span></div>"
}

function BuildFacetFilter([string]$facetKey,[string]$facetVal){
  $flt = ""
  if     ($facetKey -eq "cwe")              { $flt = "&cwe=$([uri]::EscapeDataString($facetVal))" }
  elseif ($facetKey -eq "owaspTop10-2021")  { $flt = "&owaspTop10-2021=$([uri]::EscapeDataString($facetVal))" }
  elseif ($facetKey -eq "owaspTop10-2017")  { $flt = "&owaspTop10-2017=$([uri]::EscapeDataString($facetVal))" }
  return $flt
}

function DocFromFacet($title,$subtitle,$items,$facetKey){
  if ($null -eq $items) { $items = @() }
  $rows = ""
  foreach($i in $items){
    $name = EscHtml $i.Name
    $val  = $i.Val
    $cnt  = $i.Count
    $flt  = BuildFacetFilter $facetKey $val
    $lnk  = "$baseUrl/project/issues?id=$([uri]::EscapeDataString($ProjectKey))&organization=$([uri]::EscapeDataString($Organization))&types=VULNERABILITY$flt"
    if (-not $IncludeResolved) { $lnk += "&resolved=false" }
    if ($Branch) { $lnk += "&branch=$([uri]::EscapeDataString($Branch))" }
    $lnk = HtmlUrl $lnk
    $code = EscHtml $val
    $rows += "<tr><td><span class='pill'>$code</span></td><td>$name</td><td>$cnt</td><td><a class='pill' target='_blank' href='$lnk'>View in project</a></td></tr>`n"
  }
  if ($rows -eq "") { $rows = "<tr><td colspan='4' class='muted'>No results for the current filters.</td></tr>" }
@"
  <div class="doc-page">
    <div class="doc-head">
      <div class="brand">sonarcloud</div>
      <div class="doc-title">$title <span class="doc-sub">$subtitle</span></div>
      <div class="badge badge-ok">Annex</div>
    </div>
    <div class="doc-body">
      <table>
        <thead><tr><th>Code</th><th>Category</th><th>#</th><th></th></tr></thead>
        <tbody>$rows</tbody>
      </table>
      <div class="footer-note">* Automatically derived from project vulnerabilities (branch/status filters applied).</div>
    </div>
  </div>
"@
}

function DocCweTop25($items){
  if ($null -eq $items) { $items = @() }
  $top = @(); $ix=0; foreach($i in $items){ $top += $i; $ix++; if ($ix -ge 25) { break } }
  $rows = ""; $rank = 1
  foreach($i in $top){
    $cweId = $i.Val; if ($cweId -and $cweId -match '^\d+$'){ $cweId = "CWE-$cweId" }
    $name  = EscHtml $i.Name
    $cnt   = $i.Count
    $flt   = BuildFacetFilter "cwe" $i.Val
    $lnk   = "$baseUrl/project/issues?id=$([uri]::EscapeDataString($ProjectKey))&organization=$([uri]::EscapeDataString($Organization))&types=VULNERABILITY$flt"
    if (-not $IncludeResolved) { $lnk += "&resolved=false" }
    if ($Branch) { $lnk += "&branch=$([uri]::EscapeDataString($Branch))" }
    $lnk = HtmlUrl $lnk
    $rows += "<tr><td>$rank</td><td><span class='pill'>$(EscHtml $cweId)</span></td><td>$name</td><td>$cnt</td><td><a class='pill' target='_blank' href='$lnk'>View in project</a></td></tr>`n"
    $rank++
  }
  if ($rows -eq "") { $rows = "<tr><td colspan='5' class='muted'>No results for the current filters.</td></tr>" }
@"
  <div class="doc-page">
    <div class="doc-head">
      <div class="brand">sonarcloud</div>
      <div class="doc-title">CWE Top 25 <span class="doc-sub">Prevalence in project (up to 25)</span></div>
      <div class="badge badge-ok">Annex</div>
    </div>
    <div class="doc-body">
      <table>
        <thead><tr><th>#</th><th>CWE</th><th>Title</th><th>#</th><th></th></tr></thead>
        <tbody>$rows</tbody>
      </table>
      <div class="footer-note">* List reflects CWE present (sorted by occurrences), not the official yearly list.</div>
    </div>
  </div>
"@
}

function DocAsvs403(){
  $asvs = @(
    @{Code='V1';  Name='Architecture, Design and Threat Modeling';},
    @{Code='V2';  Name='Authentication';},
    @{Code='V3';  Name='Session Management';},
    @{Code='V4';  Name='Access Control';},
    @{Code='V5';  Name='Validation, Sanitization and Encoding';},
    @{Code='V6';  Name='Stored Cryptography';},
    @{Code='V7';  Name='Error Handling and Logging';},
    @{Code='V8';  Name='Data Protection';},
    @{Code='V9';  Name='Communications';},
    @{Code='V10'; Name='Malicious Code';},
    @{Code='V11'; Name='Business Logic';},
    @{Code='V12'; Name='Files and Resources';},
    @{Code='V13'; Name='API and Web Service';},
    @{Code='V14'; Name='Configuration';}
  )
  $rows = ""
  foreach($x in $asvs){ $rows += "<tr><td><span class='pill'>$($x.Code)</span></td><td>$(EscHtml $x.Name)</td><td class='muted'>—</td></tr>`n" }
@"
  <div class="doc-page">
    <div class="doc-head">
      <div class="brand">sonarcloud</div>
      <div class="doc-title">OWASP ASVS 4.0.3 <span class="doc-sub">Verification framework (visual reference)</span></div>
      <div class="badge badge-ok">Annex</div>
    </div>
    <div class="doc-body">
      <table>
        <thead><tr><th>Section</th><th>Topic</th><th>Notes</th></tr></thead>
        <tbody>$rows</tbody>
      </table>
      <div class="footer-note">* SonarCloud does not map directly to ASVS; the table is a structure reference only.</div>
    </div>
  </div>
"@
}

# -------------------------
# Table rows
# -------------------------
$sevRows = ""
foreach($s in $sevOrder){
  $sevRows += "<tr><td><span class='sev-chip sev-$s'>$s</span></td><td>$($sevMatrix[$s]['BUG'])</td><td>$($sevMatrix[$s]['VULNERABILITY'])</td><td>$($sevMatrix[$s]['CODE_SMELL'])</td></tr>`n"
}

$rulesRows = ""
foreach ($tr in $topRules) {
  $rkey  = $tr.Key
  $rname = EscHtml $ruleNames[$rkey]
  $count = $tr.Value
  $rtype = $ruleTypes[$rkey]
  $ruleLink = "$baseUrl/project/issues?id=$([uri]::EscapeDataString($ProjectKey))&organization=$([uri]::EscapeDataString($Organization))&rules=$([uri]::EscapeDataString($rkey))"
  if (-not $IncludeResolved) { $ruleLink += "&resolved=false" }
  if ($Branch) { $ruleLink += "&branch=$([uri]::EscapeDataString($Branch))" }
  $typeBadge = "<span class='type-badge t-smell'>Code Smell</span>"
  if ($rtype -eq 'BUG') { $typeBadge = "<span class='type-badge t-bug'>Bug</span>" }
  elseif ($rtype -eq 'VULNERABILITY') { $typeBadge = "<span class='type-badge t-vuln'>Vulnerability</span>" }
  $rulesRows += "<tr><td><a href='$(HtmlUrl $ruleLink)' target='_blank'>$rname</a></td><td>$typeBadge</td><td>$count</td></tr>`n"
}

function FacetTable($title,$items,$facetKey){
  if ($null -eq $items -or $items.Count -eq 0) {
    return "<div class='doc-page'><div class='doc-head'><div class='brand'>sonarcloud</div><div class='doc-title'>$title</div><div class='badge badge-ok'>Annex</div></div><div class='doc-body'><div class='muted'>No results</div></div></div>"
  }
  $rows = ""
  foreach ($i in $items) {
    $name = EscHtml $i.Name; $val = $i.Val; $cnt = $i.Count
    $flt  = ""
    if ($facetKey -eq "cwe") { $flt = "&cwe=$([uri]::EscapeDataString($val))" }
    elseif ($facetKey -eq "owaspTop10-2021") { $flt = "&owaspTop10-2021=$([uri]::EscapeDataString($val))" }
    elseif ($facetKey -eq "owaspTop10-2017") { $flt = "&owaspTop10-2017=$([uri]::EscapeDataString($val))" }
    elseif ($facetKey -eq "owaspTop10Mobile-2024") { $flt = "&owaspTop10Mobile-2024=$([uri]::EscapeDataString($val))" }
    $lnk = "$baseUrl/project/issues?id=$([uri]::EscapeDataString($ProjectKey))&organization=$([uri]::EscapeDataString($Organization))&types=VULNERABILITY$flt"
    if (-not $IncludeResolved) { $lnk += "&resolved=false" }
    if ($Branch) { $lnk += "&branch=$([uri]::EscapeDataString($Branch))" }
    $rows += "<tr><td><span class='pill'>$(EscHtml $val)</span></td><td>$name</td><td>$cnt</td><td><a class='pill' target='_blank' href='$(HtmlUrl $lnk)'>View in project</a></td></tr>`n"
  }
@"
  <div class='doc-page'>
    <div class='doc-head'>
      <div class='brand'>sonarcloud</div>
      <div class='doc-title'>$title</div>
      <div class='badge badge-ok'>Annex</div>
    </div>
    <div class='doc-body'>
      <table>
        <thead><tr><th>Code</th><th>Category</th><th>#</th><th></th></tr></thead>
        <tbody>$rows</tbody>
      </table>
    </div>
  </div>
"@
}

# -------------------------
# Meters / donuts / Quality Gate UI
# -------------------------
$cvPct = 0.0; if ($cvg) { try { $cvPct = [double]$cvg } catch {} }
$dupPctVal = 0.0; if ($dupPct) { try { $dupPctVal = [double]$dupPct } catch {} }
$coverageMeter = MeterHtml $cvPct
$dupMeter      = MeterHtml $dupPctVal
$donutCoverage = DonutHtml $cvPct "coverage"
$donutDup      = DonutHtml $dupPctVal "dup"

$qualityOk = ($qualityStatus -eq 'OK' -or $qualityStatus -eq 'PASS' -or $qualityStatus -eq 'PASSED')
$qgClass = if ($qualityOk) { 'qg-card' } else { 'qg-card err' }
$qgText  = if ($qualityOk) { 'PASSED' } else { 'FAILED' }
$qgIcon  = if ($qualityOk) { '✓' } else { '!' }

# -------------------------
# Annex pages
# -------------------------
$docOw21 = DocFromFacet "OWASP Top 10 (2021)" "Categories present in the project" $owasp21 "owaspTop10-2021"
$docOw17 = DocFromFacet "OWASP Top 10 (2017)" "Categories present in the project" $owasp17 "owaspTop10-2017"
$docCwe  = DocCweTop25 $cweDist
$docAsvs = DocAsvs403

# -------------------------
# “Overall Code / Quality Overview” page
# -------------------------
$branchLabel = if ($Branch) { $Branch } else { '—' }
$qualHtml = @"
<div class="doc-page">
  <div class="doc-head">
    <div class="brand">sonarcloud</div>
    <div class="doc-title">Overall Code <span class="doc-sub">Quality Overview</span></div>
    <div class="muted">Branch $(EscHtml $branchLabel)</div>
  </div>
  <div class="doc-body">
    <div class="q-grid3">
      <div class="q-card">
        <div class="q-label">Security</div>
        <div style="display:flex;align-items:center;gap:12px">
          <span class="grade g$secR">$secR</span>
          <div>
            <div class="q-big">$(FmtNum $openVulns)</div>
            <div class="q-sub">Open issues</div>
          </div>
        </div>
        <div class="q-sep"></div>
        <div class="q-sub">Security Hotspots</div>
        <div>$(FmtNum $hot)</div>
      </div>

      <div class="q-card">
        <div class="q-label">Reliability</div>
        <div style="display:flex;align-items:center;gap:12px">
          <span class="grade g$relR">$relR</span>
          <div>
            <div class="q-big">$(FmtNum $openBugs)</div>
            <div class="q-sub">Open issues</div>
          </div>
        </div>
      </div>

      <div class="q-card">
        <div class="q-label">Maintainability</div>
        <div style="display:flex;align-items:center;gap:12px">
          <span class="grade g$mntR">$mntR</span>
          <div>
            <div class="q-big">$(FmtNum $openSmells)</div>
            <div class="q-sub">Open issues</div>
          </div>
        </div>
      </div>
    </div>

    <div class="q-grid3" style="margin-top:16px">
      <div class="q-card">
        <div class="q-label">Accepted Issues</div>
        <div class="q-big">$(FmtNum $acceptedIssues)</div>
        <div class="q-sub">False-Positive & Won’t Fix</div>
      </div>

      <div class="q-card">
        <div class="q-label">Coverage</div>
        <div style="display:flex;align-items:center">
          $donutCoverage
          <div>
            <div class="q-big">$(FmtNum $cvg)%</div>
            <div class="q-sub">Unit Tests: $(FmtNum $tests)</div>
          </div>
        </div>
      </div>

      <div class="q-card">
        <div class="q-label">Duplications</div>
        <div style="display:flex;align-items:center">
          $donutDup
          <div>
            <div class="q-big">$(FmtNum $dupPct)%</div>
            <div class="q-sub">Duplicated Blocks: $(FmtNum $dupBlk)</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
"@

# -------------------------
# Final HTML
# -------------------------
$now = (Get-Date).ToString("yyyy-MM-dd HH:mm")
$projLink = "$baseUrl/summary/new_code?id=$([uri]::EscapeDataString($ProjectKey))&organization=$([uri]::EscapeDataString($Organization))"
if ($Branch) { $projLink += "&branch=$([uri]::EscapeDataString($Branch))" }
$projLinkHtml = HtmlUrl $projLink

$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
<title>Executive Report - $(EscHtml $ProjectKey)</title>
$style
</head>
<body>
  <div class="wrap">

    <!-- Page 1: Executive Report -->
    <div class="doc-page">
      <div class="doc-head">
        <div class="brand">sonarcloud</div>
        <div class="doc-title">Executive Report <span class="doc-sub">Project: <a href="$projLinkHtml" target="_blank">$(EscHtml $ProjectKey)</a></span></div>
        <div class="$qgClass" style="min-width:220px">
          <div class="qg-inner">
            <div class="qg-icon">$qgIcon</div>
            <div>
              <div class="qg-text">$qgText</div>
              <div class="qg-sub">Quality Gate</div>
            </div>
          </div>
        </div>
      </div>

      <div class="doc-body">
        <div class="grid-3">
          <div class="card">
            <div class="card-head"><span class="muted">Project Size</span></div>
            <div class="kpi-big">$(FmtNum $loc)</div>
            <div class="muted">Lines of Code • Size <span class="pill">$(EscHtml (SizeBucket $loc))</span></div>
          </div>

          <div class="card">
            <div class="card-head"><span class="muted">Branch</span></div>
            <div class="kpi-big">$(EscHtml $branchLabel)</div>
            <div class="muted">Report date <span class="pill">$analysisDate</span></div>
          </div>

          <div class="card">
            <div class="card-head"><span class="muted">Quality Gate</span></div>
            <div class="kpi-big">$qgText</div>
            <div class="muted">Status reflecting Quality Gate conditions</div>
          </div>
        </div>

        <div class="grid-3" style="margin-top:16px">
          <div class="card">
            <div class="card-head"><span class="muted">Reliability</span><span class="grade g$relR">$relR</span></div>
            <div class="kpi-big">$(FmtNum $bugs)</div>
            <div class="muted">Bugs</div>
          </div>

          <div class="card">
            <div class="card-head"><span class="muted">Security</span><span class="grade g$secR">$secR</span></div>
            <div class="kpi-big">$(FmtNum $vulns)</div>
            <div class="muted">Vulnerabilities</div>
            <div class="muted" style="margin-top:8px">Security Hotspots</div>
            <div>$(FmtNum $hot)</div>
          </div>

          <div class="card">
            <div class="card-head"><span class="muted">Maintainability</span><span class="grade g$mntR">$mntR</span></div>
            <div class="kpi-big">$(FmtNum $smells)</div>
            <div class="muted">Code Smells</div>
            <div class="muted" style="margin-top:8px">Debt Ratio</div>
            <div>$(FmtNum $debt)%</div>
          </div>
        </div>

        <div class="grid-3" style="margin-top:16px">
          <div class="card">
            <h3>Issues by Severity</h3>
            <table style="margin-top:8px">
              <thead><tr><th>Severity</th><th>Bug</th><th>Vulnerability</th><th>Code Smell</th></tr></thead>
              <tbody>$sevRows</tbody>
            </table>
            <div class="footer-note">* Counts follow active filters (branch/status).</div>
          </div>

          <div class="card">
            <h3>Coverage</h3>
            <div style="display:flex;align-items:center;margin-top:8px">$donutCoverage <div class="kpi-big" style="margin:0 0 0 4px">$(FmtNum $cvg)%</div></div>
            <div class="muted">Coverage</div>
            $([string]$coverageMeter)
            <div class="muted" style="margin-top:10px">Unit Tests</div>
            <div>$(FmtNum $tests)</div>
          </div>

          <div class="card">
            <h3>Duplications</h3>
            <div style="display:flex;align-items:center;margin-top:8px">$donutDup <div class="kpi-big" style="margin:0 0 0 4px">$(FmtNum $dupPct)%</div></div>
            <div class="muted">Duplications</div>
            $([string]$dupMeter)
            <div class="muted" style="margin-top:10px">Duplicated Blocks</div>
            <div>$(FmtNum $dupBlk)</div>
          </div>
        </div>
      </div>
    </div>

    $qualHtml

    <!-- Page 3: Issues Breakdown -->
    <div class="doc-page">
      <div class="doc-head">
        <div class="brand">sonarcloud</div>
        <div class="doc-title">Issues Breakdown <span class="doc-sub">Analysis Date $analysisDate</span></div>
        <div class="muted">Branch $(EscHtml $branchLabel)</div>
      </div>
      <div class="doc-body">
        <div class="card">
          <h3>Top Common Issues</h3>
          <table style="margin-top:8px">
            <thead><tr><th>Rule</th><th>Type</th><th># Issues</th></tr></thead>
            <tbody>$rulesRows</tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Appendix pages -->
    $(FacetTable "OWASP Top 10 2021 (Vulnerabilities)" $owasp21 "owaspTop10-2021")
    $(FacetTable "OWASP Top 10 2017 (Vulnerabilities)" $owasp17 "owaspTop10-2017")
    $docCwe
    $docAsvs

  </div>
</body>
</html>
"@

# Write UTF-8 with BOM
$utf8Bom = New-Object System.Text.UTF8Encoding($true)
[System.IO.File]::WriteAllText($OutFile, $html, $utf8Bom)
Write-Host ">> Report generated: $OutFile"

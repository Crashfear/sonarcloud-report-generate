# SonarCloud Executive Report (HTML)

Generate a polished **Executive Report** from SonarCloud for any project/branch, including:

- Quality Gate banner (PASSED/FAILED)
- A/B/C/D/E grade bubbles for **Security**, **Reliability**, **Maintainability**
- Project KPIs (bugs, vulnerabilities, code smells, hotspots, debt ratio)
- **Coverage** and **Duplications** with ring visuals
- **Issues by Severity** matrix
- “Overall Code / Quality Overview” panel
- Annex pages (OWASP Top 10 2021/2017, **CWE Top 25**, **OWASP ASVS 4.0.3** reference)

The output is a single, dark-themed `HTML` file you can email or publish.

---

## Requirements

- **PowerShell 7+** (Windows, macOS, or Linux)
- A **SonarCloud Personal Access Token (PAT)** with permission to read the project  
  Create one in SonarCloud → *My Account* → *Security*.

---

## Quick start

```powershell
# Run from the repo root
.\Export-SonarCloudSecurityReport.ps1 `
  -ProjectKey "your_org_your_project" `
  -Organization "your_org" `
  -Token $env:SONARCLOUD_TOKEN `
  -Branch "master" `
  -OutFile "SonarCloud-Executive-Report.html"
```

> Tip: set your token once per session  
> ` $env:SONARCLOUD_TOKEN = "xxxxx..." `

Open the generated **`SonarCloud-Executive-Report.html`** in your browser.

---

## Parameters

| Name              | Type     | Required | Description                                                                                     |
|-------------------|----------|----------|-------------------------------------------------------------------------------------------------|
| `ProjectKey`      | string   | ✅       | SonarCloud *project key* (e.g. `myorg_myproject`).                                              |
| `Organization`    | string   | ✅       | SonarCloud *organization key*.                                                                  |
| `Token`           | string   | ✅       | SonarCloud **Personal Access Token**.                                                           |
| `OutFile`         | string   | ❌       | Output HTML file name (default: `SonarCloud-Executive-Report.html`).                            |
| `Branch`          | string   | ❌       | Branch filter (e.g. `main` or `master`).                                                        |
| `IncludeResolved` | switch   | ❌       | When present, includes resolved issues in the query (by default, only open ones are counted).   |

---

## What the script calls (SonarCloud API)

- `/api/measures/component` – bugs, vulnerabilities, smells, ratings, coverage, duplicates, LOC
- `/api/qualitygates/project_status` – **Quality Gate** status
- `/api/project_analyses/search` – latest analysis date
- `/api/issues/search` – issues (for severity matrix, facets, accepted issues totals)
- `/api/rules/show` – rule names for “Top Common Issues”

> The script gracefully skips facets not supported by your org and continues.

---

## Output details

**Page 1 – Executive Report**
- Project Size / Branch / **Quality Gate badge**
- Three KPI cards (Reliability, Security, Maintainability) with **grade bubbles**
- Issues by Severity table
- Coverage + Duplications (ring visuals + meters)

**Page 2 – Overall Code / Quality Overview**
- Security, Reliability, Maintainability (open issues)
- Accepted Issues, Coverage, Duplications

**Page 3 – Issues Breakdown**
- Top rules causing issues across BUG / VULNERABILITY / CODE_SMELL

**Annexes**
- OWASP Top 10 (2021 / 2017) – category breakdown
- **CWE Top 25** in your codebase
- **OWASP ASVS 4.0.3** reference structure (visual aid)

---

## Examples

**Basic**
```powershell
.\Export-SonarCloudSecurityReport.ps1 -ProjectKey acme_web -Organization acme -Token $env:SONARCLOUD_TOKEN
```

**Specific branch**
```powershell
.\Export-SonarCloudSecurityReport.ps1 -ProjectKey acme_web -Organization acme -Token $env:SONARCLOUD_TOKEN -Branch main
```

**Include resolved issues**
```powershell
.\Export-SonarCloudSecurityReport.ps1 -ProjectKey acme_web -Organization acme -Token $env:SONARCLOUD_TOKEN -IncludeResolved
```

**Custom output filename**
```powershell
.\Export-SonarCloudSecurityReport.ps1 -ProjectKey acme_web -Organization acme -Token $env:SONARCLOUD_TOKEN -OutFile .\distcme-report.html
```

---

## Automate with GitHub Actions

This repo includes a workflow that runs the script on a schedule and uploads the HTML as an artifact.  
Set a secret named **`SONARCLOUD_TOKEN`** in your repository settings.

See [`examples/workflows/generate-report.yml`](examples/workflows/generate-report.yml).

---

## Troubleshooting

- **401/403 Unauthorized**  
  Ensure the token is valid and has access to the org/project.

- **Wrong org or project key**  
  The API returns empty metrics. Double-check `-Organization` and `-ProjectKey`.

- **Facet not supported**  
  You may see a yellow console message; the report still generates.

- **Coverage is 0%**  
  Only reported coverage will display. Make sure your CI publishes coverage to SonarCloud.

---

## Security

- The token is only used to perform **read** calls to SonarCloud.  
- Prefer passing it via environment variable or CI secret.

---

## Contributing

PRs are welcome! Please include a clear description and screenshots of the resulting HTML.

---

## License

[MIT](LICENSE)

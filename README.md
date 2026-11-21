# Microsoft Defender XDR Incident Analysis Tool

A PowerShell script that retrieves and analyzes Microsoft Defender XDR incidents, extracting recommended actions, alert types, and MITRE ATT&CK techniques for export to CSV format.

## Features

- **Automated Incident Retrieval**: Fetches incidents created in the last 30 days via the Microsoft Graph API (v1.0)
- **Recommended Actions Extraction**: Collects the unique `recommendedActions` text from each incident's alerts
- **MITRE ATT&CK Mapping**: Extracts associated MITRE ATT&CK techniques
- **Alert Type Listing**: Collects the unique alert titles in each incident
- **CSV Export**: Timestamped CSV output for further analysis and reporting
- **Summary Statistics**: Displays counts by severity, status, and classification, plus recommended-action and MITRE ATT&CK coverage

## Prerequisites

- **PowerShell 7.0+**: Required for modern PowerShell features
- **Microsoft Graph PowerShell SDK**: Install via `Install-Module Microsoft.Graph` (the script only uses cmdlets from the `Microsoft.Graph.Authentication` module)
- **Microsoft Entra ID permission**: delegated `SecurityIncident.Read.All` scope required

## Installation

1. Clone this repository:
```bash
git clone https://github.com/trymhaak/Alert-Product-Mapping-XDR.git
cd Alert-Product-Mapping-XDR
```

2. Install Microsoft Graph PowerShell SDK (if not already installed):
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

## Usage

Run the script using PowerShell 7+:

```powershell
pwsh extract-recommended-actions.ps1
```

The script will:
1. Prompt for Microsoft Graph authentication
2. Retrieve incidents created in the last 30 days (50 per page, following `@odata.nextLink`)
3. Process and analyze incident data
4. Export results to `IncidentCatalog_WithActions_YYYYMMDD_HHmmss.csv` in the current working directory
5. Display summary statistics
6. Disconnect from Microsoft Graph

The script takes no parameters; the 30-day window and page size are set in the script.

## Output

The generated CSV file includes:

| Column | Description |
|--------|-------------|
| `IncidentId` | Unique incident identifier |
| `TenantId` | Microsoft Entra tenant ID of the incident |
| `DisplayName` | Incident name/title |
| `Severity` | Severity as returned by the API (for example `informational`, `low`, `medium`, `high`) |
| `Status` | Status as returned by the API (for example `active`, `inProgress`, `resolved`) |
| `Classification` | Incident classification |
| `Determination` | Incident determination |
| `CreatedDateTime` | When the incident was created |
| `LastUpdateDateTime` | When the incident was last updated |
| `AlertCount` | Number of alerts in the incident |
| `AlertTypes` | Unique alert titles, separated by ` \| ` |
| `MitreTechniques` | Unique MITRE ATT&CK technique IDs, separated by `, ` |
| `MitreTechniqueCount` | Number of unique MITRE ATT&CK techniques |
| `HasRecommendedActions` | `True` if at least one alert has recommended actions |
| `RecommendedActionsCount` | Number of unique recommended-action texts |
| `RecommendedActions` | Unique recommended-action texts, separated by `===NEXT ACTION SET===` |
| `IncidentUrl` | Link to the incident in the Microsoft Defender portal (`incidentWebUrl`) |

## Permissions

The script requires the following Microsoft Graph API permission:

- `SecurityIncident.Read.All` - Read security incidents and alerts

The script signs in interactively with delegated permissions (`Connect-MgGraph -Scopes "SecurityIncident.Read.All"`). Consent is requested on first sign-in; depending on tenant settings, an administrator may need to grant consent. App-only (client credential) authentication is not built in.

## Script Architecture

The script follows a structured execution flow:

1. **Authentication** - Connects to Microsoft Graph with required scopes
2. **Data Retrieval** - Paginated fetching of incidents with expanded alert details (`$expand=alerts`, `$filter=createdDateTime ge <30 days ago>`)
3. **Data Processing** - Extraction of recommended actions, MITRE techniques, and alert types
4. **Export** - CSV generation with UTF-8 encoding
5. **Reporting** - Console summary with coverage statistics

## API Documentation

This script uses validated Microsoft Graph API endpoints:

- [List Security Incidents](https://learn.microsoft.com/en-us/graph/api/security-list-incidents)
- [Security Incident Resource](https://learn.microsoft.com/en-us/graph/api/resources/security-incident)
- [Security Alert Resource](https://learn.microsoft.com/en-us/graph/api/resources/security-alert)

## License

MIT License - See [LICENSE](LICENSE) file for details

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## Maintainer

Maintained by Trym Håkansson.

- Security page: https://trym.cloud/security/
- GitHub: [@trymhaak](https://github.com/trymhaak)

To report a vulnerability, see [SECURITY.md](SECURITY.md).

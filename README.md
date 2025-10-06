# Microsoft Defender XDR Incident Analysis Tool

A PowerShell script that retrieves and analyzes Microsoft Defender XDR incidents, extracting recommended actions, alert types, and MITRE ATT&CK techniques for export to CSV format.

## Features

- **Automated Incident Retrieval**: Fetches incidents from the last 30 days via Microsoft Graph API
- **Recommended Actions Extraction**: Captures security recommendations for each incident
- **MITRE ATT&CK Mapping**: Extracts associated MITRE ATT&CK techniques
- **Alert Type Analysis**: Identifies and categorizes alert types across incidents
- **CSV Export**: Timestamped CSV output for further analysis and reporting
- **Comprehensive Statistics**: Displays summary metrics by severity, status, and classification

## Prerequisites

- **PowerShell 7.0+**: Required for modern PowerShell features
- **Microsoft Graph PowerShell SDK**: Install via `Install-Module Microsoft.Graph`
- **Azure AD Permissions**: `SecurityIncident.Read.All` scope required

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
2. Retrieve incidents from the last 30 days
3. Process and analyze incident data
4. Export results to `IncidentCatalog_WithActions_YYYYMMDD_HHmmss.csv`
5. Display summary statistics

## Output

The generated CSV file includes:

| Column | Description |
|--------|-------------|
| `IncidentId` | Unique incident identifier |
| `DisplayName` | Incident name/title |
| `Severity` | Severity level (Informational, Low, Medium, High) |
| `Status` | Current status (Active, Resolved, etc.) |
| `Classification` | Incident classification |
| `AlertCount` | Number of alerts in the incident |
| `AlertTypes` | Pipe-separated list of alert titles |
| `MitreTechniques` | Comma-separated MITRE ATT&CK technique IDs |
| `HasRecommendedActions` | Boolean indicating if actions are available |
| `RecommendedActions` | Detailed security recommendations |
| `IncidentUrl` | Direct link to incident in Microsoft 365 Defender portal |

## Permissions

The script requires the following Microsoft Graph API permission:

- `SecurityIncident.Read.All` - Read security incidents and alerts

Grant this permission through Azure AD app registration or interactive consent during first run.

## Script Architecture

The script follows a structured execution flow:

1. **Authentication** - Connects to Microsoft Graph with required scopes
2. **Data Retrieval** - Paginated fetching of incidents with expanded alert details
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

## Author

Created for security operations and incident response analysis workflows.

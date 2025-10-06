# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains a PowerShell script for analyzing Microsoft Defender XDR incidents. The script retrieves incidents from Microsoft Graph API, extracts recommended actions, alert types, and MITRE ATT&CK techniques, then exports the analysis to CSV format.

## Core Script: extract-recommended-actions.ps1

### Purpose
Complete incident analysis with recommended actions mapping for Microsoft Defender XDR incidents from the last 30 days.

### Key Requirements
- **PowerShell Version**: Requires PowerShell 7.0 or higher
- **Required Permission**: `SecurityIncident.Read.All` scope for Microsoft Graph API
- **Dependencies**: Microsoft Graph PowerShell SDK (uses `Connect-MgGraph` and `Invoke-MgGraphRequest`)

### Running the Script

```powershell
# Execute the main analysis script
pwsh extract-recommended-actions.ps1
```

The script will:
1. Connect to Microsoft Graph with `SecurityIncident.Read.All` permission
2. Fetch incidents from the last 30 days (paginated, 100 per page)
3. Process incidents and extract data from alerts
4. Export results to CSV: `IncidentCatalog_WithActions_YYYYMMDD_HHmmss.csv`
5. Display comprehensive summary statistics

### Script Architecture

**Step-by-step execution flow:**

1. **Authentication** (Lines 22-40)
   - Connects to Microsoft Graph using `Connect-MgGraph`
   - Only requests `SecurityIncident.Read.All` scope

2. **Data Retrieval** (Lines 42-85)
   - Fetches incidents using Graph API v1.0 endpoint: `/security/incidents`
   - Expands alerts with `$expand=alerts` query parameter
   - Filters by date: last 30 days using `$filter=createdDateTime ge <ISO8601>`
   - Handles pagination via `@odata.nextLink`
   - Includes throttling protection (100ms delay between pages)

3. **Data Processing** (Lines 87-167)
   - Extracts `recommendedActions` from alert objects (property name validated against MS Learn)
   - Extracts alert titles as alert types
   - Extracts MITRE ATT&CK techniques using `mitreTechniques` property (NOT `attackTechniques`)
   - Builds structured incident catalog with all relevant metadata

4. **Export** (Lines 169-184)
   - Exports to timestamped CSV file
   - Uses UTF-8 encoding

5. **Reporting** (Lines 186-241)
   - Displays summary statistics by severity, status, classification
   - Shows recommended actions coverage
   - Reports MITRE ATT&CK mapping coverage

### Key API Properties

When working with incident/alert data, use these validated property names:

**Incident properties:**
- `id`, `tenantId`, `displayName`, `severity`, `status`
- `classification`, `determination`
- `createdDateTime`, `lastUpdateDateTime`
- `alerts` (expanded collection)
- `incidentWebUrl`

**Alert properties:**
- `title` (alert type)
- `recommendedActions` (text field with actions)
- `mitreTechniques` (array of MITRE technique IDs - use this, NOT attackTechniques)

### CSV Output Structure

The exported CSV contains:
- `IncidentId`, `TenantId`, `DisplayName`
- `Severity`, `Status`, `Classification`, `Determination`
- `CreatedDateTime`, `LastUpdateDateTime`
- `AlertCount`, `AlertTypes` (pipe-separated)
- `MitreTechniques` (comma-separated), `MitreTechniqueCount`
- `HasRecommendedActions`, `RecommendedActionsCount`
- `RecommendedActions` (multi-line field with separator: `===NEXT ACTION SET===`)
- `IncidentUrl`

### Reference Documentation

All API properties and endpoints are validated against:
- https://learn.microsoft.com/en-us/graph/api/security-list-incidents
- https://learn.microsoft.com/en-us/graph/api/resources/security-incident
- https://learn.microsoft.com/en-us/graph/api/resources/security-alert

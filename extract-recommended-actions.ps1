<#
.SYNOPSIS
    Complete incident analysis with recommended actions mapping
    
.DESCRIPTION
    Retrieves all incidents from Microsoft Defender XDR and extracts recommended actions,
    alert types, and MITRE ATT&CK techniques. Validated against Microsoft Learn documentation.
    
.NOTES
    Version: 1.1
    Validated against: 
    - https://learn.microsoft.com/en-us/graph/api/security-list-incidents
    - https://learn.microsoft.com/en-us/graph/api/resources/security-incident
    - https://learn.microsoft.com/en-us/graph/api/resources/security-alert
    
    Required Permission: SecurityIncident.Read.All
#>

#Requires -Version 7.0

# ============================================================================
# STEP 1: Connect to Microsoft Graph
# ============================================================================

Write-Host "`n=== Microsoft Defender XDR Incident Analysis ===" -ForegroundColor Cyan
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Gray

try {
    # Only SecurityIncident.Read.All is needed for this operation
    # Reference: https://learn.microsoft.com/en-us/graph/api/security-list-incidents
    Connect-MgGraph -Scopes "SecurityIncident.Read.All" -NoWelcome -ErrorAction Stop
    
    $context = Get-MgContext
    Write-Host "Connected as: $($context.Account)" -ForegroundColor Green
    Write-Host "Tenant: $($context.TenantId)`n" -ForegroundColor Gray
}
catch {
    Write-Host "Failed to connect to Microsoft Graph: $_" -ForegroundColor Red
    exit 1
}

# ============================================================================
# STEP 2: Fetch Incidents from Graph API
# ============================================================================

Write-Host "Fetching incidents from last 30 days..." -ForegroundColor Cyan

$incidents = @()
$pageCount = 0

# Build the initial URI with proper date formatting
# Reference: https://learn.microsoft.com/en-us/graph/api/security-list-incidents
$startDate = (Get-Date).AddDays(-30).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$uri = "https://graph.microsoft.com/v1.0/security/incidents?`$top=50&`$expand=alerts&`$filter=createdDateTime ge $startDate"

try {
    do {
        $pageCount++
        Write-Host "  Fetching page $pageCount..." -ForegroundColor Gray
        
        # Make API request
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        
        # Add incidents from this page
        if ($response.value) {
            $incidents += $response.value
        }
        
        # Get next page URL (if exists)
        $uri = $response.'@odata.nextLink'
        
        # Small delay to avoid throttling
        if ($uri) {
            Start-Sleep -Milliseconds 100
        }
        
    } while ($uri)
    
    Write-Host "Successfully retrieved $($incidents.Count) incidents`n" -ForegroundColor Green
}
catch {
    Write-Host "Error fetching incidents: $_" -ForegroundColor Red
    Disconnect-MgGraph | Out-Null
    exit 1
}

# ============================================================================
# STEP 3: Process Incidents and Extract Data
# ============================================================================

Write-Host "Processing incidents and extracting recommended actions..." -ForegroundColor Cyan

$incidentCatalog = @()
$processedCount = 0

foreach ($incident in $incidents) {
    $processedCount++
    
    # Show progress every 10 incidents
    if ($processedCount % 10 -eq 0) {
        Write-Host "  Processed $processedCount of $($incidents.Count) incidents..." -ForegroundColor Gray
    }
    
    try {
        # Safely extract recommended actions from alerts
        # Property name verified: https://learn.microsoft.com/en-us/graph/api/resources/security-alert
        $allRecommendedActions = @()
        if ($incident.alerts) {
            $allRecommendedActions = $incident.alerts | 
                Where-Object { -not [string]::IsNullOrEmpty($_.recommendedActions) } |
                ForEach-Object { $_.recommendedActions } |
                Select-Object -Unique
        }
        
        # Extract alert types (titles)
        $alertTypes = @()
        if ($incident.alerts) {
            $alertTypes = $incident.alerts | 
                Where-Object { $_.title } |
                Select-Object -ExpandProperty title -Unique
        }
        
        # Extract MITRE ATT&CK techniques
        # Property name verified: mitreTechniques (NOT attackTechniques)
        # Reference: https://learn.microsoft.com/en-us/graph/api/resources/security-alert
        $mitreTechniques = @()
        if ($incident.alerts) {
            $mitreTechniques = $incident.alerts | 
                Where-Object { $_.mitreTechniques -and $_.mitreTechniques.Count -gt 0 } |
                ForEach-Object { $_.mitreTechniques } |
                ForEach-Object { $_ } |  # Flatten nested arrays
                Select-Object -Unique
        }
        
        # Build incident record
        # All property names verified against: https://learn.microsoft.com/en-us/graph/api/resources/security-incident
        $incidentCatalog += [PSCustomObject]@{
            IncidentId = $incident.id
            TenantId = $incident.tenantId
            DisplayName = $incident.displayName
            Severity = $incident.severity
            Status = $incident.status
            Classification = $incident.classification
            Determination = $incident.determination
            CreatedDateTime = $incident.createdDateTime
            LastUpdateDateTime = $incident.lastUpdateDateTime
            AlertCount = if ($incident.alerts) { $incident.alerts.Count } else { 0 }
            AlertTypes = if ($alertTypes) { ($alertTypes -join " | ") } else { "" }
            MitreTechniques = if ($mitreTechniques) { ($mitreTechniques -join ", ") } else { "" }
            MitreTechniqueCount = $mitreTechniques.Count
            HasRecommendedActions = ($allRecommendedActions.Count -gt 0)
            RecommendedActionsCount = $allRecommendedActions.Count
            RecommendedActions = if ($allRecommendedActions) { 
                ($allRecommendedActions -join "`n`n===NEXT ACTION SET===`n`n") 
            } else { 
                "" 
            }
            IncidentUrl = $incident.incidentWebUrl
        }
    }
    catch {
        Write-Host "  Warning: Error processing incident $($incident.id): $_" -ForegroundColor Yellow
        continue
    }
}

Write-Host "Completed processing $processedCount incidents`n" -ForegroundColor Green

# ============================================================================
# STEP 4: Export Results
# ============================================================================

Write-Host "Exporting results..." -ForegroundColor Cyan

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$exportPath = "IncidentCatalog_WithActions_$timestamp.csv"

try {
    $incidentCatalog | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
    Write-Host "Exported to: $exportPath" -ForegroundColor Green
}
catch {
    Write-Host "Error exporting CSV: $_" -ForegroundColor Red
}

# ============================================================================
# STEP 5: Display Summary
# ============================================================================

Write-Host "`n=== ANALYSIS SUMMARY ===" -ForegroundColor Yellow
Write-Host "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ""

Write-Host "Total Incidents Analyzed: " -NoNewline
Write-Host "$($incidentCatalog.Count)" -ForegroundColor White

Write-Host "Incidents with Recommended Actions: " -NoNewline
Write-Host "$(($incidentCatalog | Where-Object HasRecommendedActions).Count)" -ForegroundColor Green

Write-Host "Incidents without Recommended Actions: " -NoNewline
Write-Host "$(($incidentCatalog | Where-Object {-not $_.HasRecommendedActions}).Count)" -ForegroundColor Red

Write-Host ""
Write-Host "Breakdown by Severity:" -ForegroundColor Yellow
$incidentCatalog | 
    Group-Object Severity | 
    Select-Object @{N='Severity';E={$_.Name}}, Count | 
    Sort-Object Severity |
    Format-Table -AutoSize

Write-Host "Breakdown by Status:" -ForegroundColor Yellow
$incidentCatalog | 
    Group-Object Status | 
    Select-Object @{N='Status';E={$_.Name}}, Count | 
    Sort-Object Status |
    Format-Table -AutoSize

Write-Host "Breakdown by Classification:" -ForegroundColor Yellow
$incidentCatalog | 
    Where-Object { $_.Classification } |
    Group-Object Classification | 
    Select-Object @{N='Classification';E={$_.Name}}, Count | 
    Sort-Object Count -Descending |
    Format-Table -AutoSize

# Additional statistics
$totalAlerts = ($incidentCatalog | Measure-Object -Property AlertCount -Sum).Sum
$avgAlertsPerIncident = if ($incidentCatalog.Count -gt 0) { 
    [math]::Round($totalAlerts / $incidentCatalog.Count, 2) 
} else { 0 }

Write-Host "Total Alerts Across All Incidents: $totalAlerts" -ForegroundColor White
Write-Host "Average Alerts per Incident: $avgAlertsPerIncident" -ForegroundColor White

# MITRE Coverage
$incidentsWithMitre = ($incidentCatalog | Where-Object { $_.MitreTechniqueCount -gt 0 }).Count
Write-Host "`nIncidents with MITRE ATT&CK Mapping: $incidentsWithMitre" -ForegroundColor Cyan

Write-Host "`n=== Export Location ===" -ForegroundColor Yellow
Write-Host "$((Get-Location).Path)\$exportPath" -ForegroundColor White
Write-Host ""

# ============================================================================
# STEP 6: Disconnect
# ============================================================================

Disconnect-MgGraph | Out-Null
Write-Host "Disconnected from Microsoft Graph" -ForegroundColor Gray
Write-Host "`nScript completed successfully!`n" -ForegroundColor Green
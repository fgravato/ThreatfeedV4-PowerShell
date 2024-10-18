# Improved Threat Feed Management Script with Enhanced Menu

<#
.SYNOPSIS
    PowerShell script for managing threat feeds using the Lookout API.

.DESCRIPTION
    This script allows you to manage threat feeds using the Lookout API.
    It provides a user-friendly interface for creating, viewing, updating, and deleting threat feeds.

.NOTES
    File Name      : Improved_Threat_Feed_Management.ps1
    Author         : Frank Gravato (Lookout-SE) frank.gravato@lookout.com
    Prerequisite   : PowerShell 5.1 or later
    
.EXAMPLE
    .\Improved_Threat_Feed_Management.ps1
#>

# Configure logging
$LogFile = "ThreatFeedManagement.log"
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "$Timestamp - $Level - $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    Write-Host $LogMessage
}

# API endpoint URL
$script:BASE_URL = "https://api.lookout.com/mgmt/threat-feeds"

# File paths
$script:API_KEY_FILE = "api_key.txt"
$script:FEED_ID_FILE = "feed_id.txt"

# Headers for API requests
$script:HEADERS = @{
    "Content-Type" = "application/json"
    "Accept" = "application/json"
}

function Get-ApiKey {
    try {
        $apiKey = Get-Content -Path $API_KEY_FILE -ErrorAction Stop
        return $apiKey.Trim()
    }
    catch {
        Write-Log -Message "API key file '$API_KEY_FILE' not found." -Level "ERROR"
        return $null
    }
}

function Get-Bearer {
    param (
        [string]$ApiKey
    )
    Write-Log -Message "Validating API key"
    $tokenUrl = "https://api.lookout.com/oauth2/token"
    $headers = @{
        "Accept" = "application/json"
        "Authorization" = "Bearer $ApiKey"
        "Content-Type" = "application/x-www-form-urlencoded"
    }
    $body = @{
        "grant_type" = "client_credentials"
    }

    try {
        $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Headers $headers -Body $body
        if ($response.access_token) {
            Write-Log -Message "Access token retrieved successfully"
            return $response.access_token
        }
        else {
            Write-Log -Message "Access token not found in the response" -Level "ERROR"
            return $null
        }
    }
    catch {
        Write-Log -Message "Error occurred during token retrieval: $_" -Level "ERROR"
        return $null
    }
}

function Get-FeedGuids {
    param (
        [string]$AccessToken
    )
    $url = "$BASE_URL/api/v1/threat-feeds"
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Accept" = "application/json"
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
        Write-Log -Message "Retrieved $($response.Count) feed GUIDs"
        return $response
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $errorDetails = $_.ErrorDetails.Message
        Write-Log -Message "Error retrieving feed GUIDs: Status Code: $statusCode, Error: $errorDetails" -Level "ERROR"
        return $null
    }
}

function Get-FeedMetadata {
    param (
        [string]$FeedId,
        [string]$AccessToken
    )
    $url = "$BASE_URL/api/v1/threat-feeds/$FeedId"
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Accept" = "application/json"
    }

    try {
        $metadata = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
        Write-Log -Message "Retrieved metadata for feed $FeedId"
        return $metadata
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $errorDetails = $_.ErrorDetails.Message
        Write-Log -Message "Error retrieving feed metadata: Status Code: $statusCode, Error: $errorDetails" -Level "ERROR"
        return $null
    }
}

function Upload-ThreatDomains {
    param (
        [string]$FeedId,
        [string[]]$ThreatDomains,
        [string]$AccessToken,
        [string]$UploadType = "INCREMENTAL"
    )
    $url = "$BASE_URL/api/v1/threat-feeds/$FeedId/elements?uploadType=$UploadType"
    $boundary = [System.Guid]::NewGuid().ToString()
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type" = "multipart/form-data; boundary=$boundary"
    }

    try {
        $tempFile = [System.IO.Path]::GetTempFileName()
        Set-Content -Path $tempFile -Value "domain,action"
        foreach ($domain in $ThreatDomains) {
            $action, $domainName = $domain -split ','
            Add-Content -Path $tempFile -Value "$domainName,$action"
        }

        $fileBytes = [System.IO.File]::ReadAllBytes($tempFile)
        $fileEnc = [System.Text.Encoding]::GetEncoding('ISO-8859-1').GetString($fileBytes)

        $LF = "`r`n"
        $bodyLines = (
            "--$boundary",
            "Content-Disposition: form-data; name=`"file`"; filename=`"domains.csv`"",
            "Content-Type: text/csv$LF",
            $fileEnc,
            "--$boundary--$LF"
        ) -join $LF

        $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $bodyLines
        Write-Log -Message "Threat domains uploaded successfully."
        return $response
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $errorDetails = $_.ErrorDetails.Message
        Write-Log -Message "Error uploading threat domains: Status Code: $statusCode, Error: $errorDetails" -Level "ERROR"
        
        if ($statusCode -eq 404) {
            Write-Log -Message "404 Not Found error. Please check if the Feed ID is correct and you have the necessary permissions." -Level "ERROR"
        }
        elseif ($statusCode -eq 500) {
            Write-Log -Message "Server returned a 500 Internal Server Error. This might be a temporary issue. Retrying the operation is recommended." -Level "ERROR"
        }
        
        throw $_
    }
    finally {
        Remove-Item -Path $tempFile -ErrorAction SilentlyContinue
    }
}

function Get-ThreatDomains {
    param (
        [string]$FeedId,
        [string]$AccessToken
    )
    $url = "$BASE_URL/api/v1/threat-feeds/$FeedId/elements"
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Accept" = "text/csv"
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
        Write-Log -Message "Successfully retrieved threat domains for feed $FeedId"
        return $response -split "`n"
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $errorDetails = $_.ErrorDetails.Message
        Write-Log -Message "Error retrieving threat domains: Status Code: $statusCode, Error: $errorDetails" -Level "ERROR"
        return $null
    }
}

function Delete-ThreatFeed {
    param (
        [string]$FeedId,
        [string]$AccessToken
    )
    $url = "$BASE_URL/threat-feeds/$FeedId"
    $headers = $HEADERS.Clone()
    $headers["Authorization"] = "Bearer $AccessToken"

    try {
        Invoke-RestMethod -Uri $url -Method Delete -Headers $headers
        Write-Log -Message "Threat feed deleted successfully."
    }
    catch {
        Write-Log -Message "Error deleting threat feed: $_" -Level "ERROR"
    }
}

function Update-FeedContent {
    param (
        [string]$FeedId,
        [string]$SourceUrl,
        [string]$AccessToken
    )
    try {
        $response = Invoke-WebRequest -Uri $SourceUrl -UseBasicParsing
        $content = $response.Content

        $domainPattern = '\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        $domains = [regex]::Matches($content, $domainPattern) | ForEach-Object { $_.Value } | Sort-Object -Unique

        $threatDomains = $domains | ForEach-Object { "ADD,$_" }
        Upload-ThreatDomains -FeedId $FeedId -ThreatDomains $threatDomains -AccessToken $AccessToken

        Write-Log -Message "Feed content updated successfully."
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 404) {
            Write-Log -Message "Error: The source URL $SourceUrl is not found (404 error)." -Level "ERROR"
        }
        else {
            Write-Log -Message "Error downloading content from source URL: $_" -Level "ERROR"
        }
    }
}

function List-Feeds {
    param (
        [string]$AccessToken
    )
    $feedGuids = Get-FeedGuids -AccessToken $AccessToken
    if ($feedGuids) {
        Write-Host "`nExisting threat feeds:"
        foreach ($guid in $feedGuids) {
            $metadata = Get-FeedMetadata -FeedId $guid -AccessToken $AccessToken
            if ($metadata) {
                Write-Host "Feed ID: $guid"
                Write-Host "Title: $($metadata.title)"
                Write-Host "Elements Count: $($metadata.elementsCount)"
                Write-Host "---"
            }
            else {
                Write-Host "Feed ID: $guid (Unable to retrieve metadata)"
                Write-Host "---"
            }
        }
    }
    else {
        Write-Host "No existing threat feeds found."
    }
}

function View-FeedDetails {
    param (
        [string]$AccessToken
    )
    $feedId = Select-Feed -AccessToken $AccessToken
    if (-not $feedId) { return }

    while ($true) {
        $metadata = Get-FeedMetadata -FeedId $feedId -AccessToken $AccessToken
        if (-not $metadata) {
            Write-Host "Unable to retrieve feed metadata."
            return
        }

        Write-Host "`nFeed Details:"
        Write-Host "Feed ID: $feedId"
        Write-Host "Title: $($metadata.title)"
        Write-Host "Description: $($metadata.description)"
        Write-Host "Feed Type: $($metadata.feedType)"
        Write-Host "Elements Count: $($metadata.elementsCount)"
        Write-Host "Last Updated: $($metadata.elementsUploadedAt)"
        
        Write-Host "`nOptions:"
        Write-Host "1. View domains"
        Write-Host "2. Add domain"
        Write-Host "3. Remove domain"
        Write-Host "4. Return to previous menu"
        
        $choice = Read-Host "Enter your choice (1-4)"
        
        switch ($choice) {
            "1" { View-Domains -FeedId $feedId -AccessToken $AccessToken }
            "2" { Add-DomainToFeed -FeedId $feedId -AccessToken $AccessToken }
            "3" { Remove-DomainFromFeed -FeedId $feedId -AccessToken $AccessToken }
            "4" { break }
            default { Write-Host "Invalid choice. Please try again." }
        }
        if ($choice -eq "4") { break }
    }
}

function View-Domains {
    param (
        [string]$FeedId,
        [string]$AccessToken
    )
    $domains = Get-ThreatDomains -FeedId $FeedId -AccessToken $AccessToken
    if (-not $domains) {
        Write-Host "No domains found in this feed."
        return
    }

    $pageSize = 20
    $currentPage = 0
    $totalPages = [math]::Ceiling($domains.Count / $pageSize)

    while ($true) {
        $start = $currentPage * $pageSize
        $end = [math]::Min($start + $pageSize, $domains.Count)
        Write-Host "`nThreat domains:"
        for ($i = $start; $i -lt $end; $i++) {
            Write-Host "$($i+1). $($domains[$i])"
        }
        
        Write-Host "`nShowing $($start+1)-$end of $($domains.Count) domains."
        $choice = Read-Host "Enter 'n' for next page, 'p' for previous page, or 'q' to quit"
        switch ($choice.ToLower()) {
            "n" { if ($currentPage -lt $totalPages - 1) { $currentPage++ } }
            "p" { if ($currentPage -gt 0) { $currentPage-- } }
            "q" { return }
            default { Write-Host "Invalid choice or no more pages." }
        }
    }
}

function Select-Feed {
    param (
        [string]$AccessToken
    )
    $feedGuids = Get-FeedGuids -AccessToken $AccessToken
    if (-not $feedGuids) {
        Write-Host "No existing threat feeds found."
        return $null
    }

    Write-Host "`nSelect a feed:"
    $feedList = @{}
    foreach ($guid in $feedGuids) {
        $metadata = Get-FeedMetadata -FeedId $guid -AccessToken $AccessToken
        if ($metadata) {
            $feedList[$guid] = $metadata.title
            Write-Host "$guid. $($metadata.title)"
        }
    }

    while ($true) {
        $choice = Read-Host "Enter the UUID of the feed"
        if ($feedList.ContainsKey($choice)) {
            return $choice
        }
        else {
            Write-Host "Invalid UUID. Please try again."
        }
    }
}

function Add-DomainToFeed {
    param (
        [string]$FeedId,
        [string]$AccessToken
    )
    $domain = Read-Host "Enter the domain to add"
    $action = Read-Host "Enter the action (ADD or DELETE)"
    if ($action -notin @("ADD", "DELETE")) {
        Write-Host "Invalid action. Please use ADD or DELETE."
        return
    }

    Upload-ThreatDomains -FeedId $FeedId -ThreatDomains @("$action,$domain") -AccessToken $AccessToken
    Write-Host "Domain '$domain' has been $($action.ToLower())ed to the feed."
}

function Remove-DomainFromFeed {
    param (
        [string]$FeedId,
        [string]$AccessToken
    )
    $domain = Read-Host "Enter the domain to remove"
    try {
        $response = Upload-ThreatDomains -FeedId $FeedId -ThreatDomains @("delete,$domain") -AccessToken $AccessToken
        Write-Host "Domain '$domain' has been successfully removed from the feed."
        if ($response) {
            Write-Host "Server response: $($response | ConvertTo-Json -Depth 5)"
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-Log -Message "Error removing domain from feed: Status Code: $statusCode, Error: $errorMessage" -Level "ERROR"
        
        Write-Host "Failed to remove domain '$domain' from the feed. Error details: $errorMessage"
        Write-Host "Please try again later or contact Lookout support if the problem persists."
        
        if ($statusCode -eq 500) {
            Write-Host "This appears to be a server-side issue. Retrying the operation after a short delay might resolve it."
        }
    }
}

function Create-ThreatFeed {
    param (
        [string]$FeedType,
        [string]$Title,
        [string]$Description,
        [string]$AccessToken
    )

    if ($FeedType -notin @("CSV")) {
        Write-Log -Message "Invalid feed type. Allowed value: CSV" -Level "ERROR"
        return $null
    }
    if ($Title.Length -lt 8 -or $Title.Length -gt 255) {
        Write-Log -Message "Title must be between 8 and 255 characters." -Level "ERROR"
        return $null
    }
    if ($Description.Length -lt 8 -or $Description.Length -gt 255) {
        Write-Log -Message "Description must be between 8 and 255 characters." -Level "ERROR"
        return $null
    }

    $url = "$BASE_URL/api/v1/threat-feeds"
    $payload = @{
        feedType = $FeedType
        title = $Title
        description = $Description
    }
    $headers = $HEADERS.Clone()
    $headers["Authorization"] = "Bearer $AccessToken"

    try {
        $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body ($payload | ConvertTo-Json)
        $feedId = $response.feedId
        Set-Content -Path $FEED_ID_FILE -Value $feedId
        Write-Log -Message "Threat feed created with ID: $feedId"
        return $feedId
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $errorMessage = $_.ErrorDetails.Message | ConvertFrom-Json
        if ($statusCode -eq 400 -and $errorMessage.detail -match "Tenant reached the max allowed feed limit") {
            Write-Log -Message "Tenant has reached the maximum allowed feed limit." -Level "ERROR"
        }
        else {
            Write-Log -Message "Error creating threat feed: $statusCode - $($errorMessage.detail)" -Level "ERROR"
        }
        return $null
    }
}

function Display-MainMenu {
    Write-Host "`n=== Threat Feed Management System ==="
    Write-Host "1. View and Manage Existing Feeds"
    Write-Host "2. Create a New Threat Feed"
    Write-Host "3. Exit"
}

function Display-FeedMenu {
    Write-Host "`n--- Feed Management Menu ---"
    Write-Host "1. List All Feeds"
    Write-Host "2. View Feed Details"
    Write-Host "3. Update Feed Content"
    Write-Host "4. Delete Feed"
    Write-Host "5. Return to Main Menu"
}

# Main script execution
$ApiKey = Get-ApiKey
if ($null -eq $ApiKey) {
    Write-Log -Message "Please provide a valid API key in the 'api_key.txt' file." -Level "ERROR"
    exit
}

$AccessToken = Get-Bearer -ApiKey $ApiKey
if ($null -eq $AccessToken) {
    Write-Log -Message "Failed to retrieve access token. Please check your API key." -Level "ERROR"
    exit
}

# Test API connection
try {
    $feedGuids = Get-FeedGuids -AccessToken $AccessToken
    if ($null -ne $feedGuids) {
        Write-Host "API connection successful. Retrieved $(($feedGuids | Measure-Object).Count) feed GUIDs."
    } else {
        Write-Host "API connection successful, but no feeds were found."
    }
} catch {
    Write-Log -Message "Failed to connect to the API. Error: $_" -Level "ERROR"
    exit
}

Write-Host "PowerShell Threat Feed Management System initialized."

while ($true) {
    Display-MainMenu
    $choice = Read-Host "Enter your choice (1-3)"

    switch ($choice) {
        "1" {
            while ($true) {
                Display-FeedMenu
                $feedChoice = Read-Host "Enter your choice (1-5)"
                switch ($feedChoice) {
                    "1" { List-Feeds -AccessToken $AccessToken }
                    "2" { View-FeedDetails -AccessToken $AccessToken }
                    "3" {
                        $feedId = Select-Feed -AccessToken $AccessToken
                        if ($feedId) {
                            $sourceUrl = Read-Host "Enter the source URL for updating feed content"
                            Update-FeedContent -FeedId $feedId -SourceUrl $sourceUrl -AccessToken $AccessToken
                        }
                    }
                    "4" {
                        $feedId = Select-Feed -AccessToken $AccessToken
                        if ($feedId) {
                            $confirm = Read-Host "Are you sure you want to delete the feed with ID $feedId? (y/n)"
                            if ($confirm -eq 'y') {
                                Delete-ThreatFeed -FeedId $feedId -AccessToken $AccessToken
                            }
                        }
                    }
                    "5" { break }
                    default { Write-Host "Invalid choice. Please try again." }
                }
                if ($feedChoice -eq "5") { break }
            }
        }
        "2" {
            $feedType = Read-Host "Enter the feed type (e.g., CSV)"
            $title = Read-Host "Enter the feed title"
            $description = Read-Host "Enter the feed description"
            $feedId = Create-ThreatFeed -FeedType $feedType -Title $title -Description $description -AccessToken $AccessToken
            if ($feedId) {
                Write-Host "New threat feed created successfully!"
                Write-Host "Feed ID: $feedId"
            }
        }
        "3" {
            Write-Host "Thank you for using the Threat Feed Management System. Goodbye!"
            exit
        }
        default {
            Write-Host "Invalid choice. Please try again."
        }
    }
}
function Test-ApiConnection {
    param (
        [string]$AccessToken
    )
    $url = "$BASE_URL/api/v1/threat-feeds"
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Accept" = "application/json"
    }
    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
        Write-Host "API connection test successful. Response: $($response | ConvertTo-Json -Depth 5)"
    }
    catch {
        Write-Host "Error making API request: $_"
    }
}

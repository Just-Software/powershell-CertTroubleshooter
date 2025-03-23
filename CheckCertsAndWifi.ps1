<#
.SYNOPSIS
    Checks certificates with private keys and network profiles (WiFi and wired) using certificates.

.DESCRIPTION
    This script examines certificates in both user and computer stores that have
    private keys and validates their status. It also checks WiFi and wired (LAN) 
    network profiles on the machine that are using certificates and validates 
    their configuration.

    Note: Some operations require administrative privileges, especially when accessing
    LocalMachine certificate stores or certain private keys. Run as administrator for
    full functionality.

.PARAMETER RootCASubject
    Optional parameter to filter certificates by a specific Root CA subject name.

.PARAMETER DeleteExpiredCertificates
    If specified, prompts to delete expired certificates found during the scan.

.PARAMETER DeleteBrokenCertificates
    If specified, prompts to delete certificates with broken private keys found during the scan.

.PARAMETER SkipBanner
    If specified, skips the promotional banner at startup.

.PARAMETER ShowAllRootCAs
    If specified, shows all Root CAs in the selection menu, including those issued before 2023.
    By default, only Root CAs issued in 2023 or later are shown.

.PARAMETER AllRootCAs
    If specified, skips prompting for Root CA selection and checks all certificates.
    This is useful for automated scripts or when you want to check all certificates without filtering.

.PARAMETER DebugMode
    If specified, outputs detailed debug information during script execution.

.PARAMETER VerboseDebug
    If specified, outputs extremely detailed debug information, including raw data dumps of certificates and WiFi profiles.

.EXAMPLE
    .\CheckCertsAndWifi.ps1
    Checks all certificates with private keys and network profiles (WiFi and wired).

.EXAMPLE
    .\CheckCertsAndWifi.ps1 -RootCASubject "CN=Contoso Root CA"
    Checks only certificates issued by the specified Root CA and related WiFi profiles.

.EXAMPLE
    .\CheckCertsAndWifi.ps1 -DeleteExpiredCertificates
    Checks all certificates and prompts to delete any expired certificates.

.EXAMPLE
    .\CheckCertsAndWifi.ps1 -DeleteBrokenCertificates
    Checks all certificates and prompts to delete any certificates with broken private keys.

.EXAMPLE
    .\CheckCertsAndWifi.ps1 -SkipBanner
    Runs the tool without displaying the promotional banner.

.EXAMPLE
    .\CheckCertsAndWifi.ps1 -ShowAllRootCAs
    Shows all Root CAs in the selection menu, including those issued before 2023.

.EXAMPLE
    .\CheckCertsAndWifi.ps1 -AllRootCAs
    Checks all certificates without prompting for Root CA selection.

.EXAMPLE
    .\CheckCertsAndWifi.ps1 -DebugMode
    Runs the tool with detailed debug information displayed.

.EXAMPLE
    .\CheckCertsAndWifi.ps1 -VerboseDebug
    Runs the tool with extremely detailed debug information for troubleshooting certificate matching issues.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$RootCASubject,
    
    [Parameter(Mandatory = $false)]
    [switch]$DeleteExpiredCertificates,
    
    [Parameter(Mandatory = $false)]
    [switch]$DeleteBrokenCertificates,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipBanner,
    
    [Parameter(Mandatory = $false)]
    [switch]$ShowAllRootCAs,
    
    [Parameter(Mandatory = $false)]
    [switch]$AllRootCAs
)

# Global variable to store all certificates with private keys
$Global:AllCertificatesWithPrivateKeys = @()

# Function to display promotional banner
function Show-PromotionalBanner {
    $bannerText = @"
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║   ███████╗ █████╗ ███████╗██╗   ██╗███████╗ ██████╗███████╗██████╗               ║
║   ██╔════╝██╔══██╗██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝██╔════╝██╔══██╗              ║
║   █████╗  ███████║███████╗ ╚████╔╝ ███████╗██║     █████╗  ██████╔╝              ║
║   ██╔══╝  ██╔══██║╚════██║  ╚██╔╝  ╚════██║██║     ██╔══╝  ██╔═══╝               ║
║   ███████╗██║  ██║███████║   ██║   ███████║╚██████╗███████╗██║                   ║
║   ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚══════╝╚═╝                   ║
║                                                                                  ║
║   Cloud PKI - Certificate Management Made Easy                                   ║
║   https://easyscep.com                                                           ║
║                                                                                  ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║   ███████╗ █████╗ ███████╗██╗   ██╗██████╗  █████╗ ██████╗ ██╗██╗   ██╗███████╗  ║
║   ██╔════╝██╔══██╗██╔════╝╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗██║██║   ██║██╔════╝  ║
║   █████╗  ███████║███████╗ ╚████╔╝ ██████╔╝███████║██║  ██║██║██║   ██║███████╗  ║
║   ██╔══╝  ██╔══██║╚════██║  ╚██╔╝  ██╔══██╗██╔══██║██║  ██║██║██║   ██║╚════██║  ║
║   ███████╗██║  ██║███████║   ██║   ██║  ██║██║  ██║██████╔╝██║╚██████╔╝███████║  ║
║   ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝ ╚═════╝ ╚══════╝  ║
║                                                                                  ║
║   EAP-TLS Authentication as a Service                                            ║
║   https://easyradius.com                                                         ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝

  Try our SaaS solutions for enterprise certificate management and authentication!
  
  • EasyScep Cloud PKI - Issue and manage certificates with ease
    Native integration with Microsoft Intune and any SCEP compatible MDM
  • EasyRadius EAP-TLS - Secure WiFi authentication without the hassle
  
  For more information, visit https://just-software.com
"@

    # Display the banner with a cyan color
    Write-Host $bannerText -ForegroundColor Cyan
    
    # Wait for 5 seconds
    Start-Sleep -Seconds 5
    
    # Clear the console to continue with the script
    Clear-Host
} # End of try block

# Function to get all unique Root CA certificates from stores
function Get-UniqueRootCAs {
    param (
        [Parameter(Mandatory = $false)]
        [switch]$ShowAllRootCAs
    )
    
    $rootCAs = @()
    $stores = @(
        @{Name = "Root"; Location = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser },
        @{Name = "Root"; Location = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine },
        @{Name = "CA"; Location = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser },
        @{Name = "CA"; Location = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine }
    )
    
    # Define cutoff date for filtering (January 1, 2023)
    $cutoffDate = Get-Date -Year 2023 -Month 1 -Day 1
    
    foreach ($storeInfo in $stores) {
        try {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeInfo.Name, $storeInfo.Location)
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            
            foreach ($cert in $store.Certificates) {
                if ($cert.Subject -ne $null -and $cert.Subject -ne "") {
                    # Create a custom object with certificate details
                    $caInfo = [PSCustomObject]@{
                        Subject       = $cert.Subject
                        Thumbprint    = $cert.Thumbprint
                        Issuer        = $cert.Issuer
                        NotBefore     = $cert.NotBefore
                        NotAfter      = $cert.NotAfter
                        SerialNumber  = $cert.SerialNumber
                        Store         = "$($storeInfo.Location)\$($storeInfo.Name)"
                        HasPrivateKey = $cert.HasPrivateKey
                        IsSelfSigned  = ($cert.Subject -eq $cert.Issuer)
                        Certificate   = $cert
                    }
                    
                    # Skip certificates issued before 2023 unless ShowAllRootCAs is specified
                    if (-not $ShowAllRootCAs -and $cert.NotBefore -lt $cutoffDate) {
                        continue
                    }
                    
                    # Check if we already have this certificate by thumbprint
                    $exists = $false
                    foreach ($existingCA in $rootCAs) {
                        if ($existingCA.Thumbprint -eq $caInfo.Thumbprint) {
                            $exists = $true
                            break
                        }
                    }
                    
                    if (-not $exists) {
                        $rootCAs += $caInfo
                    }
                }
            }
            
            $store.Close()
        }
        catch {
            Write-Warning "Error accessing $($storeInfo.Location)\$($storeInfo.Name) store: $($_.Exception.Message)"
        }
    }
    
    # Sort by subject name
    return $rootCAs | Sort-Object -Property Subject
}

# Function to check if a Root CA is installed
function Test-RootCAInstalled {
    param (
        [Parameter(Mandatory = $false)]
        [string]$Subject,
        [Parameter(Mandatory = $false)]
        [string]$Thumbprint = ""
    )
    
    $rootCAs = Get-UniqueRootCAs
    
    # First try to match by thumbprint if provided
    if ($Thumbprint -ne "") {
        # Normalize thumbprint by removing spaces
        $normalizedThumbprint = $Thumbprint -replace '\s+', ''
        $matchingCA = $rootCAs | Where-Object { ($_.Thumbprint -replace '\s+', '') -eq $normalizedThumbprint }
        if ($matchingCA) {
            return $true
        }
        
        # If the input looks like a thumbprint but wasn't found in rootCAs,
        # check if it's in the certificate chain of any certificate
        if ($normalizedThumbprint -match '^[A-Fa-f0-9]{40}$') {
            # Check if this thumbprint exists in any certificate chain
            foreach ($cert in $Global:AllCertificatesWithPrivateKeys) {
                if ($cert.Chain) {
                    foreach ($chainCert in $cert.Chain) {
                        if (($chainCert.Thumbprint -replace '\s+', '') -eq $normalizedThumbprint) {
                            return $true
                        }
                    }
                }
            }
        }
    }
    
    # Then try to match by subject
    $matchingCA = $rootCAs | Where-Object { $_.Subject -eq $Subject }
    if ($matchingCA) {
        return $true
    }
    
    # If no exact match, try a more flexible match on the subject
    # Extract CN, O, and other components for more accurate matching
    $subjectComponents = @()
    if ($Subject -match "CN=([^,]+)") { $subjectComponents += $Matches[1].Trim() }
    if ($Subject -match "O=([^,]+)") { $subjectComponents += $Matches[1].Trim() }
    if ($Subject -match "C=([^,]+)") { $subjectComponents += $Matches[1].Trim() }
    
    foreach ($ca in $rootCAs) {
        # Check if all extracted components are in the CA subject
        $allComponentsMatch = $true
        foreach ($component in $subjectComponents) {
            if ($ca.Subject -notlike "*$component*") {
                $allComponentsMatch = $false
                break
            }
        }
        
        if ($allComponentsMatch -and $subjectComponents.Count -gt 0) {
            return $true
        }
        
        # Also try the traditional way as a fallback
        if ($ca.Subject -like "*$Subject*" -or $Subject -like "*$($ca.Subject)*") {
            return $true
        }
    }
    
    # Check if this subject exists in any certificate chain
    foreach ($cert in $Global:AllCertificatesWithPrivateKeys) {
        if ($cert.Chain) {
            foreach ($chainCert in $cert.Chain) {
                if ($chainCert.Subject -eq $Subject) {
                    return $true
                }
                
                # Also try component matching
                $allComponentsMatch = $true
                foreach ($component in $subjectComponents) {
                    if ($chainCert.Subject -notlike "*$component*") {
                        $allComponentsMatch = $false
                        break
                    }
                }
                
                if ($allComponentsMatch -and $subjectComponents.Count -gt 0) {
                    return $true
                }
            }
        }
    }
    
    return $false
}

# Function to get Root CA information
function Get-RootCAInfo {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Subject,
        [Parameter(Mandatory = $false)]
        [string]$Thumbprint = " "
    )
    
    $rootCAs = Get-UniqueRootCAs
    $caInfo = $null
    
    # First try to match by thumbprint if provided
    if ($Thumbprint -ne "") {
        # Normalize thumbprint by removing spaces
        $normalizedThumbprint = $Thumbprint -replace '\s+', ''
        $caInfo = $rootCAs | Where-Object { ($_.Thumbprint -replace '\s+', '') -eq $normalizedThumbprint } | Select-Object -First 1
    }
    
    # If not found by thumbprint, try exact subject match
    if (-not $caInfo) {
        $caInfo = $rootCAs | Where-Object { $_.Subject -eq $Subject } | Select-Object -First 1
    }
    
    # If still not found, try flexible subject match using components
    if (-not $caInfo) {
        # Extract CN, O, and other components for more accurate matching
        $subjectComponents = @()
        if ($Subject -match "CN=([^,]+)") { $subjectComponents += $Matches[1].Trim() }
        if ($Subject -match "O=([^,]+)") { $subjectComponents += $Matches[1].Trim() }
        if ($Subject -match "C=([^,]+)") { $subjectComponents += $Matches[1].Trim() }
        
        foreach ($ca in $rootCAs) {
            # Check if all extracted components are in the CA subject
            $allComponentsMatch = $true
            foreach ($component in $subjectComponents) {
                if ($ca.Subject -notlike "*$component*") {
                    $allComponentsMatch = $false
                    break
                }
            }
            
            if ($allComponentsMatch -and $subjectComponents.Count -gt 0) {
                $caInfo = $ca
                break
            }
        }
        
        # If still not found, try the traditional way as a fallback
        if (-not $caInfo) {
            $caInfo = $rootCAs | Where-Object { $_.Subject -like "*$Subject*" -or $Subject -like "*$($_.Subject)*" } | Select-Object -First 1
        }
    }
    
    return $caInfo
}

# Function to display menu and get user selection
function Show-RootCASelectionMenu {
    param (
        [Parameter(Mandatory = $false)]
        [switch]$ShowAllRootCAs
    )
    
    $rootCAs = Get-UniqueRootCAs -ShowAllRootCAs:$ShowAllRootCAs
    
    if ($rootCAs.Count -eq 0) {
        Write-Host "No Root CAs found in certificate stores." -ForegroundColor Yellow
        return $null
    }
    
    Write-Host "`n===== Available Root CAs =====" -ForegroundColor Cyan
    if ($ShowAllRootCAs) {
        Write-Host "Showing all Root CAs (including those issued before 2023)" -ForegroundColor Yellow
    } else {
        Write-Host "Showing only Root CAs issued in 2023 or later" -ForegroundColor Yellow
        Write-Host "Use -ShowAllRootCAs to show all Root CAs" -ForegroundColor Yellow
    }
    Write-Host "0: All Certificates (No filtering)" -ForegroundColor White
    
    # Display certificate details in a formatted table
    $format = "{0,-3} | {1,-50} | {2,-10} | {3,-25} | {4,-8}"
    Write-Host ($format -f "ID", "Subject", "Expires", "Store", "Self-Signed")
    Write-Host ("-" * 100)
    
    for ($i = 0; $i -lt $rootCAs.Count; $i++) {
        $ca = $rootCAs[$i]
        $expiryInfo = if ($ca.NotAfter -lt (Get-Date)) { 
            "EXPIRED" 
        }
        else { 
            $daysLeft = [math]::Round(($ca.NotAfter - (Get-Date)).TotalDays)
            "$daysLeft days" 
        }
        
        $subjectDisplay = if ($ca.Subject.Length -gt 47) {
            $ca.Subject.Substring(0, 44) + "..."
        }
        else {
            $ca.Subject
        }
        
        Write-Host ($format -f ($i + 1), $subjectDisplay, $expiryInfo, $ca.Store, $ca.IsSelfSigned) -ForegroundColor $(
            if ($ca.NotAfter -lt (Get-Date)) { "Red" } else { "White" }
        )
    }
    
    $selection = -1
    do {
        try {
            $input = Read-Host "`nSelect a Root CA (0-$($rootCAs.Count)) or 'D' followed by number for details"
            
            if ($input -match "^[Dd](\d+)$") {
                $detailIndex = [int]$Matches[1]
                if ($detailIndex -gt 0 -and $detailIndex -le $rootCAs.Count) {
                    $ca = $rootCAs[$detailIndex - 1]
                    Write-Host "`n===== Certificate Details =====" -ForegroundColor Cyan
                    Write-Host "Subject:       $($ca.Subject)" -ForegroundColor White
                    Write-Host "Issuer:        $($ca.Issuer)" -ForegroundColor White
                    Write-Host "Serial Number: $($ca.SerialNumber)" -ForegroundColor White
                    Write-Host "Thumbprint:    $($ca.Thumbprint)" -ForegroundColor White
                    Write-Host "Valid From:    $($ca.NotBefore)" -ForegroundColor White
                    Write-Host "Valid To:      $($ca.NotAfter)" -ForegroundColor White
                    Write-Host "Store:         $($ca.Store)" -ForegroundColor White
                    Write-Host "Has Private Key: $($ca.HasPrivateKey)" -ForegroundColor White
                    Write-Host "Self-Signed:   $($ca.IsSelfSigned)" -ForegroundColor White
                    
                    # Calculate days until expiry or days since expiry
                    $today = Get-Date
                    if ($ca.NotAfter -gt $today) {
                        $daysLeft = [math]::Round(($ca.NotAfter - $today).TotalDays)
                        Write-Host "Days until expiry: $daysLeft" -ForegroundColor $(if ($daysLeft -lt 30) { "Yellow" } else { "Green" })
                    }
                    else {
                        $daysExpired = [math]::Round(($today - $ca.NotAfter).TotalDays)
                        Write-Host "Days since expiry: $daysExpired" -ForegroundColor "Red"
                    }
                    
                    continue
                }
                else {
                    Write-Host "Invalid certificate number. Please enter a number between 1 and $($rootCAs.Count)." -ForegroundColor Red
                    continue
                }
            }
            
            $selection = [int]$input
            
            if ($selection -lt 0 -or $selection -gt $rootCAs.Count) {
                Write-Host "Invalid selection. Please enter a number between 0 and $($rootCAs.Count)." -ForegroundColor Red
                $selection = -1
            }
        }
        catch {
            Write-Host "Invalid input. Please enter a number or 'D' followed by a number for details." -ForegroundColor Red
            $selection = -1
        }
    } while ($selection -eq -1)
    
    if ($selection -eq 0) {
        return $null
    }
    else {
        return $rootCAs[$selection - 1].Subject
    }
}

# Function to test if private key is accessible and working
function Test-PrivateKeyFunctionality {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    
    if (-not $Certificate.HasPrivateKey) {
        return @{
            Success = $false
            Message = "Certificate does not have a private key"
            IsTPM   = $false
        }
    }
    
    try {
        # Get the provider information to check if it's TPM-based
        $keyProviderInfo = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        $isTPM = $false
        
        if ($keyProviderInfo -ne $null) {
            $keyProviderType = $keyProviderInfo.GetType().FullName
            $isTPM = $keyProviderType -match "CngKey" -and 
                    ($keyProviderInfo.Key.Provider.ToString() -match "TPM" -or 
            $keyProviderInfo.Key.Provider.ToString() -match "Microsoft Platform Crypto Provider")
        }
        
        # Try to perform a signature operation to verify the private key works
        $data = [System.Text.Encoding]::UTF8.GetBytes("Test data for signature verification")
        
        if ($keyProviderInfo -is [System.Security.Cryptography.RSA]) {
            # For RSA keys
            $signature = $keyProviderInfo.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $verified = $keyProviderInfo.VerifyData($data, $signature, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        }
        elseif ($keyProviderInfo -is [System.Security.Cryptography.DSA]) {
            # For DSA keys
            $signature = $keyProviderInfo.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA1)
            $verified = $keyProviderInfo.VerifyData($data, $signature, [System.Security.Cryptography.HashAlgorithmName]::SHA1)
        }
        elseif ($keyProviderInfo -is [System.Security.Cryptography.ECDsa]) {
            # For ECDSA keys
            $signature = $keyProviderInfo.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
            $verified = $keyProviderInfo.VerifyData($data, $signature, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        }
        else {
            return @{
                Success = $false
                Message = "Unsupported key type: $($keyProviderInfo.GetType().FullName)"
                IsTPM   = $isTPM
            }
        }
        
        if ($verified) {
            $locationInfo = if ($isTPM) { "TPM" } else { "software or hardware token" }
            return @{
                Success = $true
                Message = "Private key is accessible and functioning correctly (stored in $locationInfo)"
                IsTPM   = $isTPM
            }
        }
        else {
            return @{
                Success = $false
                Message = "Private key validation failed - signature verification error"
                IsTPM   = $isTPM
            }
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        $permissionRelated = $errorMsg -match "access|denied|permission|keyset does not exist"
        
        if ($permissionRelated -and -not (Test-Administrator)) {
            return @{
                Success         = $false
                Message         = "Error accessing private key: $errorMsg (This may be due to insufficient permissions - try running as Administrator)"
                IsTPM           = $isTPM
                Exception       = $_
                PermissionIssue = $true
            }
        }
        else {
            return @{
                Success         = $false
                Message         = "Error accessing private key: $errorMsg"
                IsTPM           = $isTPM
                Exception       = $_
                PermissionIssue = $false
            }
        }
    }
}

# Function to check if a certificate is valid
function Test-CertificateValidity {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $issues = @()
    
    # Check if certificate is expired
    if ($Certificate.NotAfter -lt (Get-Date)) {
        $issues += "Certificate is expired (Expired on: $($Certificate.NotAfter))"
    }
    
    # Check if certificate is not yet valid
    if ($Certificate.NotBefore -gt (Get-Date)) {
        $issues += "Certificate is not yet valid (Valid from: $($Certificate.NotBefore))"
    }
    
    # Check if certificate has been revoked (if CRL is available)
    try {
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
        
        if (-not $chain.Build($Certificate)) {
            foreach ($status in $chain.ChainStatus) {
                $issues += "Chain validation issue: $($status.StatusInformation.Trim())"
            }
        }
    }
    catch {
        $issues += "Unable to check revocation status: $($_.Exception.Message)"
    }
    finally {
        if ($chain) { $chain.Dispose() }
    }
    
    return $issues
}

# Function to get certificate chain information
function Get-CertificateChain {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
    $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
    
    $chainInfo = @()
    $rootCAThumbprint = $null
    
    try {
        $chain.Build($Certificate) | Out-Null
        
        foreach ($element in $chain.ChainElements) {
            $chainInfo += [PSCustomObject]@{
                Subject      = $element.Certificate.Subject
                Issuer       = $element.Certificate.Issuer
                NotBefore    = $element.Certificate.NotBefore
                NotAfter     = $element.Certificate.NotAfter
                SerialNumber = $element.Certificate.SerialNumber
                Thumbprint   = $element.Certificate.Thumbprint
                IsSelfSigned = ($element.Certificate.Subject -eq $element.Certificate.Issuer)
            }
            
            # If this is a self-signed certificate, it's likely a root CA
            if ($element.Certificate.Subject -eq $element.Certificate.Issuer) {
                $rootCAThumbprint = $element.Certificate.Thumbprint
            }
        }
        
        # If we have more than one element and no self-signed cert was found,
        # the last element in the chain is likely the root CA
        if ($rootCAThumbprint -eq $null -and $chain.ChainElements.Count -gt 0) {
            $lastElement = $chain.ChainElements[$chain.ChainElements.Count - 1]
            $rootCAThumbprint = $lastElement.Certificate.Thumbprint
        }
    }
    catch {
        Write-Warning "Error building certificate chain: $($_.Exception.Message)"
    }
    finally {
        if ($chain) { $chain.Dispose() }
    }
    
    return @{
        Chain            = $chainInfo
        RootCAThumbprint = $rootCAThumbprint
    }
}

# Function to check if certificate is issued by specified Root CA
function Test-IssuedByRootCA {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)]
        [string]$RootCASubject
    )
    
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $isIssuedByRootCA = $false
    
    try {
        $chain.Build($Certificate) | Out-Null
        
        # Check if any certificate in the chain matches the Root CA subject
        foreach ($element in $chain.ChainElements) {
            # First try exact match for the subject
            if ($element.Certificate.Subject -eq $RootCASubject) {
                $isIssuedByRootCA = $true
                break
            }
            
            # If no exact match, try more flexible matching
            # Extract CN, O, and other components for more accurate matching
            $subjectComponents = @()
            if ($RootCASubject -match "CN=([^,]+)") { $subjectComponents += $Matches[1].Trim() }
            if ($RootCASubject -match "O=([^,]+)") { $subjectComponents += $Matches[1].Trim() }
            if ($RootCASubject -match "C=([^,]+)") { $subjectComponents += $Matches[1].Trim() }
            
            # Check if all extracted components are in the certificate subject
            $allComponentsMatch = $true
            foreach ($component in $subjectComponents) {
                if ($element.Certificate.Subject -notlike "*$component*") {
                    $allComponentsMatch = $false
                    break
                }
            }
            
            if ($allComponentsMatch -and $subjectComponents.Count -gt 0) {
                $isIssuedByRootCA = $true
                break
            }
            
            # Also try the traditional way as a fallback
            if ($element.Certificate.Subject -like "*$RootCASubject*" -or $RootCASubject -like "*$($element.Certificate.Subject)*") {
                $isIssuedByRootCA = $true
                break
            }
        }
        
        # If still not found, check if the last element in the chain (root) contains the subject
        if (-not $isIssuedByRootCA -and $chain.ChainElements.Count -gt 0) {
            $lastElement = $chain.ChainElements[$chain.ChainElements.Count - 1]
            if ($lastElement.Certificate.Subject -like "*$RootCASubject*" -or $RootCASubject -like "*$($lastElement.Certificate.Subject)*") {
                $isIssuedByRootCA = $true
            }
        }
    }
    catch {
        Write-Warning "Error checking certificate chain for Root CA: $($_.Exception.Message)"
    }
    finally {
        if ($chain) { $chain.Dispose() }
    }
    
    return $isIssuedByRootCA
}

# Function to delete a certificate from a store
function Remove-CertificateFromStore {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)]
        [string]$StoreName,
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation,
        [Parameter(Mandatory = $true)]
        [string]$Reason
    )
    
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, $StoreLocation)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        
        Write-Host "`nCertificate to delete:" -ForegroundColor Yellow
        Write-Host "  Subject: $($Certificate.Subject)" -ForegroundColor White
        Write-Host "  Issuer: $($Certificate.Issuer)" -ForegroundColor White
        Write-Host "  Thumbprint: $($Certificate.Thumbprint)" -ForegroundColor White
        Write-Host "  Valid from: $($Certificate.NotBefore) to $($Certificate.NotAfter)" -ForegroundColor White
        Write-Host "  Store: $StoreLocation\$StoreName" -ForegroundColor White
        Write-Host "  Reason for deletion: $Reason" -ForegroundColor Red
        
        $confirmation = Read-Host "Are you sure you want to delete this certificate? (y/n)"
        if ($confirmation -eq 'y') {
            $store.Remove($Certificate)
            Write-Host "Certificate deleted successfully" -ForegroundColor Green
            return $true
        }
        else {
            Write-Host "Certificate deletion cancelled" -ForegroundColor Yellow
            return $false
        }
    }
    catch {
        Write-Host "Error deleting certificate: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
    finally {
        if ($store) { $store.Close() }
    }
}

# Function to check certificates in a store
function Check-CertificatesInStore {
    param (
        [Parameter(Mandatory = $true)]
        [string]$StoreName,
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation,
        [Parameter(Mandatory = $false)]
        [string]$RootCASubject,
        [Parameter(Mandatory = $false)]
        [switch]$DeleteExpiredCertificates,
        [Parameter(Mandatory = $false)]
        [switch]$DeleteBrokenCertificates
    )
    
    Write-Host "`n===== Checking certificates in $StoreLocation\$StoreName store =====" -ForegroundColor Cyan
    
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, $StoreLocation)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        
        $certsWithPrivateKey = $store.Certificates | Where-Object { $_.HasPrivateKey }
        
        if ($RootCASubject) {
            $filteredCerts = @()
            foreach ($cert in $certsWithPrivateKey) {
                if (Test-IssuedByRootCA -Certificate $cert -RootCASubject $RootCASubject) {
                    $filteredCerts += $cert
                }
            }
            $certsWithPrivateKey = $filteredCerts
        }
        
        if ($certsWithPrivateKey.Count -eq 0) {
            Write-Host "No certificates with private keys found in this store" -ForegroundColor Yellow
            if ($RootCASubject) {
                Write-Host "(filtered by Root CA: $RootCASubject)" -ForegroundColor Yellow
            }
            return
        }
        
        Write-Host "Found $($certsWithPrivateKey.Count) certificates with private keys" -ForegroundColor Green
        if ($RootCASubject) {
            Write-Host "(filtered by Root CA: $RootCASubject)" -ForegroundColor Green
        }
        
        foreach ($cert in $certsWithPrivateKey) {
            Write-Host "`nCertificate: $($cert.Subject)" -ForegroundColor White
            Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor White
            Write-Host "  Issuer: $($cert.Issuer)" -ForegroundColor White
            Write-Host "  Valid from: $($cert.NotBefore) to $($cert.NotAfter)" -ForegroundColor White
            Write-Host "  Has private key: $($cert.HasPrivateKey)" -ForegroundColor White
            
            # Check certificate validity
            $issues = Test-CertificateValidity -Certificate $cert
            $isExpired = $cert.NotAfter -lt (Get-Date)
            
            if ($issues.Count -gt 0) {
                Write-Host "  Issues found:" -ForegroundColor Red
                foreach ($issue in $issues) {
                    Write-Host "    - $issue" -ForegroundColor Red
                }
                
                # Handle expired certificate deletion if requested
                if ($DeleteExpiredCertificates -and $isExpired) {
                    $reason = "Certificate is expired (Expired on: $($cert.NotAfter))"
                    Remove-CertificateFromStore -Certificate $cert -StoreName $StoreName -StoreLocation $StoreLocation -Reason $reason
                }
            }
            else {
                Write-Host "  Status: Valid" -ForegroundColor Green
            }
            
            # Check private key functionality
            $privateKeyTest = Test-PrivateKeyFunctionality -Certificate $cert
            if ($privateKeyTest.Success) {
                Write-Host "  Private Key: $($privateKeyTest.Message)" -ForegroundColor Green
            }
            else {
                Write-Host "  Private Key Issue: $($privateKeyTest.Message)" -ForegroundColor Red
                if ($privateKeyTest.IsTPM) {
                    Write-Host "  TPM-related issue detected! The TPM may be cleared, faulty, or inaccessible." -ForegroundColor Red
                }
                if ($privateKeyTest.PermissionIssue) {
                    Write-Host "  This appears to be a permissions issue. Try running the script as Administrator." -ForegroundColor Yellow
                }
                
                # Handle broken certificate deletion if requested
                if ($DeleteBrokenCertificates -and -not $privateKeyTest.PermissionIssue) {
                    $reason = "Certificate has broken private key: $($privateKeyTest.Message)"
                    Remove-CertificateFromStore -Certificate $cert -StoreName $StoreName -StoreLocation $StoreLocation -Reason $reason
                }
            }
            
            # Get certificate chain information
            $chainResult = Get-CertificateChain -Certificate $cert
            $chainInfo = $chainResult.Chain
            $rootCAThumbprint = $chainResult.RootCAThumbprint
            
            Write-Host "  Certificate Chain:" -ForegroundColor White
            foreach ($chainCert in $chainInfo) {
                Write-Host "    - $($chainCert.Subject)" -ForegroundColor White
                Write-Host "      Thumbprint: $($chainCert.Thumbprint)" -ForegroundColor White
            }
            
            # Store certificate information in global variable
            $Global:AllCertificatesWithPrivateKeys += [PSCustomObject]@{
                Certificate      = $cert
                Subject          = $cert.Subject
                Issuer           = $cert.Issuer
                Thumbprint       = $cert.Thumbprint
                NotBefore        = $cert.NotBefore
                NotAfter         = $cert.NotAfter
                HasPrivateKey    = $cert.HasPrivateKey
                Store            = $StoreName
                StoreLocation    = $StoreLocation
                StoreType        = if ($StoreLocation -eq [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser) { "User" } else { "Machine" }
                PrivateKeyStatus = $privateKeyTest
                Chain            = $chainInfo
                RootCAThumbprint = $rootCAThumbprint
                Issues           = $issues
                IsExpired        = $isExpired
                IssuerHash       = ""  # Will be calculated when needed
            }
        }
    }
    catch {
        Write-Host "Error accessing $StoreLocation\$StoreName store: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        if ($store) { $store.Close() }
    }
}

# Function to get detailed WiFi interface information
function Get-WiFiInterfaceDetails {
    try {
        $interfaces = @()
        $wlanInterfaces = netsh wlan show interfaces | Select-String -Pattern "Name|SSID|State|Radio type|Authentication|Cipher|Connection mode|Channel|Receive rate|Transmit rate|Signal"
        
        $currentInterface = $null
        foreach ($line in $wlanInterfaces) {
            $lineText = $line.ToString().Trim()
            
            if ($lineText -match "^Name\s+:\s+(.+)$") {
                if ($currentInterface) {
                    $interfaces += $currentInterface
                }
                $currentInterface = @{
                    Name           = $Matches[1].Trim()
                    SSID           = ""
                    State          = ""
                    RadioType      = ""
                    Authentication = ""
                    Cipher         = ""
                    ConnectionMode = ""
                    Channel        = ""
                    ReceiveRate    = ""
                    TransmitRate   = ""
                    Signal         = ""
                }
            }
            elseif ($lineText -match "^SSID\s+:\s+(.+)$") {
                $currentInterface.SSID = $Matches[1].Trim()
            }
            elseif ($lineText -match "^State\s+:\s+(.+)$") {
                $currentInterface.State = $Matches[1].Trim()
            }
            elseif ($lineText -match "^Radio type\s+:\s+(.+)$") {
                $currentInterface.RadioType = $Matches[1].Trim()
            }
            elseif ($lineText -match "^Authentication\s+:\s+(.+)$") {
                $currentInterface.Authentication = $Matches[1].Trim()
            }
            elseif ($lineText -match "^Cipher\s+:\s+(.+)$") {
                $currentInterface.Cipher = $Matches[1].Trim()
            }
            elseif ($lineText -match "^Connection mode\s+:\s+(.+)$") {
                $currentInterface.ConnectionMode = $Matches[1].Trim()
            }
            elseif ($lineText -match "^Channel\s+:\s+(.+)$") {
                $currentInterface.Channel = $Matches[1].Trim()
            }
            elseif ($lineText -match "^Receive rate \(Mbps\)\s+:\s+(.+)$") {
                $currentInterface.ReceiveRate = $Matches[1].Trim()
            }
            elseif ($lineText -match "^Transmit rate \(Mbps\)\s+:\s+(.+)$") {
                $currentInterface.TransmitRate = $Matches[1].Trim()
            }
            elseif ($lineText -match "^Signal\s+:\s+(.+)$") {
                $currentInterface.Signal = $Matches[1].Trim()
            }
        }
        
        if ($currentInterface) {
            $interfaces += $currentInterface
        }
        
        return $interfaces
    }
    catch {
        $errorRecord = $_
        $lineNumber = $errorRecord.InvocationInfo.ScriptLineNumber
        Write-Warning "Error getting WiFi interface details: $($errorRecord.Exception.Message) at line $lineNumber"
        if ($DebugMode) {
            Write-Warning "Stack trace: $($errorRecord.ScriptStackTrace)"
        }
        return @()
    }
}

# Function to extract XML configuration from WiFi profile
function Get-WiFiProfileXML {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ProfileName
    )
    
    try {
        # Get temp folder and ensure it exists
        $tempFolder = [System.IO.Path]::GetTempPath().TrimEnd('\')
        if (-not (Test-Path -Path $tempFolder -PathType Container)) {
            New-Item -Path $tempFolder -ItemType Directory -Force | Out-Null
        }
        
        # Sanitize profile name for file path
        $safeProfileName = $ProfileName -replace '[\\\/\:\*\?\"\<\>\|]', '_'
        $xmlFilePath = Join-Path -Path $tempFolder -ChildPath "$safeProfileName.xml"
        
        # Export the profile
        $exportOutput = netsh wlan export profile name="$ProfileName" folder="$tempFolder" key=clear
        Write-Verbose "Export output: $exportOutput"
        
        # Check if file exists
        if (Test-Path $xmlFilePath) {
            $content = Get-Content -Path $xmlFilePath -Raw -ErrorAction Stop
            Remove-Item -Path $xmlFilePath -Force -ErrorAction SilentlyContinue
            return $content
        }
        else {
            # Try alternative filename (netsh sometimes modifies the filename)
            $alternativeFiles = Get-ChildItem -Path $tempFolder -Filter "*.xml" | Where-Object { $_.Name -like "*$safeProfileName*" }
            if ($alternativeFiles.Count -gt 0) {
                $alternativeFile = $alternativeFiles[0].FullName
                $content = Get-Content -Path $alternativeFile -Raw -ErrorAction Stop
                Remove-Item -Path $alternativeFile -Force -ErrorAction SilentlyContinue
                return $content
            }
            
            Write-Warning "Failed to export WiFi profile XML for '$ProfileName'. File not found at expected location."
            return $null
        }
    }
    catch {
        Write-Warning "Error exporting WiFi profile XML for '$ProfileName': $($_.Exception.Message)"
        return $null
    }
}

# Function to find matching certificates for network profiles
function Find-MatchingCertificates {
    param (
        [Parameter(Mandatory = $false)]
        [string]$Subject = "",
        [Parameter(Mandatory = $false)]
        [string]$Issuer = "",
        [Parameter(Mandatory = $false)]
        [string]$Thumbprint = "",
        [Parameter(Mandatory = $false)]
        [string]$RootCAThumbprint = "",
        [Parameter(Mandatory = $false)]
        [string]$IssuerHash = "",
        [Parameter(Mandatory = $false)]
        [switch]$TreatHashAsCAThumbprint = $false
    )
    
    # Normalize parameters by removing spaces
    $Thumbprint = $Thumbprint -replace '\s+', ''
    $RootCAThumbprint = $RootCAThumbprint -replace '\s+', ''
    $IssuerHash = $IssuerHash -replace '\s+', ''
    
    Write-Verbose "Find-MatchingCertificates called with parameters:"
    Write-Verbose "  Subject: '$Subject'"
    Write-Verbose "  Issuer: '$Issuer'"
    Write-Verbose "  Thumbprint: '$Thumbprint'"
    Write-Verbose "  RootCAThumbprint: '$RootCAThumbprint'"
    Write-Verbose "  IssuerHash: '$IssuerHash'"
    Write-Verbose "  TreatHashAsCAThumbprint: $TreatHashAsCAThumbprint"
    
    # First try to find matches in our global certificate collection
    if ($Global:AllCertificatesWithPrivateKeys.Count -gt 0) {
        Write-Debug "Searching in global certificate collection with $($Global:AllCertificatesWithPrivateKeys.Count) certificates"
        
        $matchingCerts = @()
        $filteredCerts = $Global:AllCertificatesWithPrivateKeys
        
        # Apply filters based on provided parameters
        if (-not [string]::IsNullOrEmpty($Subject)) {
            $filteredCerts = $filteredCerts | Where-Object { 
                $_.Subject -like "*$Subject*" -or 
                $_.Certificate.FriendlyName -like "*$Subject*"
            }
            Write-Debug "After Subject filter: $($filteredCerts.Count) certificates"
        }
        
        if (-not [string]::IsNullOrEmpty($Issuer)) {
            $filteredCerts = $filteredCerts | Where-Object { $_.Issuer -like "*$Issuer*" }
            Write-Debug "After Issuer filter: $($filteredCerts.Count) certificates"
        }
        
        if (-not [string]::IsNullOrEmpty($Thumbprint)) {
            $filteredCerts = $filteredCerts | Where-Object { $_.Thumbprint -eq $Thumbprint }
            Write-Debug "After Thumbprint filter: $($filteredCerts.Count) certificates"
        }
        
        if (-not [string]::IsNullOrEmpty($RootCAThumbprint)) {
            $filteredCerts = $filteredCerts | Where-Object { $_.RootCAThumbprint -eq $RootCAThumbprint }
            Write-Debug "After RootCAThumbprint filter: $($filteredCerts.Count) certificates"
        }
        
        if (-not [string]::IsNullOrEmpty($IssuerHash)) {
            $filteredCerts = $filteredCerts | Where-Object { 
                # Calculate issuer hash if not already stored
                if (-not $_.IssuerHash) {
                    try {
                        $issuerBytes = [System.Text.Encoding]::UTF8.GetBytes($_.Issuer)
                        $sha1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
                        $hashBytes = $sha1.ComputeHash($issuerBytes)
                        $_.IssuerHash = [System.BitConverter]::ToString($hashBytes).Replace("-", "")
                    }
                    catch {
                        $_.IssuerHash = ""
                    }
                }
                
                # Compare with the requested issuer hash (case-insensitive)
                return $_.IssuerHash -ieq $IssuerHash
            }
            Write-Debug "After IssuerHash filter: $($filteredCerts.Count) certificates"
        }
        
        foreach ($cert in $filteredCerts) {
            $matchingCerts += [PSCustomObject]@{
                Certificate = $cert.Certificate
                Store       = $cert.Store
                Location    = $cert.StoreLocation
                Type        = $cert.StoreType
            }
        }
        
        if ($matchingCerts.Count -gt 0) {
            Write-Debug "Found $($matchingCerts.Count) matching certificates in global collection"
            return $matchingCerts
        }
    }
    
    # If no matches found in global collection or collection is empty, fall back to direct store search
    Write-Debug "No matches found in global collection, falling back to direct store search"
    
    $matchingCerts = @()
    $stores = @(
        @{Name = "My"; Location = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser; Type = "User" },
        @{Name = "My"; Location = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine; Type = "Machine" }
    )
    
    foreach ($storeInfo in $stores) {
        try {
            Write-Debug "Searching in store: $($storeInfo.Location)\$($storeInfo.Name)"
            
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeInfo.Name, $storeInfo.Location)
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            
            $storeCerts = $store.Certificates | Where-Object { $_.HasPrivateKey }
            Write-Debug "Found $($storeCerts.Count) certificates with private keys in $($storeInfo.Location)\$($storeInfo.Name)"
            
            # Log all certificates for verbose debugging
            if ($VerboseDebug) {
                Write-Host "DEBUG: All certificates with private keys in $($storeInfo.Location)\$($storeInfo.Name):" -ForegroundColor Magenta
                foreach ($cert in $storeCerts) {
                    Write-Host "DEBUG:   Certificate: $($cert.Thumbprint)" -ForegroundColor Magenta
                    Write-Host "DEBUG:     Subject: $($cert.Subject)" -ForegroundColor Magenta
                    Write-Host "DEBUG:     Issuer: $($cert.Issuer)" -ForegroundColor Magenta
                    Write-Host "DEBUG:     FriendlyName: $($cert.FriendlyName)" -ForegroundColor Magenta
                }
            }
            
            # Apply filters based on provided parameters
            $originalCount = $storeCerts.Count
            
            if (-not [string]::IsNullOrEmpty($Subject)) {
                $storeCerts = $storeCerts | Where-Object { 
                    $_.Subject -like "*$Subject*" -or 
                    $_.FriendlyName -like "*$Subject*"
                }
                
                if ($DebugMode) {
                    Write-Host "DEBUG: After Subject filter: $($storeCerts.Count) certificates (from $originalCount)" -ForegroundColor Magenta
                    if ($storeCerts.Count -gt 0) {
                        Write-Host "DEBUG: Subject filter matches:" -ForegroundColor Magenta
                        foreach ($cert in $storeCerts) {
                            Write-Host "DEBUG:   - Subject: $($cert.Subject)" -ForegroundColor Magenta
                            Write-Host "DEBUG:     FriendlyName: $($cert.FriendlyName)" -ForegroundColor Magenta
                            Write-Host "DEBUG:     Thumbprint: $($cert.Thumbprint)" -ForegroundColor Magenta
                        }
                    }
                }
            }
            
            if (-not [string]::IsNullOrEmpty($Issuer)) {
                $preIssuerCount = $storeCerts.Count
                $storeCerts = $storeCerts | Where-Object { $_.Issuer -like "*$Issuer*" }
                
                if ($DebugMode) {
                    Write-Host "DEBUG: After Issuer filter: $($storeCerts.Count) certificates (from $preIssuerCount)" -ForegroundColor Magenta
                }
            }
            
            if (-not [string]::IsNullOrEmpty($Thumbprint)) {
                $preThumbprintCount = $storeCerts.Count
                $storeCerts = $storeCerts | Where-Object { $_.Thumbprint -eq $Thumbprint }
                
                if ($DebugMode) {
                    Write-Host "DEBUG: After Thumbprint filter: $($storeCerts.Count) certificates (from $preThumbprintCount)" -ForegroundColor Magenta
                }
            }
            
            if (-not [string]::IsNullOrEmpty($RootCAThumbprint)) {
                $preRootCACount = $storeCerts.Count
                $filteredByRootCA = @()
                
                foreach ($cert in $storeCerts) {
                    $chainResult = Get-CertificateChain -Certificate $cert
                    if ($chainResult.RootCAThumbprint -eq $RootCAThumbprint) {
                        $filteredByRootCA += $cert
                    }
                }
                
                $storeCerts = $filteredByRootCA
                
                if ($DebugMode) {
                    Write-Host "DEBUG: After RootCAThumbprint filter: $($storeCerts.Count) certificates (from $preRootCACount)" -ForegroundColor Magenta
                }
            }
            
            if (-not [string]::IsNullOrEmpty($IssuerHash)) {
                $preIssuerHashCount = $storeCerts.Count
                $filteredByIssuerHash = @()
                
                # First try direct issuer hash match
                foreach ($cert in $storeCerts) {
                    try {
                        # Calculate SHA1 hash of the issuer name
                        $issuerBytes = [System.Text.Encoding]::UTF8.GetBytes($cert.Issuer)
                        $sha1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
                        $hashBytes = $sha1.ComputeHash($issuerBytes)
                        $certIssuerHash = [System.BitConverter]::ToString($hashBytes).Replace("-", "")
                        
                        # Compare with the requested issuer hash (case-insensitive)
                        if ($certIssuerHash -ieq $IssuerHash) {
                            $filteredByIssuerHash += $cert
                        }
                        
                        if ($VerboseDebug) {
                            Write-Host "DEBUG:   Certificate: $($cert.Thumbprint)" -ForegroundColor Magenta
                            Write-Host "DEBUG:     Issuer: $($cert.Issuer)" -ForegroundColor Magenta
                            Write-Host "DEBUG:     Calculated IssuerHash: $certIssuerHash" -ForegroundColor Magenta
                            Write-Host "DEBUG:     Matches requested IssuerHash: $($certIssuerHash -ieq $IssuerHash)" -ForegroundColor Magenta
                        }
                    }
                    catch {
                        if ($DebugMode) {
                            Write-Host "DEBUG: Error calculating issuer hash for certificate $($cert.Thumbprint): $($_.Exception.Message)" -ForegroundColor Magenta
                        }
                    }
                }
                
                # If no matches found and we should try treating the hash as a CA thumbprint
                if ($filteredByIssuerHash.Count -eq 0 -and ($TreatHashAsCAThumbprint -or $Global:AllCertificatesWithPrivateKeys.Count -gt 0)) {
                    if ($DebugMode) {
                        Write-Host "DEBUG: No matches found with issuer hash. Trying to treat hash as CA thumbprint: $IssuerHash" -ForegroundColor Magenta
                    }
                    
                    # Check if this hash matches any Root CA thumbprint
                    $rootCAs = Get-UniqueRootCAs
                    # Normalize thumbprints for comparison
                    $matchingRootCA = $rootCAs | Where-Object { 
                        ($_.Thumbprint -replace '\s+', '') -eq $IssuerHash 
                    }
                    
                    if ($matchingRootCA) {
                        if ($DebugMode) {
                            Write-Host "DEBUG: Found matching Root CA with thumbprint: $IssuerHash" -ForegroundColor Magenta
                            Write-Host "DEBUG: Root CA Subject: $($matchingRootCA.Subject)" -ForegroundColor Magenta
                        }
                        
                        # First try to find certificates in the current store that are issued by this CA
                        foreach ($cert in $storeCerts) {
                            $chainResult = Get-CertificateChain -Certificate $cert
                            if ($chainResult.RootCAThumbprint -eq $IssuerHash) {
                                $filteredByIssuerHash += $cert
                                if ($DebugMode) {
                                    Write-Host "DEBUG: Found certificate issued by this CA: $($cert.Thumbprint)" -ForegroundColor Magenta
                                }
                            }
                        }
                        
                        # If we have a global collection, also check there
                        if ($filteredByIssuerHash.Count -eq 0 -and $Global:AllCertificatesWithPrivateKeys.Count -gt 0) {
                            if ($DebugMode) {
                                Write-Host "DEBUG: Checking global certificate collection for certificates issued by CA: $IssuerHash" -ForegroundColor Magenta
                            }
                            
                            $matchingCertsFromGlobal = $Global:AllCertificatesWithPrivateKeys | 
                            Where-Object { $_.RootCAThumbprint -eq $IssuerHash -and $_.StoreLocation -eq $storeInfo.Location }
                            
                            foreach ($certInfo in $matchingCertsFromGlobal) {
                                if ($DebugMode) {
                                    Write-Host "DEBUG: Found matching certificate in global collection: $($certInfo.Thumbprint)" -ForegroundColor Magenta
                                }
                                
                                # Check if this certificate is already in our filtered list
                                $alreadyAdded = $false
                                foreach ($existingCert in $filteredByIssuerHash) {
                                    if ($existingCert.Thumbprint -eq $certInfo.Certificate.Thumbprint) {
                                        $alreadyAdded = $true
                                        break
                                    }
                                }
                                
                                if (-not $alreadyAdded) {
                                    $filteredByIssuerHash += $certInfo.Certificate
                                }
                            }
                        }
                    }
                }
                
                $storeCerts = $filteredByIssuerHash
                
                if ($DebugMode) {
                    Write-Host "DEBUG: After IssuerHash/CA thumbprint filter: $($storeCerts.Count) certificates (from $preIssuerHashCount)" -ForegroundColor Magenta
                }
            }
            
            foreach ($cert in $storeCerts) {
                $matchingCerts += [PSCustomObject]@{
                    Certificate = $cert
                    Store       = $storeInfo.Name
                    Location    = $storeInfo.Location
                    Type        = $storeInfo.Type
                }
            }
            
            $store.Close()
        }
        catch {
            Write-Warning "Error accessing $($storeInfo.Location)\$($storeInfo.Name) store: $($_.Exception.Message)"
            if ($DebugMode) {
                Write-Host "DEBUG: Exception details: $($_.Exception)" -ForegroundColor Magenta
            }
        }
    }
    
    Write-Debug "Find-MatchingCertificates returning $($matchingCerts.Count) total matching certificates"
    return $matchingCerts
}

# Helper function to select XML nodes regardless of namespace
function Select-XmlNodeIgnoreNamespace {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlNode]$Node,
        
        [Parameter(Mandatory = $true)]
        [string]$XPath,
        
        [Parameter(Mandatory = $false)]
        [System.Xml.XmlNamespaceManager]$NamespaceManager = $null
    )
    
    try {
        # First try direct XPath
        $result = $Node.SelectSingleNode($XPath)
        
        if ($null -eq $result) {
            # Extract the element name from the XPath
            $elementName = $XPath
            if ($XPath -match "/([^/]+)$") {
                $elementName = $Matches[1]
            }
            elseif ($XPath -match "//([^/]+)$") {
                $elementName = $Matches[1]
            }
            
            # Try using local-name() to ignore namespace completely
            $localNameXPath = "//*[local-name()='$elementName']"
            $result = $Node.SelectSingleNode($localNameXPath)
            
            # If still not found and namespace manager is provided
            if ($null -eq $result -and $null -ne $NamespaceManager) {
                # Try with namespace prefix, but be careful with XPath construction
                # This was causing the invalid qualified name error
                $result = $Node.SelectSingleNode("//ns:$elementName", $NamespaceManager)
            }
        }
        
        return $result
    }
    catch {
        Write-Warning "Error in Select-XmlNodeIgnoreNamespace: $($_.Exception.Message)"
        return $null
    }
}

# Function to select multiple XML nodes regardless of namespace
function Select-XmlNodesIgnoreNamespace {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlNode]$Node,
        
        [Parameter(Mandatory = $true)]
        [string]$XPath,
        
        [Parameter(Mandatory = $false)]
        [System.Xml.XmlNamespaceManager]$NamespaceManager = $null
    )
    
    try {
        # First try direct XPath
        $result = $Node.SelectNodes($XPath)
        
        if ($null -eq $result -or $result.Count -eq 0) {
            # Extract the element name from the XPath
            $elementName = $XPath
            if ($XPath -match "/([^/]+)$") {
                $elementName = $Matches[1]
            }
            elseif ($XPath -match "//([^/]+)$") {
                $elementName = $Matches[1]
            }
            
            # Try using local-name() to ignore namespace completely
            $localNameXPath = "//*[local-name()='$elementName']"
            $result = $Node.SelectNodes($localNameXPath)
            
            # If still not found and namespace manager is provided
            if (($null -eq $result -or $result.Count -eq 0) -and $null -ne $NamespaceManager) {
                # Try with namespace prefix, but be careful with XPath construction
                # This was causing the invalid qualified name error
                $result = $Node.SelectNodes("//ns:$elementName", $NamespaceManager)
            }
        }
        
        return $result
    }
    catch {
        Write-Warning "Error in Select-XmlNodesIgnoreNamespace: $($_.Exception.Message)"
        return @()
    }
}

# Function to parse EAP configuration from WiFi profile XML
function Parse-EAPConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ProfileXML
    )

    try {
        # Create XML object from string
        [xml]$xml = $ProfileXML
        
        # Create a namespace manager to ignore namespaces
        $nsManager = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $nsManager.AddNamespace("ns", $xml.DocumentElement.NamespaceURI)
        
        $eapConfig = @{
            EAPType              = ""
            ServerValidation     = @{
                Enabled                  = $false
                TrustedRootCANames       = @()
                TrustedRootCAThumbprints = @()
                ServerNames              = ""
            }
            ClientAuthentication = @{
                Method                  = ""
                UseStrongCertProtection = $false
                SimpleCertSelection     = $false
                DifferentUser           = $false
                CertificateSubject      = ""
                CertificateIssuer       = ""
                CertificateThumbprint   = ""
                IssuerHash              = ""
            }
            TLSExtensions        = @{
                Enabled                     = $false
                ServerName                  = ""
                ClientCertificateExtensions = @()
                FilteringInfo               = @{
                    Enabled           = $false
                    ClientAuthEKUs    = @()
                    CAFlags           = 0
                    AllPurposeEnabled = $null
                    CAHashList        = @()
                    EKUMappings       = @()
                }
            }
        }
        
        # Use direct XPath with local-name() to find elements regardless of namespace
        # Extract EAP type - first try to find it directly
        $typeNodes = $xml.SelectNodes("//*[local-name()='Type']")
        if ($typeNodes -and $typeNodes.Count -gt 0) {
            # Find the EAP type node (usually the first one or one under EapMethod)
            foreach ($node in $typeNodes) {
                if ($node.ParentNode -and $node.ParentNode.LocalName -eq "EapMethod") {
                    $eapConfig.EAPType = $node.InnerText
                    break
                }
            }
            
            # If not found under EapMethod, use the first one
            if ([string]::IsNullOrEmpty($eapConfig.EAPType) -and $typeNodes.Count -gt 0) {
                $eapConfig.EAPType = $typeNodes[0].InnerText
            }
        }
        
        # Extract Server Validation settings
        $serverValidationNode = $xml.SelectSingleNode("//*[local-name()='ServerValidation']")
        if ($serverValidationNode) {
            $eapConfig.ServerValidation.Enabled = $true
            
            # Get server names
            $serverNamesNode = $serverValidationNode.SelectSingleNode("*[local-name()='ServerNames']")
            if ($serverNamesNode) {
                $eapConfig.ServerValidation.ServerNames = $serverNamesNode.InnerText
            }
            
            # Get trusted root CA
            $trustedRootCANodes = $serverValidationNode.SelectNodes("*[local-name()='TrustedRootCA']")
            if ($trustedRootCANodes -and $trustedRootCANodes.Count -gt 0) {
                foreach ($caNode in $trustedRootCANodes) {
                    $eapConfig.ServerValidation.TrustedRootCAThumbprints += $caNode.InnerText.Trim()
                }
            }
        }
        
        # Extract Client Authentication settings - look for CertificateStore node first
        $certStoreNode = $xml.SelectSingleNode("//*[local-name()='CertificateStore']")
        if ($certStoreNode) {
            # Check for SimpleCertSelection
            $simpleCertNode = $certStoreNode.SelectSingleNode("*[local-name()='SimpleCertSelection']")
            if ($simpleCertNode) {
                $eapConfig.ClientAuthentication.SimpleCertSelection = ($simpleCertNode.InnerText -eq "true")
            }
        }
        
        # Check for DifferentUsername
        $diffUsernameNode = $xml.SelectSingleNode("//*[local-name()='DifferentUsername']")
        if ($diffUsernameNode) {
            $eapConfig.ClientAuthentication.DifferentUser = ($diffUsernameNode.InnerText -eq "true")
        }
        
        # Extract TLS Extensions settings
        $tlsExtensionsNode = $xml.SelectSingleNode("//*[local-name()='TLSExtensions']")
        if ($tlsExtensionsNode) {
            $eapConfig.TLSExtensions.Enabled = $true
            
            # Look for FilteringInfo
            $filteringInfoNode = $tlsExtensionsNode.SelectSingleNode("*[local-name()='FilteringInfo']")
            if ($filteringInfoNode) {
                $eapConfig.TLSExtensions.FilteringInfo.Enabled = $true
                
                # Get CAHashList
                $caHashListNode = $filteringInfoNode.SelectSingleNode("*[local-name()='CAHashList']")
                if ($caHashListNode) {
                    # Check if it has an Enabled attribute
                    if ($caHashListNode.HasAttribute("Enabled")) {
                        $eapConfig.TLSExtensions.FilteringInfo.Enabled = ($caHashListNode.GetAttribute("Enabled") -eq "true")
                    }
                    
                    # Get IssuerHash nodes
                    $issuerHashNodes = $caHashListNode.SelectNodes("*[local-name()='IssuerHash']")
                    if ($issuerHashNodes -and $issuerHashNodes.Count -gt 0) {
                        foreach ($hashNode in $issuerHashNodes) {
                            $eapConfig.TLSExtensions.FilteringInfo.CAHashList += $hashNode.InnerText.Trim()
                        }
                    }
                }
                
                # Get ClientAuthEKUList
                $clientAuthEKUListNode = $filteringInfoNode.SelectSingleNode("*[local-name()='ClientAuthEKUList']")
                if ($clientAuthEKUListNode) {
                    # Check for EKUMapInList nodes
                    $ekuMapInListNodes = $clientAuthEKUListNode.SelectNodes("*[local-name()='EKUMapInList']")
                    if ($ekuMapInListNodes -and $ekuMapInListNodes.Count -gt 0) {
                        foreach ($ekuNode in $ekuMapInListNodes) {
                            $ekuNameNode = $ekuNode.SelectSingleNode("*[local-name()='EKUName']")
                            if ($ekuNameNode) {
                                $eapConfig.TLSExtensions.FilteringInfo.ClientAuthEKUs += $ekuNameNode.InnerText.Trim()
                            }
                        }
                    }
                }
            }
        }
        
        return $eapConfig
    }
    catch {
        $errorRecord = $_
        $lineNumber = $errorRecord.InvocationInfo.ScriptLineNumber
        Write-Warning "Error parsing EAP configuration: $($errorRecord.Exception.Message) at line $lineNumber"
        if ($DebugMode) {
            Write-Host "DEBUG: XML parsing error details: $($errorRecord)" -ForegroundColor Magenta
            Write-Host "DEBUG: Stack trace: $($errorRecord.ScriptStackTrace)" -ForegroundColor Magenta
            Write-Host "DEBUG: XML content sample: $($ProfileXML.Substring(0, [Math]::Min(500, $ProfileXML.Length)))" -ForegroundColor Magenta
        }
        return $null
    }
}

# Function to dump all certificates with private keys for debugging
function Dump-AllCertificatesWithPrivateKeys {
    if (-not $VerbosePreference -eq 'Continue') {
        return
    }
    
    Write-Verbose "`n===== Dumping All Certificates with Private Keys ====="
    
    $stores = @(
        @{Name = "My"; Location = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser; Type = "User" },
        @{Name = "My"; Location = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine; Type = "Machine" }
    )
    
    foreach ($storeInfo in $stores) {
        try {
            Write-Host "DEBUG: Certificates in $($storeInfo.Location)\$($storeInfo.Name) store:" -ForegroundColor Magenta
            
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeInfo.Name, $storeInfo.Location)
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            
            $certs = $store.Certificates | Where-Object { $_.HasPrivateKey }
            
            if ($certs.Count -eq 0) {
                Write-Host "DEBUG:   No certificates with private keys found in this store" -ForegroundColor Magenta
            }
            else {
                Write-Host "DEBUG:   Found $($certs.Count) certificates with private keys" -ForegroundColor Magenta
                
                foreach ($cert in $certs) {
                    Write-Host "DEBUG:   Certificate:" -ForegroundColor Magenta
                    Write-Host "DEBUG:     Subject: $($cert.Subject)" -ForegroundColor Magenta
                    Write-Host "DEBUG:     Issuer: $($cert.Issuer)" -ForegroundColor Magenta
                    Write-Host "DEBUG:     Thumbprint: $($cert.Thumbprint)" -ForegroundColor Magenta
                    Write-Host "DEBUG:     FriendlyName: $($cert.FriendlyName)" -ForegroundColor Magenta
                    Write-Host "DEBUG:     NotBefore: $($cert.NotBefore)" -ForegroundColor Magenta
                    Write-Host "DEBUG:     NotAfter: $($cert.NotAfter)" -ForegroundColor Magenta
                    Write-Host "DEBUG:     HasPrivateKey: $($cert.HasPrivateKey)" -ForegroundColor Magenta
                    Write-Host "DEBUG:     SerialNumber: $($cert.SerialNumber)" -ForegroundColor Magenta
                }
            }
            
            $store.Close()
        }
        catch {
            Write-Host "DEBUG: Error accessing $($storeInfo.Location)\$($storeInfo.Name) store: $($_.Exception.Message)" -ForegroundColor Magenta
        }
    }
}

# Function to get wired (LAN) interface details
function Get-WiredInterfaceDetails {
    try {
        $interfaces = @()
        $lanInterfaces = Get-NetAdapter | Where-Object { $_.MediaType -eq "802.3" -and $_.Status -eq "Up" }
        
        foreach ($adapter in $lanInterfaces) {
            $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex
            $authSettings = $null
            
            # Try to get 802.1X authentication settings
            try {
                $authSettings = Get-NetAdapterAdvancedProperty -InterfaceDescription $adapter.InterfaceDescription | 
                Where-Object { $_.RegistryKeyword -like "*802.1X*" -or $_.RegistryKeyword -like "*Authentication*" }
            }
            catch {
                # Ignore errors if advanced properties can't be accessed
            }
            
            $interfaces += [PSCustomObject]@{
                Name                 = $adapter.Name
                InterfaceDescription = $adapter.InterfaceDescription
                Status               = $adapter.Status
                MacAddress           = $adapter.MacAddress
                LinkSpeed            = $adapter.LinkSpeed
                MediaType            = $adapter.MediaType
                IPAddress            = ($ipConfig.IPv4Address.IPAddress -join ", ")
                Gateway              = ($ipConfig.IPv4DefaultGateway.NextHop -join ", ")
                DNSServer            = ($ipConfig.DNSServer.ServerAddresses -join ", ")
                Authentication       = if ($authSettings) { "802.1X Enabled" } else { "Unknown" }
            }
        }
        
        return $interfaces
    }
    catch {
        $errorRecord = $_
        $lineNumber = $errorRecord.InvocationInfo.ScriptLineNumber
        Write-Warning "Error getting wired interface details: $($errorRecord.Exception.Message) at line $lineNumber"
        if ($DebugMode) {
            Write-Warning "Stack trace: $($errorRecord.ScriptStackTrace)"
        }
        return @()
    }
}

# Function to get wired (LAN) 802.1X profiles
function Get-WiredProfiles {
    try {
        # Get all wired profiles using netsh
        $output = netsh lan show profiles
        
        if ($DebugMode) {
            Write-Debug "Raw netsh lan show profiles output:"
            Write-Debug ($output -join "`n")
        }
        
        $profiles = @()
        $currentProfile = $null
        
        foreach ($line in $output) {
            # Look for lines that indicate the start of a profile section
            if ($line -match "Profile on interface (.+)") {
                $interfaceName = $Matches[1].Trim()
                $currentProfile = $interfaceName
                $profiles += $currentProfile
            }
            # Alternative format that might be used
            elseif ($line -match "^Profile Name\s*:\s*(.+)$") {
                $profileName = $Matches[1].Trim()
                if (-not $profiles.Contains($profileName)) {
                    $profiles += $profileName
                }
            }
        }
        
        if ($DebugMode) {
            Write-Debug "Found $($profiles.Count) wired profiles:"
            foreach ($profile in $profiles) {
                Write-Debug "  - $profile"
            }
        }
        
        return $profiles
    }
    catch {
        Write-Warning "Error getting wired profiles: $($_.Exception.Message)"
        return @()
    }
}

# Function to get wired profile XML
function Get-WiredProfileXML {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ProfileName
    )
    
    try {
        # Get temp folder and ensure it exists
        $tempFolder = [System.IO.Path]::GetTempPath().TrimEnd('\')
        if (-not (Test-Path -Path $tempFolder -PathType Container)) {
            New-Item -Path $tempFolder -ItemType Directory -Force | Out-Null
        }
        
        # Sanitize profile name for file path
        $safeProfileName = $ProfileName -replace '[\\\/\:\*\?\"\<\>\|]', '_'
        $xmlFilePath = Join-Path -Path $tempFolder -ChildPath "$safeProfileName.xml"
        
        # Check if this is an interface name or a profile name
        $isInterface = $false
        $interfaceDetails = Get-NetAdapter | Where-Object { $_.Name -eq $ProfileName }
        if ($interfaceDetails) {
            $isInterface = $true
            Write-Debug "'$ProfileName' appears to be an interface name"
        }
        
        # Export the profile
        $exportCommand = if ($isInterface) {
            "netsh lan export profile interface=`"$ProfileName`" folder=`"$tempFolder`""
        }
        else {
            "netsh lan export profile name=`"$ProfileName`" folder=`"$tempFolder`""
        }
        
        Write-Debug "Executing: $exportCommand"
        
        $exportOutput = Invoke-Expression $exportCommand
        
        Write-Debug "Export output: $exportOutput"
        
        # Check if file exists
        if (Test-Path $xmlFilePath) {
            $content = Get-Content -Path $xmlFilePath -Raw -ErrorAction Stop
            Remove-Item -Path $xmlFilePath -Force -ErrorAction SilentlyContinue
            return $content
        }
        else {
            # Try alternative filename (netsh sometimes modifies the filename)
            $alternativeFiles = Get-ChildItem -Path $tempFolder -Filter "*.xml" | Where-Object { $_.Name -like "*$safeProfileName*" -or $_.Name -like "*lan*" }
            
            if ($alternativeFiles.Count -gt 0) {
                Write-Debug "Found alternative files:"
                foreach ($file in $alternativeFiles) {
                    Write-Debug "  - $($file.FullName)"
                }
            }
            
            if ($alternativeFiles.Count -gt 0) {
                $alternativeFile = $alternativeFiles[0].FullName
                $content = Get-Content -Path $alternativeFile -Raw -ErrorAction Stop
                Remove-Item -Path $alternativeFile -Force -ErrorAction SilentlyContinue
                return $content
            }
            
            # If still not found, try exporting all profiles and find the one we need
            Write-Debug "Trying to export all wired profiles"
            
            $exportAllOutput = netsh lan export profile folder="$tempFolder"
            $allXmlFiles = Get-ChildItem -Path $tempFolder -Filter "*.xml"
            
            if ($allXmlFiles.Count -gt 0) {
                foreach ($file in $allXmlFiles) {
                    $fileContent = Get-Content -Path $file.FullName -Raw
                    # Check if this file contains our profile or interface name
                    if ($fileContent -match $ProfileName) {
                        $content = $fileContent
                        Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
                        return $content
                    }
                }
                
                # Clean up any remaining files
                foreach ($file in $allXmlFiles) {
                    if (Test-Path $file.FullName) {
                        Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            
            Write-Warning "Failed to export wired profile XML for '$ProfileName'. File not found at expected location."
            return $null
        }
    }
    catch {
        Write-Warning "Error exporting wired profile XML for '$ProfileName': $($_.Exception.Message)"
        return $null
    }
}

# Function to check wired (LAN) profiles using certificates
function Check-WiredProfiles {
    Write-Host "`n===== Checking Wired (LAN) Profiles Using Certificates =====" -ForegroundColor Cyan
    
    try {
        # Get current wired interfaces and their status
        $wiredInterfaces = Get-WiredInterfaceDetails
        if ($wiredInterfaces.Count -gt 0) {
            Write-Host "`nCurrent Wired Interface Status:" -ForegroundColor Cyan
            foreach ($interface in $wiredInterfaces) {
                $connectionStatus = if ($interface.Status -eq "Up") { "Green" } else { "Yellow" }
                Write-Host "  Interface: $($interface.Name)" -ForegroundColor White
                Write-Host "    Status: $($interface.Status)" -ForegroundColor $connectionStatus
                Write-Host "    Description: $($interface.InterfaceDescription)" -ForegroundColor White
                Write-Host "    MAC Address: $($interface.MacAddress)" -ForegroundColor White
                Write-Host "    Link Speed: $($interface.LinkSpeed)" -ForegroundColor White
                Write-Host "    IP Address: $($interface.IPAddress)" -ForegroundColor White
                if ($interface.Gateway) {
                    Write-Host "    Gateway: $($interface.Gateway)" -ForegroundColor White
                }
                if ($interface.Authentication) {
                    Write-Host "    Authentication: $($interface.Authentication)" -ForegroundColor White
                }
            }
        }
        else {
            Write-Host "`nNo active wired interfaces found" -ForegroundColor Yellow
        }
        
        # Get all wired profiles
        $profiles = Get-WiredProfiles
        
        if ($profiles.Count -eq 0) {
            Write-Host "`nNo wired 802.1X profiles found on this machine" -ForegroundColor Yellow
            return
        }
        
        Write-Host "`nFound $($profiles.Count) wired 802.1X profiles on this machine" -ForegroundColor White
        
        $certBasedProfiles = @()
        $nonCertProfiles = @()
        $profileResults = @()
        
        foreach ($profile in $profiles) {
            # Get detailed information for each profile
            # Check if this is an interface name
            $isInterface = $false
            $interfaceDetails = Get-NetAdapter | Where-Object { $_.Name -eq $profile }
            if ($interfaceDetails) {
                $isInterface = $true
                Write-Debug "'$profile' is an interface name"
                $profileInfo = netsh lan show profile interface="$profile"
            }
            else {
                Write-Debug "'$profile' is a profile name"
                $profileInfo = netsh lan show profile name="$profile"
            }
            
            if ($DebugMode) {
                Write-Host "DEBUG: Profile info for '$profile':" -ForegroundColor Magenta
                Write-Host $profileInfo -ForegroundColor Magenta
            }
            
            # Check if the profile uses certificate-based authentication
            $usesCert = $profileInfo | Select-String -Pattern "EAP type|Certificate|Smart Card"
            
            if ($usesCert) {
                $certBasedProfiles += $profile
                
                Write-Host "`nWired Profile: $profile" -ForegroundColor White
                
                # Check if this is the currently connected profile
                $isConnected = $false
                foreach ($interface in $wiredInterfaces) {
                    # This is a simplification - in reality, determining if a specific 802.1X profile
                    # is active on a wired interface requires more complex checks
                    if ($interface.Status -eq "Up" -and $interface.Authentication -eq "802.1X Enabled") {
                        $isConnected = $true
                        Write-Host "  Status: Possibly connected (on interface $($interface.Name))" -ForegroundColor Green
                        break
                    }
                }
                
                if (-not $isConnected) {
                    Write-Host "  Status: Not connected" -ForegroundColor Yellow
                }
                
                # Get EAP configuration from XML
                $profileXML = Get-WiredProfileXML -ProfileName $profile
                $eapConfig = $null
                
                if ($profileXML) {
                    Write-Verbose "Raw wired profile XML for '$profile':"
                    Write-Verbose "----------------------------------------"
                    Write-Verbose $profileXML
                    Write-Verbose "----------------------------------------"
                    
                    $eapConfig = Parse-EAPConfiguration -ProfileXML $profileXML
                    
                    if ($eapConfig) {
                        Write-Host "  EAP Configuration:" -ForegroundColor White
                        $eapTypeDisplay = if ([string]::IsNullOrEmpty($eapConfig.EAPType)) { 
                            # Try to get EAP type from profile output if not in XML
                            $eapTypeFromProfile = $profileInfo | Select-String -Pattern "EAP type\s+:" | ForEach-Object { ($_ -split ":", 2)[1].Trim() }
                            if ([string]::IsNullOrEmpty($eapTypeFromProfile)) { "EAP-TLS (default)" } else { $eapTypeFromProfile }
                        }
                        else { 
                            # Convert numeric EAP type to descriptive text
                            switch ($eapConfig.EAPType) {
                                "13" { "EAP-TLS" }
                                "25" { "PEAP" }
                                "26" { "EAP-MSCHAP v2" }
                                "43" { "EAP-AKA" }
                                "50" { "EAP-SIM" }
                                "23" { "EAP-TTLS" }
                                default { "EAP Type $($eapConfig.EAPType)" }
                            }
                        }
                        Write-Host "    EAP Type: $eapTypeDisplay" -ForegroundColor White
                        
                        # Server validation
                        Write-Host "    Server Validation:" -ForegroundColor White
                        Write-Host "      Enabled: $($eapConfig.ServerValidation.Enabled)" -ForegroundColor White
                        
                        if ($eapConfig.ServerValidation.ServerNames) {
                            Write-Host "      Server Names: $($eapConfig.ServerValidation.ServerNames)" -ForegroundColor White
                        }
                        
                        if ($eapConfig.ServerValidation.TrustedRootCANames.Count -gt 0 -or $eapConfig.ServerValidation.TrustedRootCAThumbprints.Count -gt 0) {
                            Write-Host "      Trusted Root CAs:" -ForegroundColor White
                            
                            # First try by names
                            foreach ($ca in $eapConfig.ServerValidation.TrustedRootCANames) {
                                # Check if this Root CA is installed
                                $isInstalled = Test-RootCAInstalled -Subject $ca
                                $caInfo = Get-RootCAInfo -Subject $ca
                                
                                if ($isInstalled) {
                                    Write-Host "        - $ca" -ForegroundColor Green
                                    if ($caInfo) {
                                        Write-Host "          Thumbprint: $($caInfo.Thumbprint)" -ForegroundColor White
                                        Write-Host "          Store: $($caInfo.Store)" -ForegroundColor White
                                        
                                        # Check expiration
                                        $daysUntilExpiry = [math]::Round(($caInfo.NotAfter - (Get-Date)).TotalDays)
                                        $expiryColor = if ($daysUntilExpiry -lt 30) { "Yellow" } elseif ($daysUntilExpiry -lt 0) { "Red" } else { "Green" }
                                        $expiryStatus = if ($daysUntilExpiry -lt 0) { "EXPIRED" } else { "Valid for $daysUntilExpiry days" }
                                        Write-Host "          Expiry: $expiryStatus" -ForegroundColor $expiryColor
                                    }
                                }
                                else {
                                    Write-Host "        - $ca" -ForegroundColor Red
                                    Write-Host "          WARNING: This trusted Root CA is not installed on this device!" -ForegroundColor Red
                                    Write-Host "          Authentication may fail due to missing Root CA" -ForegroundColor Red
                                }
                            }
                            
                            # Then by thumbprints
                            foreach ($thumbprint in $eapConfig.ServerValidation.TrustedRootCAThumbprints) {
                                # Normalize thumbprint by removing spaces
                                $normalizedThumbprint = $thumbprint -replace '\s+', ''
                                
                                # Check if this Root CA is installed
                                $isInstalled = Test-RootCAInstalled -Thumbprint $normalizedThumbprint
                                $rootCAs = Get-UniqueRootCAs
                                $caInfo = $rootCAs | Where-Object { ($_.Thumbprint -replace '\s+', '') -eq $normalizedThumbprint } | Select-Object -First 1
                                
                                if ($isInstalled -and $caInfo) {
                                    Write-Host "        - $($caInfo.Subject)" -ForegroundColor Green
                                    Write-Host "          Thumbprint: $normalizedThumbprint" -ForegroundColor White
                                    Write-Host "          Store: $($caInfo.Store)" -ForegroundColor White
                                    
                                    # Check expiration
                                    $daysUntilExpiry = [math]::Round(($caInfo.NotAfter - (Get-Date)).TotalDays)
                                    $expiryColor = if ($daysUntilExpiry -lt 30) { "Yellow" } elseif ($daysUntilExpiry -lt 0) { "Red" } else { "Green" }
                                    $expiryStatus = if ($daysUntilExpiry -lt 0) { "EXPIRED" } else { "Valid for $daysUntilExpiry days" }
                                    Write-Host "          Expiry: $expiryStatus" -ForegroundColor $expiryColor
                                }
                                else {
                                    Write-Host "        - CA with thumbprint: $normalizedThumbprint" -ForegroundColor Red
                                    Write-Host "          WARNING: This trusted Root CA is not installed on this device!" -ForegroundColor Red
                                    Write-Host "          Authentication may fail due to missing Root CA" -ForegroundColor Red
                                }
                            }
                        }
                        else {
                            Write-Host "      Trusted Root CAs: None specified (will prompt user)" -ForegroundColor Yellow
                        }
                        
                        # Client authentication
                        Write-Host "    Client Authentication:" -ForegroundColor White
                        Write-Host "      Method: $($eapConfig.ClientAuthentication.Method)" -ForegroundColor White
                        
                        if ($eapConfig.ClientAuthentication.Method -eq "Certificate") {
                            Write-Host "      Use Strong Certificate Protection: $($eapConfig.ClientAuthentication.UseStrongCertProtection)" -ForegroundColor White
                            Write-Host "      Simple Certificate Selection: $($eapConfig.ClientAuthentication.SimpleCertSelection)" -ForegroundColor White
                            
                            if ($eapConfig.ClientAuthentication.CertificateSubject) {
                                Write-Host "      Certificate Subject: $($eapConfig.ClientAuthentication.CertificateSubject)" -ForegroundColor White
                            }
                            
                            if ($eapConfig.ClientAuthentication.CertificateIssuer) {
                                Write-Host "      Certificate Issuer: $($eapConfig.ClientAuthentication.CertificateIssuer)" -ForegroundColor White
                            }
                            
                            if ($eapConfig.ClientAuthentication.CertificateThumbprint) {
                                Write-Host "      Certificate Thumbprint: $($eapConfig.ClientAuthentication.CertificateThumbprint)" -ForegroundColor White
                            }
                            
                            if ($eapConfig.ClientAuthentication.IssuerHash) {
                                Write-Host "      Certificate Issuer Hash: $($eapConfig.ClientAuthentication.IssuerHash)" -ForegroundColor White
                            }
                        }
                        
                        # Display TLS Extensions if present
                        if ($eapConfig.TLSExtensions.Enabled) {
                            Write-Host "    TLS Extensions:" -ForegroundColor White
                            
                            if ($eapConfig.TLSExtensions.ServerName) {
                                Write-Host "      Server Name Indication (SNI): $($eapConfig.TLSExtensions.ServerName)" -ForegroundColor White
                            }
                            
                            if ($eapConfig.TLSExtensions.ClientCertificateExtensions.Count -gt 0) {
                                Write-Host "      Client Certificate Extensions:" -ForegroundColor White
                                foreach ($ext in $eapConfig.TLSExtensions.ClientCertificateExtensions) {
                                    $extName = if ($ext.Name) { "$($ext.Name) ($($ext.OID))" } else { $ext.OID }
                                    $criticalText = if ($ext.Critical) { " (Critical)" } else { "" }
                                    Write-Host "        - $extName$criticalText" -ForegroundColor White
                                    if ($ext.Type) {
                                        Write-Host "          Type: $($ext.Type)" -ForegroundColor White
                                    }
                                    if ($ext.Value -and $VerboseDebug) {
                                        Write-Host "          Value: $($ext.Value)" -ForegroundColor White
                                    }
                                }
                            }
                            
                            if ($eapConfig.TLSExtensions.FilteringInfo.Enabled) {
                                Write-Host "      Certificate Filtering:" -ForegroundColor White
                                
                                if ($eapConfig.TLSExtensions.FilteringInfo.AllPurposeEnabled -ne $null) {
                                    Write-Host "        All Purpose Enabled: $($eapConfig.TLSExtensions.FilteringInfo.AllPurposeEnabled)" -ForegroundColor White
                                }
                                
                                if ($eapConfig.TLSExtensions.FilteringInfo.CAHashList.Count -gt 0) {
                                    Write-Host "        CA Hash List:" -ForegroundColor White
                                    foreach ($hash in $eapConfig.TLSExtensions.FilteringInfo.CAHashList) {
                                        Write-Host "          - $hash" -ForegroundColor White
                                        
                                        # Find certificates matching this hash - try both issuer hash and CA thumbprint
                                        $matchingCertsForHash = Find-MatchingCertificates -Subject "" -Issuer "" -Thumbprint "" -IssuerHash $hash -TreatHashAsCAThumbprint
                                        
                                        if ($matchingCertsForHash.Count -gt 0) {
                                            Write-Host "            Matching Certificates:" -ForegroundColor Green
                                            foreach ($certMatch in $matchingCertsForHash) {
                                                Show-CertificateDetails -Certificate $certMatch.Certificate -StoreType $certMatch.Type -IndentLevel 4
                                            }
                                        }
                                        else {
                                            Write-Host "            No matching certificates found for this hash" -ForegroundColor Yellow
                                        }
                                    }
                                }
                                
                                if ($eapConfig.TLSExtensions.FilteringInfo.ClientAuthEKUs.Count -gt 0) {
                                    Write-Host "        Required EKUs:" -ForegroundColor White
                                    foreach ($eku in $eapConfig.TLSExtensions.FilteringInfo.ClientAuthEKUs) {
                                        Write-Host "          - $eku" -ForegroundColor White
                                    }
                                }
                                
                                if ($eapConfig.TLSExtensions.FilteringInfo.EKUMappings.Count -gt 0) {
                                    Write-Host "        EKU Mappings:" -ForegroundColor White
                                    foreach ($mapping in $eapConfig.TLSExtensions.FilteringInfo.EKUMappings) {
                                        Write-Host "          - $($mapping.Name) ($($mapping.OID))" -ForegroundColor White
                                    }
                                }
                                
                                if ($eapConfig.TLSExtensions.FilteringInfo.CAFlags -ne 0) {
                                    Write-Host "        CA Flags: $($eapConfig.TLSExtensions.FilteringInfo.CAFlags)" -ForegroundColor White
                                    
                                    # Interpret CA Flags
                                    $caFlagsValue = $eapConfig.TLSExtensions.FilteringInfo.CAFlags
                                    $caFlagsDesc = @()
                                    
                                    if ($caFlagsValue -band 0x01) { $caFlagsDesc += "End Entity certificates only" }
                                    if ($caFlagsValue -band 0x02) { $caFlagsDesc += "CA certificates only" }
                                    if ($caFlagsValue -band 0x04) { $caFlagsDesc += "Certificates with Basic Constraints extension required" }
                                    
                                    if ($caFlagsDesc.Count -gt 0) {
                                        foreach ($desc in $caFlagsDesc) {
                                            Write-Host "          - $desc" -ForegroundColor White
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                # Get certificate information from profile output
                $eapType = $profileInfo | Select-String -Pattern "EAP type\s+:" | ForEach-Object { ($_ -split ":", 2)[1].Trim() }
                if ($eapType -and -not $eapConfig) {
                    Write-Host "  EAP Type: $eapType" -ForegroundColor White
                }
                    
                $certInfo = $profileInfo | Select-String -Pattern "Certificate issuer\s+:|Certificate name\s+:|Certificate type\s+:|Certificate thumbprint\s+:"
                if ($certInfo) {
                    Write-Host "  Certificate Information (from profile):" -ForegroundColor White
                    foreach ($info in $certInfo) {
                        $label = ($info -split ":")[0].Trim()
                        $value = ($info -split ":", 2)[1].Trim()
                        Write-Host "    $label : $value" -ForegroundColor White
                    }
                    
                    # Extract certificate criteria from profile and EAP config
                    $profileType = $profileInfo | Select-String -Pattern "Profile type\s+:" | ForEach-Object { ($_ -split ":", 2)[1].Trim() }
                    Write-Host "  Profile Type: $profileType" -ForegroundColor White
                    
                    $certCriteria = Extract-CertificateCriteria -ProfileInfo $profileInfo -EAPConfig $eapConfig
                    
                    # Get trusted root CA thumbprints from EAP config
                    $trustedRootCAThumbprints = if ($eapConfig) { $eapConfig.ServerValidation.TrustedRootCAThumbprints } else { @() }
                    
                    # Find matching certificates using multiple strategies
                    $matchingCerts = Find-MatchingCertificatesWithMultipleStrategies -CertificateCriteria $certCriteria -TrustedRootCAThumbprints $trustedRootCAThumbprints
                    
                    # Analyze matching certificates
                    $certAnalysis = Analyze-MatchingCertificates -MatchingCertificates $matchingCerts `
                        -ProfileType $profileType `
                        -ProfileName $profile `
                        -NetworkType "Wired" `
                        -CertificateCriteria $certCriteria `
                        -TrustedRootCANames $(if ($eapConfig) { $eapConfig.ServerValidation.TrustedRootCANames } else { @() }) `
                        -TrustedRootCAThumbprints $trustedRootCAThumbprints
                    
                    # Store results for summary
                    $profileResults += [PSCustomObject]@{
                        Name             = $profile
                        IsConnected      = $isConnected
                        HasMatchingCerts = $certAnalysis.FoundInStore
                        ValidCerts       = $certAnalysis.ValidCertificates
                        ExpiredCerts     = $certAnalysis.ExpiredCertificates
                        ProblemCerts     = $certAnalysis.ProblemCertificates
                        TotalCerts       = $certAnalysis.TotalCertificates
                        UserCerts        = $certAnalysis.UserCertificates
                        MachineCerts     = $certAnalysis.MachineCertificates
                    }
                    
                    # Provide wired-specific troubleshooting guidance
                    Write-Host "    To view wired profile details, run: " -NoNewline -ForegroundColor White
                    Write-Host "netsh lan show profile name=`"$profile`"" -ForegroundColor Cyan
                    
                    # Create profiles directory if it doesn't exist
                    $exportFolder = "C:\lanprofiles"
                    if (-not (Test-Path -Path $exportFolder -PathType Container)) {
                        Write-Host "    Note: Export folder C:\lanprofiles must exist before exporting" -ForegroundColor Yellow
                    }
                    
                    Write-Host "    To export this profile: " -NoNewline -ForegroundColor White
                    Write-Host "netsh lan export profile name=`"$profile`" folder=C:\lanprofiles" -ForegroundColor Cyan
                }
                else {
                    Write-Host "  No specific certificate information found in profile" -ForegroundColor Yellow
                }
            }
            else {
                $nonCertProfiles += $profile
            }
        }
        
        if ($certBasedProfiles.Count -eq 0) {
            Write-Host "`nNo wired profiles using certificate-based authentication found" -ForegroundColor Yellow
            if ($nonCertProfiles.Count -gt 0) {
                Write-Host "Found $($nonCertProfiles.Count) wired profiles using other authentication methods" -ForegroundColor White
            }
        }
        else {
            Write-Host "`nSummary:" -ForegroundColor Cyan
            Write-Host "Found $($certBasedProfiles.Count) wired profiles using certificate-based authentication" -ForegroundColor Green
            if ($nonCertProfiles.Count -gt 0) {
                Write-Host "Found $($nonCertProfiles.Count) wired profiles using other authentication methods" -ForegroundColor White
            }
            
            # Show certificate status summary
            $validProfiles = $profileResults | Where-Object { $_.ValidCerts -gt 0 }
            $problemProfiles = $profileResults | Where-Object { $_.HasMatchingCerts -and $_.ValidCerts -eq 0 }
            $noCertProfiles = $profileResults | Where-Object { -not $_.HasMatchingCerts }
            
            if ($validProfiles.Count -gt 0) {
                Write-Host "$($validProfiles.Count) profiles have valid certificates" -ForegroundColor Green
            }
            if ($problemProfiles.Count -gt 0) {
                Write-Host "$($problemProfiles.Count) profiles have matching certificates with issues" -ForegroundColor Yellow
            }
            if ($noCertProfiles.Count -gt 0) {
                Write-Host "$($noCertProfiles.Count) profiles have no matching certificates" -ForegroundColor Red
            }
        }
    }
    catch {
        $errorRecord = $_
        $lineNumber = $errorRecord.InvocationInfo.ScriptLineNumber
        Write-Host "Error checking wired profiles: $($errorRecord.Exception.Message) at line $lineNumber" -ForegroundColor Red
        if ($DebugMode) {
            Write-Host "Stack trace: $($errorRecord.ScriptStackTrace)" -ForegroundColor Red
        }
    }
}

# Function to check WiFi profiles using certificates
function Check-WiFiProfiles {
    Write-Host "`n===== Checking WiFi Profiles Using Certificates =====" -ForegroundColor Cyan
    
    try {
        # Get current WiFi interfaces and their status
        $wifiInterfaces = Get-WiFiInterfaceDetails
        if ($wifiInterfaces.Count -gt 0) {
            Write-Host "`nCurrent WiFi Interface Status:" -ForegroundColor Cyan
            foreach ($interface in $wifiInterfaces) {
                $connectionStatus = if ($interface.State -eq "connected") { "Green" } else { "Yellow" }
                Write-Host "  Interface: $($interface.Name)" -ForegroundColor White
                Write-Host "    Status: $($interface.State)" -ForegroundColor $connectionStatus
                
                if ($interface.State -eq "connected") {
                    Write-Host "    Connected to: $($interface.SSID)" -ForegroundColor White
                    Write-Host "    Authentication: $($interface.Authentication)" -ForegroundColor White
                    Write-Host "    Signal Strength: $($interface.Signal)" -ForegroundColor White
                    Write-Host "    Radio Type: $($interface.RadioType)" -ForegroundColor White
                    Write-Host "    Channel: $($interface.Channel)" -ForegroundColor White
                    Write-Host "    Connection Speed: $($interface.ReceiveRate)/$($interface.TransmitRate) Mbps (Rx/Tx)" -ForegroundColor White
                }
            }
        }
        
        # Get all WiFi profiles
        $profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object { ($_ -split ":")[-1].Trim() }
        
        if ($profiles.Count -eq 0) {
            Write-Host "`nNo WiFi profiles found on this machine" -ForegroundColor Yellow
            return
        }
        
        Write-Host "`nFound $($profiles.Count) WiFi profiles on this machine" -ForegroundColor White
        
        $certBasedProfiles = @()
        $nonCertProfiles = @()
        $profileResults = @()
        
        foreach ($profile in $profiles) {
            # Get detailed information for each profile
            $profileInfo = netsh wlan show profile name="$profile" key=clear
            
            # Check if the profile uses certificate-based authentication
            $usesCert = $profileInfo | Select-String -Pattern "EAP type|Certificate"
            
            if ($usesCert) {
                $certBasedProfiles += $profile
                
                Write-Host "`nWiFi Profile: $profile" -ForegroundColor White
                
                # Check if this is the currently connected profile
                $isConnected = $false
                foreach ($interface in $wifiInterfaces) {
                    # Get SSID from profile info for more accurate comparison
                    $profileSSID = $profileInfo | Select-String -Pattern "SSID name\s+:" | ForEach-Object { ($_ -split ":", 2)[1].Trim() }
                    
                    # Remove quotes from SSID if present
                    if ($profileSSID -match '^"(.*)"$') {
                        $profileSSID = $Matches[1]
                    }
                    
                    # Compare both the profile name and the actual SSID
                    if (($interface.SSID -eq $profile -or $interface.SSID -eq $profileSSID) -and $interface.State -eq "connected") {
                        $isConnected = $true
                        Write-Host "  Status: Connected (on interface $($interface.Name))" -ForegroundColor Green
                        break
                    }
                }
                
                if (-not $isConnected) {
                    Write-Host "  Status: Not connected" -ForegroundColor Yellow
                }
                
                # Get basic profile information
                $ssid = $profileInfo | Select-String -Pattern "SSID name\s+:" | ForEach-Object { ($_ -split ":", 2)[1].Trim() }
                $connectionType = $profileInfo | Select-String -Pattern "Network type\s+:" | ForEach-Object { ($_ -split ":", 2)[1].Trim() }
                $connectionMode = $profileInfo | Select-String -Pattern "Connection mode\s+:" | ForEach-Object { ($_ -split ":", 2)[1].Trim() }
                $autoSwitch = $profileInfo | Select-String -Pattern "AutoSwitch\s+:" | ForEach-Object { ($_ -split ":", 2)[1].Trim() }
                
                Write-Host "  SSID: $ssid" -ForegroundColor White
                Write-Host "  Network Type: $connectionType" -ForegroundColor White
                Write-Host "  Connection Mode: $connectionMode" -ForegroundColor White
                Write-Host "  Auto Switch: $autoSwitch" -ForegroundColor White
                
                # Security settings
                $authMethod = $profileInfo | Select-String -Pattern "Authentication\s+:" | ForEach-Object { ($_ -split ":", 2)[1].Trim() }
                $encryption = $profileInfo | Select-String -Pattern "Encryption\s+:" | ForEach-Object { ($_ -split ":", 2)[1].Trim() }
                
                Write-Host "  Security Settings:" -ForegroundColor White
                Write-Host "    Authentication: $authMethod" -ForegroundColor White
                Write-Host "    Encryption: $encryption" -ForegroundColor White
                
                # Get EAP configuration from XML
                $profileXML = Get-WiFiProfileXML -ProfileName $profile
                $eapConfig = $null
                
                if ($profileXML) {
                    Write-Verbose "Raw WiFi profile XML for '$profile':"
                    Write-Verbose "----------------------------------------"
                    Write-Verbose $profileXML
                    Write-Verbose "----------------------------------------"
                    
                    $eapConfig = Parse-EAPConfiguration -ProfileXML $profileXML
                    
                    if ($eapConfig) {
                        Write-Host "  EAP Configuration:" -ForegroundColor White
                        $eapTypeDisplay = if ([string]::IsNullOrEmpty($eapConfig.EAPType)) { 
                            # Try to get EAP type from profile output if not in XML
                            $eapTypeFromProfile = $profileInfo | Select-String -Pattern "EAP type\s+:" | ForEach-Object { ($_ -split ":", 2)[1].Trim() }
                            if ([string]::IsNullOrEmpty($eapTypeFromProfile)) { "EAP-TLS (default)" } else { $eapTypeFromProfile }
                        }
                        else { 
                            # Convert numeric EAP type to descriptive text
                            switch ($eapConfig.EAPType) {
                                "13" { "EAP-TLS" }
                                "25" { "PEAP" }
                                "26" { "EAP-MSCHAP v2" }
                                "43" { "EAP-AKA" }
                                "50" { "EAP-SIM" }
                                "23" { "EAP-TTLS" }
                                default { "EAP Type $($eapConfig.EAPType)" }
                            }
                        }
                        Write-Host "    EAP Type: $eapTypeDisplay" -ForegroundColor White
                        
                        # Server validation
                        Write-Host "    Server Validation:" -ForegroundColor White
                        Write-Host "      Enabled: $($eapConfig.ServerValidation.Enabled)" -ForegroundColor White
                        
                        if ($eapConfig.ServerValidation.ServerNames) {
                            Write-Host "      Server Names: $($eapConfig.ServerValidation.ServerNames)" -ForegroundColor White
                        }
                        
                        if ($eapConfig.ServerValidation.TrustedRootCANames.Count -gt 0 -or $eapConfig.ServerValidation.TrustedRootCAThumbprints.Count -gt 0) {
                            Write-Host "      Trusted Root CAs:" -ForegroundColor White
                            
                            # First try by names
                            foreach ($ca in $eapConfig.ServerValidation.TrustedRootCANames) {
                                # Check if this Root CA is installed
                                $isInstalled = Test-RootCAInstalled -Subject $ca
                                $caInfo = Get-RootCAInfo -Subject $ca
                                
                                if ($isInstalled) {
                                    Write-Host "        - $ca" -ForegroundColor Green
                                    if ($caInfo) {
                                        Write-Host "          Thumbprint: $($caInfo.Thumbprint)" -ForegroundColor White
                                        Write-Host "          Store: $($caInfo.Store)" -ForegroundColor White
                                        
                                        # Check expiration
                                        $daysUntilExpiry = [math]::Round(($caInfo.NotAfter - (Get-Date)).TotalDays)
                                        $expiryColor = if ($daysUntilExpiry -lt 30) { "Yellow" } elseif ($daysUntilExpiry -lt 0) { "Red" } else { "Green" }
                                        $expiryStatus = if ($daysUntilExpiry -lt 0) { "EXPIRED" } else { "Valid for $daysUntilExpiry days" }
                                        Write-Host "          Expiry: $expiryStatus" -ForegroundColor $expiryColor
                                    }
                                }
                                else {
                                    Write-Host "        - $ca" -ForegroundColor Red
                                    Write-Host "          WARNING: This trusted Root CA is not installed on this device!" -ForegroundColor Red
                                    Write-Host "          WiFi authentication may fail due to missing Root CA" -ForegroundColor Red
                                }
                            }
                            
                            # Then by thumbprints
                            foreach ($thumbprint in $eapConfig.ServerValidation.TrustedRootCAThumbprints) {
                                # Normalize thumbprint by removing spaces
                                $normalizedThumbprint = $thumbprint -replace '\s+', ''
                                
                                # Check if this Root CA is installed
                                $isInstalled = Test-RootCAInstalled -Thumbprint $normalizedThumbprint
                                $rootCAs = Get-UniqueRootCAs
                                $caInfo = $rootCAs | Where-Object { ($_.Thumbprint -replace '\s+', '') -eq $normalizedThumbprint } | Select-Object -First 1
                                
                                if ($isInstalled -and $caInfo) {
                                    Write-Host "        - $($caInfo.Subject)" -ForegroundColor Green
                                    Write-Host "          Thumbprint: $normalizedThumbprint" -ForegroundColor White
                                    Write-Host "          Store: $($caInfo.Store)" -ForegroundColor White
                                    
                                    # Check expiration
                                    $daysUntilExpiry = [math]::Round(($caInfo.NotAfter - (Get-Date)).TotalDays)
                                    $expiryColor = if ($daysUntilExpiry -lt 30) { "Yellow" } elseif ($daysUntilExpiry -lt 0) { "Red" } else { "Green" }
                                    $expiryStatus = if ($daysUntilExpiry -lt 0) { "EXPIRED" } else { "Valid for $daysUntilExpiry days" }
                                    Write-Host "          Expiry: $expiryStatus" -ForegroundColor $expiryColor
                                }
                                else {
                                    Write-Host "        - CA with thumbprint: $normalizedThumbprint" -ForegroundColor Red
                                    Write-Host "          WARNING: This trusted Root CA is not installed on this device!" -ForegroundColor Red
                                    Write-Host "          WiFi authentication may fail due to missing Root CA" -ForegroundColor Red
                                }
                            }
                        }
                        else {
                            Write-Host "      Trusted Root CAs: None specified (will prompt user)" -ForegroundColor Yellow
                        }
                        
                        # Client authentication
                        Write-Host "    Client Authentication:" -ForegroundColor White
                        Write-Host "      Method: $($eapConfig.ClientAuthentication.Method)" -ForegroundColor White
                        
                        if ($eapConfig.ClientAuthentication.Method -eq "Certificate") {
                            Write-Host "      Use Strong Certificate Protection: $($eapConfig.ClientAuthentication.UseStrongCertProtection)" -ForegroundColor White
                            Write-Host "      Simple Certificate Selection: $($eapConfig.ClientAuthentication.SimpleCertSelection)" -ForegroundColor White
                            
                            if ($eapConfig.ClientAuthentication.CertificateSubject) {
                                Write-Host "      Certificate Subject: $($eapConfig.ClientAuthentication.CertificateSubject)" -ForegroundColor White
                            }
                            
                            if ($eapConfig.ClientAuthentication.CertificateIssuer) {
                                Write-Host "      Certificate Issuer: $($eapConfig.ClientAuthentication.CertificateIssuer)" -ForegroundColor White
                            }
                            
                            if ($eapConfig.ClientAuthentication.CertificateThumbprint) {
                                Write-Host "      Certificate Thumbprint: $($eapConfig.ClientAuthentication.CertificateThumbprint)" -ForegroundColor White
                            }
                            
                            if ($eapConfig.ClientAuthentication.IssuerHash) {
                                Write-Host "      Certificate Issuer Hash: $($eapConfig.ClientAuthentication.IssuerHash)" -ForegroundColor White
                            }
                        }
                        
                        # Display TLS Extensions if present
                        if ($eapConfig.TLSExtensions.Enabled) {
                            Write-Host "    TLS Extensions:" -ForegroundColor White
                            
                            if ($eapConfig.TLSExtensions.ServerName) {
                                Write-Host "      Server Name Indication (SNI): $($eapConfig.TLSExtensions.ServerName)" -ForegroundColor White
                            }
                            
                            if ($eapConfig.TLSExtensions.ClientCertificateExtensions.Count -gt 0) {
                                Write-Host "      Client Certificate Extensions:" -ForegroundColor White
                                foreach ($ext in $eapConfig.TLSExtensions.ClientCertificateExtensions) {
                                    $extName = if ($ext.Name) { "$($ext.Name) ($($ext.OID))" } else { $ext.OID }
                                    $criticalText = if ($ext.Critical) { " (Critical)" } else { "" }
                                    Write-Host "        - $extName$criticalText" -ForegroundColor White
                                    if ($ext.Type) {
                                        Write-Host "          Type: $($ext.Type)" -ForegroundColor White
                                    }
                                    if ($ext.Value -and $VerboseDebug) {
                                        Write-Host "          Value: $($ext.Value)" -ForegroundColor White
                                    }
                                }
                            }
                            
                            if ($eapConfig.TLSExtensions.FilteringInfo.Enabled) {
                                Write-Host "      Certificate Filtering:" -ForegroundColor White
                                
                                if ($eapConfig.TLSExtensions.FilteringInfo.AllPurposeEnabled -ne $null) {
                                    Write-Host "        All Purpose Enabled: $($eapConfig.TLSExtensions.FilteringInfo.AllPurposeEnabled)" -ForegroundColor White
                                }
                                
                                if ($eapConfig.TLSExtensions.FilteringInfo.CAHashList.Count -gt 0) {
                                    Write-Host "        CA Hash List:" -ForegroundColor White
                                    foreach ($hash in $eapConfig.TLSExtensions.FilteringInfo.CAHashList) {
                                        Write-Host "          - $hash" -ForegroundColor White
                                        
                                        # Find certificates matching this hash - try both issuer hash and CA thumbprint
                                        $matchingCertsForHash = Find-MatchingCertificates -Subject "" -Issuer "" -Thumbprint "" -IssuerHash $hash -TreatHashAsCAThumbprint
                                        
                                        if ($DebugMode -and $matchingCertsForHash.Count -gt 0) {
                                            Write-Host "DEBUG:         Found $($matchingCertsForHash.Count) matching certificates for hash: $hash" -ForegroundColor Magenta
                                        }
                                        
                                        if ($matchingCertsForHash.Count -gt 0) {
                                            Write-Host "            Matching Certificates:" -ForegroundColor Green
                                            foreach ($certMatch in $matchingCertsForHash) {
                                                Show-CertificateDetails -Certificate $certMatch.Certificate -StoreType $certMatch.Type -IndentLevel 4
                                            }
                                        }
                                        else {
                                            Write-Host "            No matching certificates found for this hash" -ForegroundColor Yellow
                                        }
                                    }
                                }
                                
                                if ($eapConfig.TLSExtensions.FilteringInfo.ClientAuthEKUs.Count -gt 0) {
                                    Write-Host "        Required EKUs:" -ForegroundColor White
                                    foreach ($eku in $eapConfig.TLSExtensions.FilteringInfo.ClientAuthEKUs) {
                                        Write-Host "          - $eku" -ForegroundColor White
                                    }
                                }
                                
                                if ($eapConfig.TLSExtensions.FilteringInfo.EKUMappings.Count -gt 0) {
                                    Write-Host "        EKU Mappings:" -ForegroundColor White
                                    foreach ($mapping in $eapConfig.TLSExtensions.FilteringInfo.EKUMappings) {
                                        Write-Host "          - $($mapping.Name) ($($mapping.OID))" -ForegroundColor White
                                    }
                                }
                                
                                if ($eapConfig.TLSExtensions.FilteringInfo.CAFlags -ne 0) {
                                    Write-Host "        CA Flags: $($eapConfig.TLSExtensions.FilteringInfo.CAFlags)" -ForegroundColor White
                                    
                                    # Interpret CA Flags
                                    $caFlagsValue = $eapConfig.TLSExtensions.FilteringInfo.CAFlags
                                    $caFlagsDesc = @()
                                    
                                    if ($caFlagsValue -band 0x01) { $caFlagsDesc += "End Entity certificates only" }
                                    if ($caFlagsValue -band 0x02) { $caFlagsDesc += "CA certificates only" }
                                    if ($caFlagsValue -band 0x04) { $caFlagsDesc += "Certificates with Basic Constraints extension required" }
                                    
                                    if ($caFlagsDesc.Count -gt 0) {
                                        foreach ($desc in $caFlagsDesc) {
                                            Write-Host "          - $desc" -ForegroundColor White
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                # Get certificate information from profile output
                $eapType = $profileInfo | Select-String -Pattern "EAP type\s+:" | ForEach-Object { ($_ -split ":", 2)[1].Trim() }
                if ($eapType -and -not $eapConfig) {
                    Write-Host "  EAP Type: $eapType" -ForegroundColor White
                }
                    
                $certInfo = $profileInfo | Select-String -Pattern "Certificate issuer\s+:|Certificate name\s+:|Certificate type\s+:|Certificate thumbprint\s+:"
                if ($certInfo) {
                    Write-Host "  Certificate Information (from profile):" -ForegroundColor White
                    foreach ($info in $certInfo) {
                        $label = ($info -split ":")[0].Trim()
                        $value = ($info -split ":", 2)[1].Trim()
                        Write-Host "    $label : $value" -ForegroundColor White
                    }
                    
                    # Extract certificate criteria from profile and EAP config
                    $profileType = $profileInfo | Select-String -Pattern "Profile type\s+:" | ForEach-Object { ($_ -split ":", 2)[1].Trim() }
                    Write-Host "  Profile Type: $profileType" -ForegroundColor White
                    
                    $certCriteria = Extract-CertificateCriteria -ProfileInfo $profileInfo -EAPConfig $eapConfig
                    
                    # Get trusted root CA thumbprints from EAP config
                    $trustedRootCAThumbprints = if ($eapConfig) { $eapConfig.ServerValidation.TrustedRootCAThumbprints } else { @() }
                    
                    # Find matching certificates using multiple strategies
                    $matchingCerts = Find-MatchingCertificatesWithMultipleStrategies -CertificateCriteria $certCriteria -TrustedRootCAThumbprints $trustedRootCAThumbprints
                    
                    # Analyze matching certificates
                    $certAnalysis = Analyze-MatchingCertificates -MatchingCertificates $matchingCerts `
                        -ProfileType $profileType `
                        -ProfileName $profile `
                        -NetworkType "WiFi" `
                        -CertificateCriteria $certCriteria `
                        -TrustedRootCANames $(if ($eapConfig) { $eapConfig.ServerValidation.TrustedRootCANames } else { @() }) `
                        -TrustedRootCAThumbprints $trustedRootCAThumbprints
                    
                    # Store results for summary
                    $profileResults += [PSCustomObject]@{
                        Name             = $profile
                        SSID             = $ssid
                        IsConnected      = $isConnected
                        HasMatchingCerts = $certAnalysis.FoundInStore
                        ValidCerts       = $certAnalysis.ValidCertificates
                        ExpiredCerts     = $certAnalysis.ExpiredCertificates
                        ProblemCerts     = $certAnalysis.ProblemCertificates
                        TotalCerts       = $certAnalysis.TotalCertificates
                        UserCerts        = $certAnalysis.UserCertificates
                        MachineCerts     = $certAnalysis.MachineCertificates
                    }
                    
                    # Provide WiFi-specific troubleshooting guidance
                    if ($isConnected) {
                        Write-Host "    Profile is currently connected and working" -ForegroundColor Green
                    }
                    else {
                        Write-Host "    To test this profile, run: " -NoNewline -ForegroundColor White
                        Write-Host "netsh wlan connect name=`"$profile`"" -ForegroundColor Cyan
                    }
                    
                    Write-Host "    To view connection status: " -NoNewline -ForegroundColor White
                    Write-Host "netsh wlan show interfaces" -ForegroundColor Cyan
                    
                    # Create WiFi profiles directory if it doesn't exist
                    $exportFolder = "C:\wifiprofiles"
                    if (-not (Test-Path -Path $exportFolder -PathType Container)) {
                        Write-Host "    Note: Export folder C:\wifiprofiles must exist before exporting" -ForegroundColor Yellow
                    }
                    
                    Write-Host "    To export this profile: " -NoNewline -ForegroundColor White
                    Write-Host "netsh wlan export profile name=`"$profile`" folder=C:\wifiprofiles" -ForegroundColor Cyan
                }
                else {
                    Write-Host "  No specific certificate information found in profile" -ForegroundColor Yellow
                }
            }
            else {
                $nonCertProfiles += $profile
            }
        }
        
        if ($certBasedProfiles.Count -eq 0) {
            Write-Host "`nNo WiFi profiles using certificate-based authentication found" -ForegroundColor Yellow
            if ($nonCertProfiles.Count -gt 0) {
                Write-Host "Found $($nonCertProfiles.Count) WiFi profiles using other authentication methods" -ForegroundColor White
            }
        }
        else {
            Write-Host "`nSummary:" -ForegroundColor Cyan
            Write-Host "Found $($certBasedProfiles.Count) WiFi profiles using certificate-based authentication" -ForegroundColor Green
            if ($nonCertProfiles.Count -gt 0) {
                Write-Host "Found $($nonCertProfiles.Count) WiFi profiles using other authentication methods" -ForegroundColor White
            }
            
            # Check if any profiles are currently connected
            $connectedProfiles = $profileResults | Where-Object { $_.IsConnected }
            
            if ($connectedProfiles.Count -gt 0) {
                Write-Host "Currently connected to $($connectedProfiles.Count) certificate-based WiFi networks: $($connectedProfiles.Name -join ', ')" -ForegroundColor Green
            }
            else {
                Write-Host "Not currently connected to any certificate-based WiFi networks" -ForegroundColor Yellow
            }
            
            # Show certificate status summary
            $validProfiles = $profileResults | Where-Object { $_.ValidCerts -gt 0 }
            $problemProfiles = $profileResults | Where-Object { $_.HasMatchingCerts -and $_.ValidCerts -eq 0 }
            $noCertProfiles = $profileResults | Where-Object { -not $_.HasMatchingCerts }
            
            if ($validProfiles.Count -gt 0) {
                Write-Host "$($validProfiles.Count) profiles have valid certificates" -ForegroundColor Green
            }
            if ($problemProfiles.Count -gt 0) {
                Write-Host "$($problemProfiles.Count) profiles have matching certificates with issues" -ForegroundColor Yellow
            }
            if ($noCertProfiles.Count -gt 0) {
                Write-Host "$($noCertProfiles.Count) profiles have no matching certificates" -ForegroundColor Red
            }
        }
    }
    catch {
        $errorRecord = $_
        $lineNumber = $errorRecord.InvocationInfo.ScriptLineNumber
        Write-Host "Error checking WiFi profiles: $($errorRecord.Exception.Message) at line $lineNumber" -ForegroundColor Red
        if ($DebugMode) {
            Write-Host "Stack trace: $($errorRecord.ScriptStackTrace)" -ForegroundColor Red
        }
    }
}

# Function to check if running as administrator
function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to show summary of certificates by Root CA
function Show-CertificatesByRootCA {
    if ($Global:AllCertificatesWithPrivateKeys.Count -eq 0) {
        Write-Host "`nNo certificates with private keys found to summarize" -ForegroundColor Yellow
        return
    }
    
    Write-Host "`n===== Certificates by Root CA =====" -ForegroundColor Cyan
    
    # Group certificates by Root CA thumbprint
    $certsByRootCA = $Global:AllCertificatesWithPrivateKeys | Group-Object -Property RootCAThumbprint
    
    foreach ($group in $certsByRootCA) {
        $rootCAThumbprint = $group.Name
        $certs = $group.Group
        
        # Find the Root CA name from the first certificate's chain
        $rootCAName = "Unknown Root CA"
        if ($certs[0].Chain.Count -gt 0) {
            $rootCA = $certs[0].Chain | Where-Object { $_.Thumbprint -eq $rootCAThumbprint }
            if ($rootCA) {
                $rootCAName = $rootCA.Subject
            }
            else {
                # If not found in chain, try the last certificate in the chain
                $lastCert = $certs[0].Chain[$certs[0].Chain.Count - 1]
                if ($lastCert) {
                    $rootCAName = $lastCert.Subject
                }
            }
        }
        
        Write-Host "`nRoot CA: $rootCAName" -ForegroundColor White
        Write-Host "  Thumbprint: $rootCAThumbprint" -ForegroundColor White
        Write-Host "  Client Certificates: $($certs.Count)" -ForegroundColor White
        
        # Group by store type
        $userCerts = $certs | Where-Object { $_.StoreType -eq "User" }
        $machineCerts = $certs | Where-Object { $_.StoreType -eq "Machine" }
        
        Write-Host "  User Store Certificates: $($userCerts.Count)" -ForegroundColor White
        Write-Host "  Machine Store Certificates: $($machineCerts.Count)" -ForegroundColor White
        
        # Count valid vs expired/problematic certificates
        $validCerts = $certs | Where-Object { -not $_.IsExpired -and $_.Issues.Count -eq 0 -and $_.PrivateKeyStatus.Success }
        $expiredCerts = $certs | Where-Object { $_.IsExpired }
        $problemCerts = $certs | Where-Object { -not $_.IsExpired -and ($_.Issues.Count -gt 0 -or -not $_.PrivateKeyStatus.Success) }
        
        Write-Host "  Valid Certificates: $($validCerts.Count)" -ForegroundColor $(if ($validCerts.Count -gt 0) { "Green" } else { "White" })
        Write-Host "  Expired Certificates: $($expiredCerts.Count)" -ForegroundColor $(if ($expiredCerts.Count -gt 0) { "Red" } else { "White" })
        Write-Host "  Problem Certificates: $($problemCerts.Count)" -ForegroundColor $(if ($problemCerts.Count -gt 0) { "Yellow" } else { "White" })
    }
}

# Function to analyze matching certificates for a network profile
function Analyze-MatchingCertificates {
    param (
        [Parameter(Mandatory = $true)]
        [array]$MatchingCertificates,
        [Parameter(Mandatory = $false)]
        [string]$ProfileType = "",
        [Parameter(Mandatory = $false)]
        [string]$ProfileName = "",
        [Parameter(Mandatory = $false)]
        [string]$NetworkType = "network", # "WiFi" or "Wired" or generic "network"
        [Parameter(Mandatory = $false)]
        [hashtable]$CertificateCriteria = @{},
        [Parameter(Mandatory = $false)]
        [array]$TrustedRootCANames = @(),
        [Parameter(Mandatory = $false)]
        [array]$TrustedRootCAThumbprints = @()
    )
    
    $foundInStore = $MatchingCertificates.Count -gt 0
    
    if ($foundInStore) {
        Write-Host "  Certificate Selection Analysis:" -ForegroundColor Cyan
        
        # Group certificates by store type
        $userCerts = $MatchingCertificates | Where-Object { $_.Type -eq "User" }
        $machineCerts = $MatchingCertificates | Where-Object { $_.Type -eq "Machine" }
        
        # Show compatibility with profile type
        $isUserProfile = $ProfileType -eq "All user profile" -or $ProfileType -eq "Per user profile"
        $isMachineProfile = $ProfileType -eq "All user profile" -or $ProfileType -eq "Per device profile"
        
        if ($isUserProfile) {
            Write-Host "    User Profile: Will use certificates from CurrentUser store" -ForegroundColor White
            if ($userCerts.Count -eq 0 -and $machineCerts.Count -gt 0) {
                Write-Host "    WARNING: Found matching certificates only in Machine store, but this is a User profile!" -ForegroundColor Red
                Write-Host "    $NetworkType authentication may fail - consider moving certificate to User store" -ForegroundColor Red
            }
        }
        
        if ($isMachineProfile) {
            Write-Host "    Machine Profile: Will use certificates from LocalMachine store" -ForegroundColor White
            if ($machineCerts.Count -eq 0 -and $userCerts.Count -gt 0) {
                Write-Host "    WARNING: Found matching certificates only in User store, but this is a Machine profile!" -ForegroundColor Red
                Write-Host "    $NetworkType authentication may fail - consider moving certificate to Machine store" -ForegroundColor Red
            }
        }
        
        # Show matching certificates
        Write-Host "    Found $($MatchingCertificates.Count) matching certificates:" -ForegroundColor Green
        
        $validCerts = 0
        $expiredCerts = 0
        $problemCerts = 0
        
        foreach ($certMatch in $MatchingCertificates) {
            $cert = $certMatch.Certificate
            $storeType = $certMatch.Type
            
            $certStatus = Show-CertificateDetails -Certificate $cert -StoreType $storeType `
                -StoreLocation $certMatch.Location -StoreName $certMatch.Store `
                -ProfileType $ProfileType -IndentLevel 2
            
            # Count certificate status
            if ($certStatus.IsExpired) {
                $expiredCerts++
            }
            elseif (-not $certStatus.IsValid -or -not $certStatus.PrivateKeyValid) {
                $problemCerts++
            }
            else {
                $validCerts++
            }
            
            # Show certificate chain info
            $chainResult = Get-CertificateChain -Certificate $cert
            if ($chainResult.Chain.Count -gt 0) {
                Write-Host "      Certificate Chain:" -ForegroundColor White
                foreach ($chainCert in $chainResult.Chain) {
                    Write-Host "        - $($chainCert.Subject)" -ForegroundColor White
                    Write-Host "          Thumbprint: $($chainCert.Thumbprint)" -ForegroundColor White
                }
            }
        }
    }
    else {
        Write-Host "    WARNING: No matching certificates found in certificate stores!" -ForegroundColor Red
        Write-Host "    $NetworkType authentication will fail" -ForegroundColor Red
        
        # Provide more detailed guidance
        Write-Host "    Certificate Selection Criteria:" -ForegroundColor Yellow
        if ($CertificateCriteria.CertName) { 
            Write-Host "      Certificate Name: $($CertificateCriteria.CertName)" -ForegroundColor Yellow 
        }
        if ($CertificateCriteria.CertIssuer) { 
            Write-Host "      Certificate Issuer: $($CertificateCriteria.CertIssuer)" -ForegroundColor Yellow 
        }
        if ($CertificateCriteria.CertSubject) { 
            Write-Host "      Certificate Subject: $($CertificateCriteria.CertSubject)" -ForegroundColor Yellow 
        }
        if ($CertificateCriteria.CertThumbprint) { 
            Write-Host "      Certificate Thumbprint: $($CertificateCriteria.CertThumbprint)" -ForegroundColor Yellow 
        }
        if ($CertificateCriteria.CertThumbprintFromProfile) { 
            Write-Host "      Certificate Thumbprint (from profile): $($CertificateCriteria.CertThumbprintFromProfile)" -ForegroundColor Yellow 
        }
        if ($CertificateCriteria.CertIssuerHash) { 
            Write-Host "      Certificate Issuer Hash: $($CertificateCriteria.CertIssuerHash)" -ForegroundColor Yellow 
        }
        
        # Show trusted root CAs if available
        if ($TrustedRootCANames.Count -gt 0) {
            Write-Host "      Trusted Root CAs:" -ForegroundColor Yellow
            for ($i = 0; $i -lt $TrustedRootCANames.Count; $i++) {
                $rootCAName = $TrustedRootCANames[$i]
                $rootCAThumbprint = if ($i -lt $TrustedRootCAThumbprints.Count) {
                    $TrustedRootCAThumbprints[$i]
                }
                else { "Unknown" }
                
                # Check if this Root CA is installed
                $isInstalled = Test-RootCAInstalled -Subject $rootCAName -Thumbprint $rootCAThumbprint
                
                if ($isInstalled) {
                    Write-Host "        - $rootCAName (Thumbprint: $rootCAThumbprint)" -ForegroundColor Green
                    
                    # Get more information about the CA
                    $caInfo = Get-RootCAInfo -Subject $rootCAName -Thumbprint $rootCAThumbprint
                    if ($caInfo) {
                        Write-Host "          Store: $($caInfo.Store)" -ForegroundColor Yellow
                        
                        # Check expiration
                        $daysUntilExpiry = [math]::Round(($caInfo.NotAfter - (Get-Date)).TotalDays)
                        $expiryStatus = if ($daysUntilExpiry -lt 0) { "EXPIRED" } else { "Valid for $daysUntilExpiry days" }
                        Write-Host "          Expiry: $expiryStatus" -ForegroundColor Yellow
                    }
                }
                else {
                    Write-Host "        - $rootCAName (Thumbprint: $rootCAThumbprint)" -ForegroundColor Red
                    Write-Host "          WARNING: This trusted Root CA is not installed on this device!" -ForegroundColor Red
                    Write-Host "          $NetworkType authentication will fail due to missing Root CA" -ForegroundColor Red
                }
            }
        }
        
        if ($isUserProfile) {
            Write-Host "    This is a User profile - certificate must be in CurrentUser store" -ForegroundColor Yellow
        }
        if ($isMachineProfile) {
            Write-Host "    This is a Machine profile - certificate must be in LocalMachine store" -ForegroundColor Yellow
        }
    }
    
    # Provide troubleshooting guidance
    Write-Host "  Troubleshooting:" -ForegroundColor White
    
    # Add certificate installation guidance if no matching certificates found
    if (-not $foundInStore) {
        Write-Host "    Certificate Installation Guidance:" -ForegroundColor Yellow
        if ($isUserProfile) {
            Write-Host "    - This profile requires a user certificate in the CurrentUser store" -ForegroundColor Yellow
        }
        if ($isMachineProfile) {
            Write-Host "    - This profile requires a machine certificate in the LocalMachine store" -ForegroundColor Yellow
            Write-Host "    - Machine certificates must be installed with administrative privileges" -ForegroundColor Yellow
        }
        Write-Host "    - Consider using EasyScep to request a new certificate: https://easyscep.com" -ForegroundColor Cyan
    }
    
    return @{
        FoundInStore        = $foundInStore
        ValidCertificates   = $validCerts
        ExpiredCertificates = $expiredCerts
        ProblemCertificates = $problemCerts
        TotalCertificates   = $MatchingCertificates.Count
        UserCertificates    = ($MatchingCertificates | Where-Object { $_.Type -eq "User" }).Count
        MachineCertificates = ($MatchingCertificates | Where-Object { $_.Type -eq "Machine" }).Count
    }
}
# Function to display certificate information in a standardized format
function Show-CertificateDetails {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)]
        [string]$StoreType,
        [Parameter(Mandatory = $false)]
        [string]$StoreLocation = "",
        [Parameter(Mandatory = $false)]
        [string]$StoreName = "",
        [Parameter(Mandatory = $false)]
        [string]$ProfileType = "",
        [Parameter(Mandatory = $false)]
        [int]$IndentLevel = 1
    )
    
    $indent = "  " * $IndentLevel
    $storeTypeColor = "White"
    
    # Determine if this certificate is in the right store for the profile type
    if ($ProfileType) {
        $isUserProfile = $ProfileType -eq "All user profile" -or $ProfileType -eq "Per user profile"
        $isMachineProfile = $ProfileType -eq "All user profile" -or $ProfileType -eq "Per device profile"
        
        if (($isUserProfile -and $StoreType -eq "User") -or ($isMachineProfile -and $StoreType -eq "Machine")) {
            $storeTypeColor = "Green"
        }
        else {
            $storeTypeColor = "Yellow"
        }
    }
    
    # Display store information
    $storeInfo = if ($StoreLocation -and $StoreName) {
        "$StoreType Store ($StoreLocation\$StoreName)"
    }
    else {
        "$StoreType Store"
    }
    
    Write-Host "$indent${storeInfo}:" -ForegroundColor $storeTypeColor
    Write-Host "$indent  Subject: $($Certificate.Subject)" -ForegroundColor White
    Write-Host "$indent  Issuer: $($Certificate.Issuer)" -ForegroundColor White
    Write-Host "$indent  Thumbprint: $($Certificate.Thumbprint)" -ForegroundColor White
    Write-Host "$indent  Valid from: $($Certificate.NotBefore) to $($Certificate.NotAfter)" -ForegroundColor White
    
    # Calculate days until expiry
    $daysUntilExpiry = [math]::Round(($Certificate.NotAfter - (Get-Date)).TotalDays)
    $expiryColor = if ($daysUntilExpiry -lt 30) { "Yellow" } elseif ($daysUntilExpiry -lt 0) { "Red" } else { "Green" }
    $expiryStatus = if ($daysUntilExpiry -lt 0) { "EXPIRED" } else { "Valid for $daysUntilExpiry days" }
    Write-Host "$indent  Expiry Status: $expiryStatus" -ForegroundColor $expiryColor
    
    # Check if this certificate will be selected based on profile type
    if ($ProfileType) {
        $willBeSelected = if (($isUserProfile -and $StoreType -eq "User") -or ($isMachineProfile -and $StoreType -eq "Machine")) {
            "Likely to be selected for authentication"
        }
        else {
            "NOT likely to be selected (wrong store type for profile type)"
        }
        Write-Host "$indent  Selection Status: $willBeSelected" -ForegroundColor $storeTypeColor
    }
    
    # Check certificate validity
    $issues = Test-CertificateValidity -Certificate $Certificate
    if ($issues.Count -gt 0) {
        Write-Host "$indent  Certificate issues:" -ForegroundColor Red
        foreach ($issue in $issues) {
            Write-Host "$indent    - $issue" -ForegroundColor Red
        }
    }
    else {
        Write-Host "$indent  Certificate status: Valid" -ForegroundColor Green
    }
    
    # Check private key functionality
    $privateKeyTest = Test-PrivateKeyFunctionality -Certificate $Certificate
    if ($privateKeyTest.Success) {
        Write-Host "$indent  Private Key: $($privateKeyTest.Message)" -ForegroundColor Green
    }
    else {
        Write-Host "$indent  Private Key Issue: $($privateKeyTest.Message)" -ForegroundColor Red
        if ($privateKeyTest.IsTPM) {
            Write-Host "$indent  TPM-related issue detected! Authentication may fail." -ForegroundColor Red
        }
        if ($privateKeyTest.PermissionIssue) {
            Write-Host "$indent  This appears to be a permissions issue. Try running the script as Administrator." -ForegroundColor Yellow
        }
    }
    
    # Return a hashtable with the certificate status information
    return @{
        IsValid          = ($issues.Count -eq 0)
        PrivateKeyValid  = $privateKeyTest.Success
        IsExpired        = ($daysUntilExpiry -lt 0)
        DaysUntilExpiry  = $daysUntilExpiry
        Issues           = $issues
        PrivateKeyStatus = $privateKeyTest
    }
}

# Function to extract certificate criteria from network profiles
function Extract-CertificateCriteria {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ProfileInfo,
        [Parameter(Mandatory = $false)]
        [hashtable]$EAPConfig = $null
    )
    
    $criteria = @{
        CertName                  = ""
        CertIssuer                = ""
        CertThumbprintFromProfile = ""
        CertSubject               = ""
        CertIssuerFromEAP         = ""
        CertThumbprint            = ""
        CertIssuerHash            = ""
        CAHashList                = @()
    }
    
    # Extract from profile output - convert string to array of lines first
    $profileLines = $ProfileInfo -split "`r`n|\r|\n"
    
    # Process each line to find certificate information
    foreach ($line in $profileLines) {
        if ($line -match "Certificate name\s+:\s+(.+)$") {
            $criteria.CertName = $Matches[1].Trim()
        }
        elseif ($line -match "Certificate issuer\s+:\s+(.+)$") {
            $criteria.CertIssuer = $Matches[1].Trim()
        }
        elseif ($line -match "Certificate thumbprint\s+:\s+(.+)$") {
            $criteria.CertThumbprintFromProfile = $Matches[1].Trim()
        }
    }
    
    # If no matches found using regex, try a more direct approach
    if ([string]::IsNullOrEmpty($criteria.CertName) -and 
        [string]::IsNullOrEmpty($criteria.CertIssuer) -and
        [string]::IsNullOrEmpty($criteria.CertThumbprintFromProfile)) {
        
        # Look for lines containing "Certificate name", "Certificate issuer", etc.
        foreach ($line in $profileLines) {
            if ($line.Contains("Certificate name")) {
                $parts = $line.Split(':')
                if ($parts.Length -gt 1) {
                    $criteria.CertName = $parts[1].Trim()
                }
            }
            elseif ($line.Contains("Certificate issuer")) {
                $parts = $line.Split(':')
                if ($parts.Length -gt 1) {
                    $criteria.CertIssuer = $parts[1].Trim()
                }
            }
            elseif ($line.Contains("Certificate thumbprint")) {
                $parts = $line.Split(':')
                if ($parts.Length -gt 1) {
                    $criteria.CertThumbprintFromProfile = $parts[1].Trim()
                }
            }
        }
    }
    
    # Extract from EAP config if available
    if ($EAPConfig) {
        if ($EAPConfig.ClientAuthentication.CertificateSubject) { 
            $criteria.CertSubject = $EAPConfig.ClientAuthentication.CertificateSubject 
        }
        if ($EAPConfig.ClientAuthentication.CertificateIssuer) { 
            $criteria.CertIssuerFromEAP = $EAPConfig.ClientAuthentication.CertificateIssuer 
        }
        if ($EAPConfig.ClientAuthentication.CertificateThumbprint) { 
            $criteria.CertThumbprint = $EAPConfig.ClientAuthentication.CertificateThumbprint 
        }
        if ($EAPConfig.ClientAuthentication.IssuerHash) { 
            $criteria.CertIssuerHash = $EAPConfig.ClientAuthentication.IssuerHash 
        }
        
        # Get additional issuer hashes from CAHashList if available
        if ($EAPConfig.TLSExtensions.FilteringInfo.CAHashList.Count -gt 0) {
            $criteria.CAHashList = $EAPConfig.TLSExtensions.FilteringInfo.CAHashList
        }
    }
    
    if ($DebugMode -or $VerboseDebug) {
        Write-Host "DEBUG: Certificate criteria extracted from profile:" -ForegroundColor Magenta
        Write-Host "DEBUG:   From profile output:" -ForegroundColor Magenta
        Write-Host "DEBUG:     Certificate name: '$($criteria.CertName)'" -ForegroundColor Magenta
        Write-Host "DEBUG:     Certificate issuer: '$($criteria.CertIssuer)'" -ForegroundColor Magenta
        Write-Host "DEBUG:     Certificate thumbprint: '$($criteria.CertThumbprintFromProfile)'" -ForegroundColor Magenta
        if ($EAPConfig) {
            Write-Host "DEBUG:   From EAP config XML:" -ForegroundColor Magenta
            Write-Host "DEBUG:     Certificate subject: '$($criteria.CertSubject)'" -ForegroundColor Magenta
            Write-Host "DEBUG:     Certificate issuer: '$($criteria.CertIssuerFromEAP)'" -ForegroundColor Magenta
            Write-Host "DEBUG:     Certificate thumbprint: '$($criteria.CertThumbprint)'" -ForegroundColor Magenta
            Write-Host "DEBUG:     Certificate issuer hash: '$($criteria.CertIssuerHash)'" -ForegroundColor Magenta
        }
    }
    
    return $criteria
}
# Function to find matching certificates using multiple strategies
function Find-MatchingCertificatesWithMultipleStrategies {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$CertificateCriteria,
        [Parameter(Mandatory = $false)]
        [array]$TrustedRootCAThumbprints = @()
    )
    
    # First attempt: using profile output criteria
    $matchingCerts = Find-MatchingCertificates -Subject $CertificateCriteria.CertName `
        -Issuer $CertificateCriteria.CertIssuer `
        -Thumbprint $CertificateCriteria.CertThumbprintFromProfile `
        -IssuerHash $CertificateCriteria.CertIssuerHash
    
    if ($DebugMode -or $VerboseDebug) {
        Write-Host "DEBUG: First attempt found $($matchingCerts.Count) matching certificates" -ForegroundColor Magenta
    }
    
    # Second attempt: using EAP config criteria if no matches found
    if ($matchingCerts.Count -eq 0 -and ($CertificateCriteria.CertSubject -or 
            $CertificateCriteria.CertIssuerFromEAP -or 
            $CertificateCriteria.CertThumbprint)) {
        if ($DebugMode -or $VerboseDebug) {
            Write-Host "DEBUG: No matches found with profile output criteria. Trying with EAP config criteria..." -ForegroundColor Magenta
        }
        
        $matchingCerts = Find-MatchingCertificates -Subject $CertificateCriteria.CertSubject `
            -Issuer $CertificateCriteria.CertIssuerFromEAP `
            -Thumbprint $CertificateCriteria.CertThumbprint `
            -IssuerHash $CertificateCriteria.CertIssuerHash
        
        if ($DebugMode -or $VerboseDebug) {
            Write-Host "DEBUG: Second attempt found $($matchingCerts.Count) matching certificates" -ForegroundColor Magenta
        }
    }
    
    # Third attempt: using just the thumbprint from profile
    if ($matchingCerts.Count -eq 0 -and $CertificateCriteria.CertThumbprintFromProfile) {
        if ($DebugMode -or $VerboseDebug) {
            Write-Host "DEBUG: No matches found with previous criteria. Trying with just thumbprint from profile..." -ForegroundColor Magenta
        }
        
        $matchingCerts = Find-MatchingCertificates -Subject "" -Issuer "" -Thumbprint $CertificateCriteria.CertThumbprintFromProfile
        
        if ($DebugMode -or $VerboseDebug) {
            Write-Host "DEBUG: Third attempt found $($matchingCerts.Count) matching certificates" -ForegroundColor Magenta
        }
    }
    
    # Fourth attempt: using just the thumbprint from EAP config
    if ($matchingCerts.Count -eq 0 -and $CertificateCriteria.CertThumbprint) {
        if ($DebugMode -or $VerboseDebug) {
            Write-Host "DEBUG: No matches found with previous criteria. Trying with just thumbprint from EAP config..." -ForegroundColor Magenta
        }
        
        $matchingCerts = Find-MatchingCertificates -Subject "" -Issuer "" -Thumbprint $CertificateCriteria.CertThumbprint
        
        if ($DebugMode -or $VerboseDebug) {
            Write-Host "DEBUG: Fourth attempt found $($matchingCerts.Count) matching certificates" -ForegroundColor Magenta
        }
    }
    
    # Fifth attempt: using issuer hashes from CAHashList
    if ($matchingCerts.Count -eq 0 -and $CertificateCriteria.CAHashList.Count -gt 0) {
        if ($DebugMode -or $VerboseDebug) {
            Write-Host "DEBUG: No matches found with previous criteria. Trying with issuer hashes from CAHashList..." -ForegroundColor Magenta
        }
        
        foreach ($hash in $CertificateCriteria.CAHashList) {
            if ($DebugMode -or $VerboseDebug) {
                Write-Host "DEBUG: Trying with hash from CAHashList: $hash" -ForegroundColor Magenta
            }
            
            # Try both as issuer hash and CA thumbprint
            $certsFromIssuerHash = Find-MatchingCertificates -Subject "" -Issuer "" -Thumbprint "" -IssuerHash $hash -TreatHashAsCAThumbprint
            
            if ($certsFromIssuerHash.Count -gt 0) {
                if ($DebugMode -or $VerboseDebug) {
                    Write-Host "DEBUG: Found $($certsFromIssuerHash.Count) certificates with hash $hash" -ForegroundColor Magenta
                }
                $matchingCerts += $certsFromIssuerHash
            }
        }
        
        if ($DebugMode -or $VerboseDebug) {
            Write-Host "DEBUG: CAHashList attempt found $($matchingCerts.Count) matching certificates" -ForegroundColor Magenta
        }
    }
    
    # Sixth attempt: using trusted root CA thumbprints
    if ($matchingCerts.Count -eq 0 -and $TrustedRootCAThumbprints.Count -gt 0) {
        if ($DebugMode -or $VerboseDebug) {
            Write-Host "DEBUG: No matches found with previous criteria. Trying with trusted root CA thumbprints..." -ForegroundColor Magenta
        }
        
        foreach ($rootCAThumbprint in $TrustedRootCAThumbprints) {
            if ($DebugMode -or $VerboseDebug) {
                Write-Host "DEBUG: Searching for certificates issued by Root CA with thumbprint: $rootCAThumbprint" -ForegroundColor Magenta
            }
            
            $certsFromRootCA = Find-MatchingCertificates -Subject "" -Issuer "" -Thumbprint "" -RootCAThumbprint $rootCAThumbprint
            
            if ($certsFromRootCA.Count -gt 0) {
                if ($DebugMode -or $VerboseDebug) {
                    Write-Host "DEBUG: Found $($certsFromRootCA.Count) certificates issued by this Root CA" -ForegroundColor Magenta
                }
                $matchingCerts += $certsFromRootCA
            }
        }
        
        if ($DebugMode -or $VerboseDebug) {
            Write-Host "DEBUG: Root CA thumbprint attempt found $($matchingCerts.Count) matching certificates" -ForegroundColor Magenta
        }
    }
    
    return $matchingCerts
}

# Main script execution - only run if script is not being imported (e.g., by Pester)
# Check if the script is being run directly (not dot-sourced/imported)
if ($MyInvocation.InvocationName -ne '.') {
    # Show promotional banner if not skipped
    if (-not $SkipBanner) {
        Show-PromotionalBanner
    }

    Write-Host "===== Certificate and Network Profile Validation Tool =====" -ForegroundColor Cyan
    Write-Host "Checking certificates with private keys and network profiles (WiFi and wired) using certificates" -ForegroundColor Cyan

    # Check if running as administrator and warn if not
    $isAdmin = Test-Administrator
    if (-not $isAdmin) {
        Write-Host "`nWARNING: Script is not running with administrative privileges." -ForegroundColor Yellow
        Write-Host "Some operations may fail, especially when accessing:" -ForegroundColor Yellow
        Write-Host " - LocalMachine certificate stores" -ForegroundColor Yellow
        Write-Host " - Private keys for certain certificates" -ForegroundColor Yellow
        Write-Host " - Some system WiFi profiles" -ForegroundColor Yellow
        Write-Host "For complete results, consider running this script as Administrator.`n" -ForegroundColor Yellow
    }

    # Clear the global certificate collection
    $Global:AllCertificatesWithPrivateKeys = @()

    # If no Root CA subject is provided and AllRootCAs is not specified, show selection menu
    if (-not $RootCASubject -and -not $AllRootCAs) {
        $RootCASubject = Show-RootCASelectionMenu -ShowAllRootCAs:$ShowAllRootCAs
    }

    if ($RootCASubject) {
        Write-Host "Filtering by Root CA Subject: $RootCASubject" -ForegroundColor Cyan
    }
    else {
        Write-Host "No filtering applied - checking all certificates" -ForegroundColor Cyan
        if ($AllRootCAs) {
            Write-Host "AllRootCAs parameter specified - skipping Root CA selection prompt" -ForegroundColor Cyan
        }
    }

    # Check certificates in Personal store (CurrentUser)
    Check-CertificatesInStore -StoreName "My" -StoreLocation ([System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser) -RootCASubject $RootCASubject -DeleteExpiredCertificates:$DeleteExpiredCertificates -DeleteBrokenCertificates:$DeleteBrokenCertificates

    # Check certificates in Personal store (LocalMachine)
    Check-CertificatesInStore -StoreName "My" -StoreLocation ([System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine) -RootCASubject $RootCASubject -DeleteExpiredCertificates:$DeleteExpiredCertificates -DeleteBrokenCertificates:$DeleteBrokenCertificates

    # Show summary of certificates by Root CA
    Show-CertificatesByRootCA

    # Dump all certificates with private keys if verbose output is enabled
    Dump-AllCertificatesWithPrivateKeys

    # Check WiFi profiles
    Check-WiFiProfiles

    # Check wired (LAN) profiles
    Check-WiredProfiles

    Write-Host "`n===== Certificate and Network Profile Validation Complete =====" -ForegroundColor Cyan
}
else {
    Write-Host "Script is being imported - functions are available for use" -ForegroundColor Cyan
}

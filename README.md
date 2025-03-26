# Certificate and Network Profile Validation Tool

A PowerShell utility for checking and managing certificates with private keys and network profiles (WiFi and wired LAN) that use certificate-based authentication.

## Overview

This tool helps IT administrators diagnose and resolve issues with certificates and WiFi profiles, particularly in enterprise environments where certificate-based authentication is used for network access.

## Features

- **Certificate Validation**: Examines certificates in both user and computer stores that have private keys
- **Private Key Testing**: Verifies that private keys are accessible and functioning correctly
- **Network Profile Analysis**: 
  - Checks WiFi profiles that use certificate-based authentication
  - Checks wired (LAN) 802.1X profiles that use certificate-based authentication
  - Shows which certificates will match and whether user or machine certificates are required
- **TPM Detection**: Identifies certificates stored in the TPM and potential TPM-related issues
- **Certificate Chain Validation**: Validates the entire certificate chain
- **Root CA Filtering**: Option to filter certificates by a specific Root CA
- **Certificate Management**: Options to delete expired or broken certificates with confirmation
- **Root CA Selection**: Interactive menu to select a specific Root CA to filter by
- **Enhanced Error Reporting**: Detailed error messages with line numbers for troubleshooting

## Usage

### Basic Usage

```powershell
.\CheckCertsAndWifi.ps1
```

This will check all certificates with private keys and network profiles, with an interactive prompt to select a Root CA.

### Filter by Root CA

```powershell
.\CheckCertsAndWifi.ps1 -RootCASubject "CN=Contoso Root CA"
```

This will check only certificates issued by the specified Root CA and related network profiles.

### Skip Root CA Selection

```powershell
.\CheckCertsAndWifi.ps1 -AllRootCAs
```

This will check all certificates without prompting for Root CA selection.

### Show All Root CAs in Selection Menu

```powershell
.\CheckCertsAndWifi.ps1 -ShowAllRootCAs
```

By default, only Root CAs issued in 2023 or later are shown in the selection menu. This option shows all Root CAs.

### Delete Expired Certificates

```powershell
.\CheckCertsAndWifi.ps1 -DeleteExpiredCertificates
```

This will check all certificates and prompt to delete any expired certificates found.

### Delete Broken Certificates

```powershell
.\CheckCertsAndWifi.ps1 -DeleteBrokenCertificates
```

This will check all certificates and prompt to delete any certificates with broken private keys.

### Skip Promotional Banner

```powershell
.\CheckCertsAndWifi.ps1 -SkipBanner
```

### Combined Options

```powershell
.\CheckCertsAndWifi.ps1 -RootCASubject "CN=Contoso Root CA" -DeleteExpiredCertificates -SkipBanner
```

## Parameters

| Parameter | Description |
|-----------|-------------|
| `-RootCASubject` | Filter certificates by a specific Root CA subject name |
| `-DeleteExpiredCertificates` | Prompts to delete expired certificates found during the scan |
| `-DeleteBrokenCertificates` | Prompts to delete certificates with broken private keys found during the scan |
| `-SkipBanner` | Skips the promotional banner at startup |
| `-ShowAllRootCAs` | Shows all Root CAs in the selection menu, including those issued before 2023 |
| `-AllRootCAs` | Skips prompting for Root CA selection and checks all certificates |

## Requirements

- Windows 10 or later
- PowerShell 5.1 or later
- Administrative privileges recommended for full functionality

## Best Practices

1. **Run as Administrator**: Some operations require administrative privileges, especially when accessing LocalMachine certificate stores or certain private keys.
2. **Backup Before Deletion**: Always back up your certificates before using the deletion options.
3. **Test in Non-Production**: Test the script in a non-production environment before using it in production.
4. **Filter by Root CA**: For large environments, use the Root CA filtering to focus on specific certificate types.

## Troubleshooting

If you encounter issues:

1. Ensure you're running the script with administrative privileges
2. Check that the certificate stores are accessible
3. Verify that the WiFi profiles are correctly configured
4. Look for specific error messages in the output, which now include line numbers for easier debugging

## About

This tool is developed by Just Software, the creators of EasyScep and EasyRadius, enterprise solutions for certificate management and network authentication.

### Our SaaS Products

- **EasyScep Cloud PKI**: A cloud-based certificate management solution that simplifies the issuance, renewal, and revocation of certificates. Features native integration with Microsoft Intune and works with any SCEP compatible MDM solution. Visit [easyscep.com](https://easyscep.com) for more information.

- **EasyRadius EAP-TLS**: A cloud-based RADIUS service that provides secure WiFi authentication using EAP-TLS without the complexity of managing your own RADIUS infrastructure. Visit [easyradius.com](https://easyradius.com) for more information.

For more information about Just Software, visit [just-software.com](https://just-software.com).

## License

Copyright (c) 2025 Just Software. See LICENSE for details.

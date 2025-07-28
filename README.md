# Certificate Expiration Checker

A PowerShell script that alerts when local certificates will expire within a configurable number of days.

## Features

- Configurable expiration warning period (default: 30 days)
- Option to ignore self-signed certificates
- Filters out certificates expired for a long time (configurable cutoff)
- Ignores certificates with extremely short validity periods
- Integration with NinjaOne custom fields
- Detailed certificate reporting

## Usage

```powershell
.\Certificate-Expiration-Check.ps1
```

### Parameters

- `-DaysUntilExpiration`: Days before expiration to alert (default: 30)
- `-MustBeValidBefore`: Only alert on certificates older than X days (default: 2)
- `-Cutoff`: Don't alert on certificates expired for more than X days (default: 91)
- `-IgnoreSelfSignedCerts`: Ignore self-signed certificates
- `-ExpirationFromCustomField`: Custom field name for expiration days
- `-OutputCustomField`: Custom field name for output (default: "expiredCertificates")

## Requirements

- Windows 7 or Server 2008 minimum
- PowerShell 3.0+ recommended for custom field features
- Administrator privileges for custom field integration

## Example Output

```
Checking for certificates that were valid before 10/10/2023 09:07:23 and will expire before 11/11/2023 09:07:23.

WARNING: Expired Certificates found!

### Expired Certificates ###

SerialNumber                     HasPrivateKey ExpirationDate        Subject
------------                     ------------- --------------        -------
0AA60783EBB5076EBC2D12DA9B04C290         False 6/10/2024 4:59:59 PM  CN=Example.Com LLC
```
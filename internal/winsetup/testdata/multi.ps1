# VPNaaS native Windows IKEv2 setup. No account password is included.
# Run in Windows PowerShell 5.1 as Administrator, using the VPN user's Windows account.
# Review the CA trust below; importing a CA grants system-wide trust.
# Disconnect the VPN before running. Internet stays on the existing local connection.
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$')]
    [string]$ConnectionName = 'VPNaaS-PoC'
)
$ErrorActionPreference = 'Stop'
$answer = Read-Host "Connection name [$ConnectionName] (Enter keeps default)"
if ($answer) { $ConnectionName = $answer }
if ($ConnectionName -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$') {
    throw 'Use 1-64 letters, digits, spaces, dots, underscores or hyphens for the connection name.'
}
$server = 'vpn.example.com'
$serverIdentity = 'vpn.example.com'
$routes = @('10.10.7.0/24', '192.168.1.0/24', '2001:db8::/32', '10.1.2.3/32')
$existing = Get-VpnConnection -Name $ConnectionName -ErrorAction SilentlyContinue
if ($existing -and $existing.ConnectionStatus -ne 'Disconnected') { throw 'Disconnect this VPN before updating it.' }
$caFile = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName() + '.cer')
try {
    [IO.File]::WriteAllBytes($caFile, [Convert]::FromBase64String('ICAtLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0NClFVSkQNClJFVkcKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='))
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($caFile)
    Write-Host "Trusting VPN CA: $($cert.Subject) / SHA1 $($cert.Thumbprint)"
    if ((Read-Host 'Import this CA into LocalMachine Root? Type YES') -cne 'YES') { throw 'CA import cancelled.' }
    Import-Certificate -FilePath $caFile -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    $thumbprint = $cert.Thumbprint
} finally {
    Remove-Item -LiteralPath $caFile -ErrorAction SilentlyContinue
}
$escapedIdentity = [System.Security.SecurityElement]::Escape($serverIdentity)
[xml]$eap = @"
<EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
  <EapMethod><Type xmlns="http://www.microsoft.com/provisioning/EapCommon">26</Type><VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId><VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType><AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId></EapMethod>
  <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig"><Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>26</Type><EapType xmlns="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1"><UseWinLogonCredentials>false</UseWinLogonCredentials></EapType></Eap></Config>
</EapHostConfig>
"@
# IKEv2 validates the gateway certificate against the trusted CA and server address.
if ($existing) {
    Set-VpnConnection -Name $ConnectionName -ServerAddress $server -TunnelType Ikev2 -AuthenticationMethod Eap -EapConfigXmlStream $eap -EncryptionLevel Required -SplitTunneling $true -RememberCredential $false -Force | Out-Null
} else {
    Add-VpnConnection -Name $ConnectionName -ServerAddress $server -TunnelType Ikev2 -AuthenticationMethod Eap -EapConfigXmlStream $eap -EncryptionLevel Required -SplitTunneling $true -RememberCredential $false | Out-Null
}
Set-VpnConnectionIPsecConfiguration -ConnectionName $ConnectionName -AuthenticationTransformConstants SHA256128 -CipherTransformConstants AES256 -EncryptionMethod AES256 -IntegrityCheckMethod SHA256 -DHGroup Group14 -PfsGroup None -Force | Out-Null
# Replace any prior routes (including default routes) with only the allowed networks.
foreach ($route in @((Get-VpnConnection -Name $ConnectionName).Routes)) {
    Remove-VpnConnectionRoute -ConnectionName $ConnectionName -DestinationPrefix $route.DestinationPrefix -Confirm:$false
}
foreach ($prefix in $routes) {
    Add-VpnConnectionRoute -ConnectionName $ConnectionName -DestinationPrefix $prefix | Out-Null
}
Write-Host 'Split tunneling enabled. Only the listed allowed networks use this VPN:'
$routes | ForEach-Object { Write-Host "  $_" }
Write-Host 'Enter your VPN username and password in the Windows connection dialog. No password was stored by this script.'
Start-Process -FilePath "$env:SystemRoot\System32\rasphone.exe" -ArgumentList @('-d', ('"' + $ConnectionName + '"'))

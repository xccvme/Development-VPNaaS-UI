# VPNaaS native Windows IKEv2 setup. No account password is included.
# Run in Windows PowerShell 5.1 as Administrator, using the VPN user's Windows account.
# Review the CA trust below; importing a CA grants system-wide trust.
# Disconnect the VPN before running. Internet stays on the existing local connection.
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9_@.:-][A-Za-z0-9 _@.:-]{0,127}$')]
    [string]$ConnectionName = 'alice'
)
$ErrorActionPreference = 'Stop'
# Stop before prompts, CA import, or VPN changes. This is the VPN profile name,
# not a rename of a physical network adapter. Elevate the same Windows user.
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open Windows PowerShell with Run as Administrator (Jalankan sebagai Administrator), then run this script again. No changes were made.'
}
$answer = Read-Host "Connection name [$ConnectionName] (Enter keeps default)"
if ($answer) { $ConnectionName = $answer }
if ($ConnectionName -notmatch '^[A-Za-z0-9_@.:-][A-Za-z0-9 _@.:-]{0,127}$') {
    throw 'Use 1-128 letters, digits, spaces, dots, underscores, @, colons or hyphens for the VPN profile name.'
}
$server = '192.0.2.10'
$serverIdentity = '192.0.2.10'
$routes = @('10.10.7.0/24')
$existing = Get-VpnConnection -Name $ConnectionName -ErrorAction SilentlyContinue
if ($existing -and $existing.ConnectionStatus -ne 'Disconnected') { throw 'Disconnect this VPN before updating it.' }
$caFile = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName() + '.cer')
try {
    [IO.File]::WriteAllBytes($caFile, [Convert]::FromBase64String('LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tClkyVnlkQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0='))
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

$UpdateSession = New-Object -ComObject 'Microsoft.Update.Session'
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
$SearchResult = $UpdateSearcher.Search("IsInstalled=0 and IsHidden=0")
$ErrorCount = 0

if ( $searchResult.Updates.Count -eq 0 ) {
    return 0
}

$UpdatesToInstall = New-Object -ComObject "Microsoft.Update.UpdateColl"
foreach ( $Update in $SearchResult.Updates ) {
    if ( $Update.InstallationBehavior.CanRequestUserInput -eq $true ) { continue }
    if ( $Update.IsDownloaded -eq $false ) { continue }
    if ( $Update.EulaAccepted -eq $false ) { $Update.AcceptEula() }
    $UpdatesToInstall.Add($Update) | Out-Null
}
if ( $UpdatesToInstall.Count -gt 0 ) {

    $Installer = $UpdateSession.CreateUpdateInstaller()
    $Installer.Updates = $UpdatesToInstall
    $InstallationResult = $Installer.Install()

    0..( $UpdatesToInstall.Count - 1 ) | ForEach-Object {
        $Result = $InstallationResult.GetUpdateResult($PSItem).ResultCode
        if ( $Result -ge 4 ) {
            $ErrorCount++
        }
    }
}
return $ErrorCount

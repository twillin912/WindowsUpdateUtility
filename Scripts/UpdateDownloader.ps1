$UpdateSession = New-Object -ComObject 'Microsoft.Update.Session'
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
$SearchResult = $UpdateSearcher.Search("IsInstalled=0 and IsHidden=0")
$DownloadCount = 0

if ( $searchResult.Updates.Count -eq 0 ) {
    return 0
}

$UpdatesToDownload = New-Object -ComObject "Microsoft.Update.UpdateColl"
foreach ( $Update in $SearchResult.Updates ) {
    if ( $Update.IsDownloaded -eq $false ) {
        $UpdatesToDownload.Add( $Update ) | Out-Null
    }
}
if ( $UpdatesToDownload.Count -gt 0 ) {
    $Downloader = $UpdateSession.CreateUpdateDownloader()
    $Downloader.Updates = $UpdatesToDownload
    $DownloadResult = $Downloader.Download()


    0..( $UpdatesToDownload.Count - 1 ) | ForEach-Object {
        $Result = $DownloadResult.GetUpdateResult( $PSItem ).ResultCode
        if ( $Result -eq 2 -or $Result -eq 3 ) {
            $DownloadCount++
        }
    }
}
return $DownloadCount

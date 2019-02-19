#Proxy Disable

#Possible HEX values of 9th byte (8)
#Decimal value | Hexadecimal value –> Description
#1 | 01 –> All unchecked
#3 | 03 –> Use a Proxy Server…” (2) checked
#9 | 09 –> “Automatically detect settings” (8) checked
#11 | 0b (1+8+2) –> “Automatically detect settings” (8) and “Use a Proxy Server…” (2) checked
#13 | 0d (1+8+4) –> “Automatically detect settings” (8) and “Use Automatic configuration script” (4) checked
#15 | 0f (1+8+4+2) –> All three check box are checked

$RegKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
$Settings = (Get-ItemProperty -Path $RegKey).DefaultConnectionSettings
if ($Settings[8] -ne 1) {
    $Settings[8] = 1
    Set-ItemProperty -path $regKey -name DefaultConnectionSettings -value $Settings
    #msg console /time:3 "Proxy is now disabled"
}
$Settings = (Get-ItemProperty -Path $RegKey).SavedLegacySettings
if ($Settings[8] -ne 1) {
    $Settings[8] = 1
    Set-ItemProperty -path $regKey -name SavedLegacySettings -value $Settings
    #msg console /time:3 "Proxy is now disabled"
}


& bitsadmin /reset /allusers
& netsh winhttp reset proxy
& gpupdate /force
& wuauclt /ResetAuthorization /detectnow
& wuauclt /ReportNow

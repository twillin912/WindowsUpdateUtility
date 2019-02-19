If ([boolean](Get-Command new-netfirewallrule -ErrorAction SilentlyContinue)) {
    Get-NetFirewallRule -DisplayName "RPC Dynamic Ports" | Remove-NetFirewallRule
    $result = New-NetFirewallRule -DisplayName "RPC Dynamic Ports" -Enabled:True -Profile:Domain -Direction:Inbound -Action:Allow -Protocol "TCP" -Program "%systemroot%\system32\dllhost.exe" -LocalPort rpc
    return $result
}
Else {
    & netsh advfirewall firewall delete rule name="RPC Dynamic Ports"
    $Result = & netsh advfirewall firewall add rule name="RPC Dynamic Ports" dir=IN protocol=TCP localport=RPC program="%SystemRoot%\System32\dllhost.exe" remoteip="Any" action=ALLOW
}

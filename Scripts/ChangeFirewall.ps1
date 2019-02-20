If ([boolean](Get-Command Enable-PSRemoting -ErrorAction SilentlyContinue) -and $psversiontable.PSVersion -ge '3.0') {
    #PSVersion 3: Microsoft warning:
    # CAUTION: On systems that have both Windows PowerShell 3.0 and the Windows PowerShell 2.0 engine, do not use Windows
    # PowerShell 2.0 to run the Enable-PSRemoting and Disable-PSRemoting cmdlets. The commands might appear to succeed,
    # but the remoting is not configured correctly. Remote commands, and later attempts to enable and disable remoting, a
    # re likely to fail.
    Enable-PSRemoting -Force -quiet
}
Else {
    & cmd /c winrm quickconfig -force
}

If ([boolean](Get-Command new-netfirewallrule -ErrorAction SilentlyContinue)) {
    Get-NetFirewallRule -DisplayName "RPC Dynamic Ports" | Remove-NetFirewallRule
    Get-NetFirewallRule -DisplayName "*WMI*In*" | Enable-NetFirewallRule
    $result = New-NetFirewallRule -DisplayName "RPC Dynamic Ports" -Enabled:True -Profile:Domain -Direction:Inbound -Action:Allow -Protocol "TCP" -Program "%systemroot%\system32\dllhost.exe" -LocalPort rpc
    return $result
}
Else {
    & netsh advfirewall firewall delete rule name="RPC Dynamic Ports"
    & netsh advfirewall firewall add rule name="RPC Dynamic Ports" dir=IN protocol=TCP localport=RPC program="%SystemRoot%\System32\dllhost.exe" remoteip="Any" action=ALLOW
    & netsh advfirewall firewall set rule group="Windows Management Instrumentation (WMI)" new enable=yes
}

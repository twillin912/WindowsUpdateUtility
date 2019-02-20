## Needs to be tested 
#  I’ve adapted the function to return $true on the first condition that satisfies, 
# since I only care about whether the computer is pending a reboot, 
# and not where the source of the reboot is comping from.
Function Test-PendingReboot {
    Try {
    if ((New-Object -ComObject "Microsoft.Update.SystemInfo").RebootRequired -eq $true)  { return $true }
    }
    Catch {}
    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA SilentlyContinue) { return $true }
    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA SIlentlyContinue) { return $true }
    if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA SilentlyContinue) { return $true }
    try { 
        $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
        $status = $util.DetermineIfRebootPending()
        if (($status -ne $null) -and $status.RebootPending) {
            return $true
        }
        
    }
    catch {}
    return $false
}

Test-PendingReboot
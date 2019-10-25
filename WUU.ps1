<#
.SYNOPSIS
This script provides a GUI for remotely managing Windows Updates.

.DESCRIPTION
This script provides a GUI for remotely managing Windows Updates. You can check for, download, and install updates remotely. There is also an option to automatically reboot the Computer after installing updates if required.

.EXAMPLE
.\WUU.ps1

This example open the Windows Update Utility.

.NOTES
Author: Tyler Siegrist
Date: 12/14/2016

This script needs to be run as an administrator with the credentials of an administrator on the remote Computers.

There is limited feedback on the download and install processes due to Microsoft restricting the ability to remotely download or install Windows Updates. This is done by using psexec to run a script locally on the remote machine.
#>

#region Synchronized collections
$DisplayHash = [hashtable]::Synchronized(@{})
$runspaceHash = [hashtable]::Synchronized(@{})
$Jobs = [system.collections.arraylist]::Synchronized((New-Object System.Collections.ArrayList))
$JobCleanup = [hashtable]::Synchronized(@{})
$UpdatesHash = [hashtable]::Synchronized(@{})
#endregion Synchronized collections

#region Environment validation
#Validate user is an Administrator
Write-Verbose 'Checking Administrator credentials.'
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be elevated!`nNow attempting to elevate."
    Start-Process -Verb 'Runas' -FilePath 'PowerShell.exe' -ArgumentList "-STA -NoProfile -WindowStyle Hidden -File `"$($MyInvocation.MyCommand.Definition)`""
    Break
}

#Ensure that we are running the GUI from the correct location so that scripts & psexec can be accessed.
Set-Location $(Split-Path $MyInvocation.MyCommand.Path)

#Check for PsExec
Write-Verbose 'Checking for psexec.exe.'
if (-Not (Test-Path psexec.exe)) {
    Write-Warning ("Psexec.exe missing from {0}!`n Please place file in the path so WUU can work properly" -f (Split-Path $MyInvocation.MyCommand.Path))
    Break
}

#Determine if this instance of PowerShell can run WPF (required for GUI)
Write-Verbose 'Checking the apartment state.'
if ($host.Runspace.ApartmentState -ne 'STA') {
    Write-Warning "This script must be run in PowerShell started using -STA switch!`nScript will attempt to open PowerShell in STA and run re-run script."
    Start-Process -File PowerShell.exe -Argument "-STA -NoProfile -WindowStyle Hidden -File `"$($myinvocation.mycommand.definition)`""
    Break
}
#endregion Environment validation

#region Load required assemblies
Write-Verbose 'Loading required assemblies.'
Add-Type -assemblyName PresentationFramework
Add-Type -assemblyName PresentationCore
Add-Type -assemblyName WindowsBase
Add-Type -assemblyName Microsoft.VisualBasic
Add-Type -assemblyName System.Windows.Forms
#endregion Load required assemblies

#region Load XAML
Write-Verbose 'Loading XAML data.'
try {
    [xml]$xaml = Get-Content .\WUU.xaml
    $reader = (New-Object System.Xml.XmlNodeReader $xaml)
    $DisplayHash.Window = [Windows.Markup.XamlReader]::Load($reader)
}
catch {
    Write-Warning 'Unable to load XAML data!'
    Break
}
#endregion

#region ScriptBlocks
#Add new Computer(s) to list
$AddEntry = {
    Param ($ComputerName)
    Write-Verbose "Adding $ComputerName."

    if (Test-Path Exempt.txt) {
        Write-Verbose 'Collecting systems from exempt list.'
        [string[]]$exempt = Get-Content Exempt.txt
    }

    #Add to list
    foreach ($Computer in $ComputerName) {
        $Computer = $Computer.Trim() #Remove any whitspace
        if ([System.String]::IsNullOrEmpty($Computer)) {continue} #Do not add if name empty
        if ($exempt -contains $Computer) {continue} #Do not add excluded
        if (($DisplayHash.Listview.Items | Select-Object -Expand Computer) -contains $Computer) {continue} #Do not add duplicate

        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.clientObservable.Add((
                        New-Object PSObject -Property @{
                            Computer       = $Computer
                            Available      = 0 -as [int]
                            Downloaded     = 0 -as [int]
                            InstallErrors  = 0 -as [int]
                            Status         = "Initalizing."
                            RebootRequired = $false -as [bool]
                            Runspace       = $null
                        }))
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })
    }

    #Setup runspace
    ($DisplayHash.Listview.Items | Where-Object {$_.Runspace -eq $Null}) | % {
        $NewRunspace = [runspacefactory]::CreateRunspace()
        $NewRunspace.ApartmentState = "STA"
        $NewRunspace.ThreadOptions = "ReuseThread"
        $NewRunspace.Open()
        $NewRunspace.SessionStateProxy.SetVariable("DisplayHash", $DisplayHash)
        $NewRunspace.SessionStateProxy.SetVariable("UpdatesHash", $UpdatesHash)
        $NewRunspace.SessionStateProxy.SetVariable("path", $pwd)

        $_.Runspace = $NewRunspace

        # $PowerShell = [powershell]::Create().AddScript($GetUpdates).AddArgument($_)
        # $PowerShell.Runspace = $_.Runspace

        # #Save handle so we can later end the runspace
        # $Temp = New-Object PSObject -Property @{
        #     PowerShell = $PowerShell
        #     Runspace   = $PowerShell.BeginInvoke()
        # }

        # $Jobs.Add($Temp) | Out-Null
    }
}

#Clear Computer list
$ClearComputerList = {
    #Remove Computers & associated updates
    &$removeEntry @($DisplayHash.Listview.Items)

    #Update status
    $DisplayHash.StatusTextBox.Dispatcher.Invoke('Background', [action] {
            $DisplayHash.StatusTextBox.Foreground = 'Black'
            $DisplayHash.StatusTextBox.Text = 'Computer List Cleared!'
        })
}

#Download available updates
$DownloadUpdates = {
    Param ($Computer)
    Try {
        #Set path for psexec, scripts
        Set-Location $Path

        #Check download size
        $DownloadStats = ($UpdatesHash[$Computer.Computer] | Where-Object {$_.IsDownloaded -eq $false} | Select-Object -ExpandProperty MaxDownloadSize | Measure-Object -Sum)

        #Update status
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = "Downloading $($DownloadStats.Count) Updates ($([math]::Round($DownloadStats.Sum/1MB))MB)."
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })

        #Copy script to remote Computer and execute
        if ( ! ( Test-Path -Path "\\$($Computer.Computer)\C$\Admin\Scripts") ) {
            New-Item -Path "\\$($Computer.Computer)\C$\Admin\Scripts" -ItemType Directory
        }
        Copy-Item '.\Scripts\UpdateDownloader.ps1' "\\$($Computer.Computer)\c$\Admin\Scripts" -Force
        [int]$DownloadCount = .\PsExec.exe -accepteula -nobanner -s "\\$($Computer.Computer)" cmd.exe /c 'echo . | powershell.exe -ExecutionPolicy Bypass -file C:\Admin\Scripts\UpdateDownloader.ps1'
        Remove-Item "\\$($Computer.Computer)\c$\Admin\Scripts\UpdateDownloader.ps1"
        if ($LASTEXITCODE -ne 0) {
            throw "PsExec failed with error code $LASTEXITCODE"
        }

        #Update status
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = 'Download complete.'
                $Computer.Downloaded += $DownloadCount
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })
    }
    catch {
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = "Error occured: $($_.Exception.Message)"
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })

        #Cancel any remaining actions
        exit
    }
}

#Check for available updates
$GetUpdates = {
    Param ($Computer)
    Try {
        #Update status
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = 'Checking for updates, this may take some time.'
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })

        Set-Location $path

        #Check for updates
        $UpdateSession = [activator]::CreateInstance([type]::GetTypeFromProgID('Microsoft.Update.Session', $Computer.Computer))
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        $SearchResult = $UpdateSearcher.Search('IsInstalled=0 and IsHidden=0')

        #Save update info in hash to view with 'Show Available Updates'
        $UpdatesHash[$Computer.Computer] = $SearchResult.Updates

        #Update status
        $DownloadCount = @($SearchResult.Updates | Where-Object {$_.IsDownloaded -eq $true}).Count
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Available = $SearchResult.Updates.Count
                $Computer.Downloaded = $DownloadCount
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })

        #Don't bother checking for reboot if there is nothing to be pending.
        # if ($DownloadCount -gt 0) {
        #Update status
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = 'Checking for a pending reboot.'
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })

        #Check if there is a pending update

        $rebootRequired = (.\PsExec.exe -accepteula -nobanner -s "\\$($Computer.Computer)" cmd.exe /c 'echo . | powershell.exe -ExecutionPolicy Bypass -Command "&{return (New-Object -ComObject "Microsoft.Update.SystemInfo").RebootRequired}"') -eq $true

        if ($LASTEXITCODE -ne 0) {
            throw "PsExec failed with error code $LASTEXITCODE"
        }

        #Update status
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.RebootRequired = [bool]$rebootRequired
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })
        # }

        #Update status
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = 'Finished checking for updates.'
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })
    }
    catch {
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = "Error occured: $($_.Exception.Message)"
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })

        #Cancel any remaining actions
        exit
    }
}

#Format errors for Out-GridView
$GetErrors = {
    foreach ($err in $error) {
        Switch ($err) {
            {$err -is [System.Management.Automation.ErrorRecord]} {
                $hash = @{
                    Category        = $err.categoryinfo.Category
                    Activity        = $err.categoryinfo.Activity
                    Reason          = $err.categoryinfo.Reason
                    Type            = $err.GetType().ToString()
                    Exception       = ($err.exception -split ': ')[1]
                    QualifiedError  = $err.FullyQualifiedErrorId
                    CharacterNumber = $err.InvocationInfo.OffsetInLine
                    LineNumber      = $err.InvocationInfo.ScriptLineNumber
                    Line            = $err.InvocationInfo.Line
                    TargetObject    = $err.TargetObject
                }
            }
            Default {
                $hash = @{
                    Category        = $err.errorrecord.categoryinfo.category
                    Activity        = $err.errorrecord.categoryinfo.Activity
                    Reason          = $err.errorrecord.categoryinfo.Reason
                    Type            = $err.GetType().ToString()
                    Exception       = ($err.errorrecord.exception -split ': ')[1]
                    QualifiedError  = $err.errorrecord.FullyQualifiedErrorId
                    CharacterNumber = $err.errorrecord.InvocationInfo.OffsetInLine
                    LineNumber      = $err.errorrecord.InvocationInfo.ScriptLineNumber
                    Line            = $err.errorrecord.InvocationInfo.Line
                    TargetObject    = $err.errorrecord.TargetObject
                }
            }
        }
        $object = New-Object PSObject -Property $hash
        $object.PSTypeNames.Insert(0, 'ErrorInformation')
        $object
    }
}

#Install downloaded updates
$InstallUpdates = {
    Param ($Computer)
    Try {
        #Set path for psexec, scripts
        Set-Location $path

        #Update status
        $installCount = ($UpdatesHash[$Computer.Computer] | Where-Object {$_.IsDownloaded -eq $true -and $_.InstallationBehavior.CanRequestUserInput -eq $false} | Measure-Object).Count
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = "Installing $installCount Updates, this may take some time."
                $Computer.InstallErrors = 0
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })

        #Copy script to remote Computer and execute
        if ( ! ( Test-Path -Path "\\$($Computer.Computer)\C$\Admin\Scripts") ) {
            New-Item -Path "\\$($Computer.Computer)\C$\Admin\Scripts" -ItemType Directory
        }
        Copy-Item .\Scripts\UpdateInstaller.ps1 "\\$($Computer.Computer)\C$\Admin\Scripts" -Force
        [int]$installErrors = .\PsExec.exe -accepteula -nobanner -s "\\$($Computer.Computer)" cmd.exe /c 'echo . | powershell.exe -ExecutionPolicy Bypass -file C:\Admin\Scripts\UpdateInstaller.ps1'
        Remove-Item "\\$($Computer.Computer)\C$\Admin\Scripts\UpdateInstaller.ps1"
        if ($LASTEXITCODE -ne 0) {
            throw "PsExec failed with error code $LASTEXITCODE"
        }

        #Update status
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = 'Checking if a reboot is required.'
                $Computer.InstallErrors = $installErrors
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })

        #Check if any updates require reboot
        $rebootRequired = (.\PsExec.exe -accepteula -nobanner -s "\\$($Computer.Computer)" cmd.exe /c 'echo . | powershell.exe -ExecutionPolicy Bypass -Command "&{return (New-Object -ComObject "Microsoft.Update.SystemInfo").RebootRequired}"') -eq $true
        if ($LASTEXITCODE -ne 0) {
            throw "PsExec failed with error code $LASTEXITCODE"
        }

        #Update status
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = 'Install complete.'
                $Computer.RebootRequired = [bool]$rebootRequired
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })
    }
    catch {
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = "Error occured: $($_.Exception.Message)"
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })

        #Cancel any remaining actions
        exit
    }
}

#Remove Computer(s) from list
$RemoveEntry = {
    Param ($Computers)

    #Remove Computers from list
    foreach ($Computer in $Computers) {
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $DisplayHash.clientObservable.Remove($Computer)
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })
    }

    $CleanUp = {
        Param($Computers)
        foreach ($Computer in $Computers) {
            $UpdatesHash.Remove($Computer.Computer)
            $Computer.Runspace.Dispose()
        }
    }

    $NewRunspace = [runspacefactory]::CreateRunspace()
    $NewRunspace.ApartmentState = "STA"
    $NewRunspace.ThreadOptions = "ReuseThread"
    $NewRunspace.Open()
    $NewRunspace.SessionStateProxy.SetVariable("DisplayHash", $DisplayHash)
    $NewRunspace.SessionStateProxy.SetVariable("UpdatesHash", $UpdatesHash)

    $PowerShell = [powershell]::Create().AddScript($CleanUp).AddArgument($Computers)
    $PowerShell.Runspace = $NewRunspace

    #Save handle so we can later end the runspace
    $Temp = New-Object PSObject -Property @{
        PowerShell = $PowerShell
        Runspace   = $PowerShell.BeginInvoke()
    }

    $Jobs.Add($Temp) | Out-Null
}

#Remove Computer that cannot be pinged
$RemoveOfflineComputer = {
    Param ($Computer, $RemoveEntry)
    try {
        #Update status
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = 'Testing Connectivity.'
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })
        #Verify connectivity
        if (Test-Connection -Count 1 -ComputerName $Computer.Computer -Quiet) {
            $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                    $DisplayHash.Listview.Items.EditItem($Computer)
                    $Computer.Status = 'Online.'
                    $DisplayHash.Listview.Items.CommitEdit()
                    $DisplayHash.Listview.Items.Refresh()
                })
        }
        else {
            #Remove unreachable Computers
            $UpdatesHash.Remove($Computer.Computer)
            $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                    $DisplayHash.Listview.Items.EditItem($Computer)
                    $DisplayHash.clientObservable.Remove($Computer)
                    $DisplayHash.Listview.Items.CommitEdit()
                    $DisplayHash.Listview.Items.Refresh()
                })
        }
    }
    catch {
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = "Error occured: $($_.Exception.Message)"
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })

        #Cancel any remaining actions
        exit
    }
}

#Report status to WSUS server
$ReportStatus = {
    Param ($Computer)
    try {
        #Set path for psexec, scripts
        Set-Location $Path

        #Update status
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = 'Reporting status to WSUS server.'
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })

        $ExecStatus = .\PsExec.exe -accepteula -nobanner -s "\\$($Computer.Computer)" cmd.exe /c 'echo . | wuauclt /reportnow'
        if ($LASTEXITCODE -ne 0) {
            throw "PsExec failed with error code $LASTEXITCODE"
        }

        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = 'Finished updating status.'
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })
    }
    catch {
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = "Error occured: $($_.Exception.Message)"
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })

        #Cancel any remaining actions
        exit
    }
}

#Reboot remote Computer
$RestartComputer = {
    Param ($Computer, $afterInstall)
    try {
        #Avoid auto reboot if not enabled and required
        if ($afterInstall -and (-not $Computer.RebootRequired -or -not $DisplayHash.AutoRebootCheckBox.IsChecked)) {return}
        #Update status
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = 'Restarting... Waiting for Computer to shutdown.'
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })

        #Restart and wait until remote COM can be connected
        Restart-Computer $Computer.Computer -Force
        while (Test-Connection -Count 1 -ComputerName $Computer.Computer -Quiet) { Start-Sleep -Milliseconds 500 } #Wait for Computer to go offline

        #Update status
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = 'Restarting... Waiting for Computer to come online.'
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })

        while ($true) {
            #Wait for Computer to come online
            Start-Sleep -Seconds 5
            try {
                [activator]::CreateInstance([type]::GetTypeFromProgID('Microsoft.Update.Session', $Computer.Computer))
                Break
            }
            catch {
                Start-Sleep -Seconds 5
            }
        }
    }
    catch {
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = 'Error occured: $($_.Exception.Message)'
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })

        #Cancel any remaining actions
        exit
    }
}

#Start, stop, or restart Windows Update Service
$WUServiceAction = {
    Param($Computer, $Action)
    try {
        #Start Windows Update Service
        if ($Action -eq 'Start') {
            #Update status
            $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                    $DisplayHash.Listview.Items.EditItem($Computer)
                    $Computer.Status = 'Starting Windows Update Service'
                    $DisplayHash.Listview.Items.CommitEdit()
                    $DisplayHash.Listview.Items.Refresh()
                })

            #Start service
            Get-Service -ComputerName $($Computer.Computer) -Name 'wuauserv' -ErrorAction Stop | Start-Service -ErrorAction Stop

            #Update status
            $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                    $DisplayHash.Listview.Items.EditItem($Computer)
                    $Computer.Status = 'Windows Update Service Started'
                    $DisplayHash.Listview.Items.CommitEdit()
                    $DisplayHash.Listview.Items.Refresh()
                })
        }

        #Stop Windows Update Service
        elseif ($Action -eq 'Stop') {
            #Update status
            $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                    $DisplayHash.Listview.Items.EditItem($Computer)
                    $Computer.Status = 'Stopping Windows Update Service'
                    $DisplayHash.Listview.Items.CommitEdit()
                    $DisplayHash.Listview.Items.Refresh()
                })

            #Stop service
            Get-Service -ComputerName $Computer.Computer -Name wuauserv -ErrorAction Stop | Stop-Service -ErrorAction Stop

            #Update status
            $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                    $DisplayHash.Listview.Items.EditItem($Computer)
                    $Computer.Status = 'Windows Update Service Stopped'
                    $DisplayHash.Listview.Items.CommitEdit()
                    $DisplayHash.Listview.Items.Refresh()
                })
        }

        #Restart Windows Update Service
        elseif ($Action -eq 'Restart') {
            #Update status
            $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                    $DisplayHash.Listview.Items.EditItem($Computer)
                    $Computer.Status = 'Restarting Windows Update Service'
                    $DisplayHash.Listview.Items.CommitEdit()
                    $DisplayHash.Listview.Items.Refresh()
                })

            #Restart service
            Get-Service -ComputerName $Computer.Computer -Name wuauserv -ErrorAction Stop | Restart-Service -ErrorAction Stop

            #Update status
            $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                    $DisplayHash.Listview.Items.EditItem($Computer)
                    $Computer.Status = 'Windows Update Service Restarted'
                    $DisplayHash.Listview.Items.CommitEdit()
                    $DisplayHash.Listview.Items.Refresh()
                })
        }

        #Invalid action
        else {
            Write-Error 'Invalid action specified.'
        }
    }
    catch {
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = "Error occured: $($_.Exception.Message)"
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })

        #Cancel any remaining actions
        exit
    }
}
#endregion ScriptBlocks

#region Background runspace to clean up Jobs
$JobCleanup.Flag = $true
$NewRunspace = [runspacefactory]::CreateRunspace()
$NewRunspace.ApartmentState = 'STA'
$NewRunspace.ThreadOptions = 'ReuseThread'
$NewRunspace.Open()
$NewRunspace.SessionStateProxy.SetVariable('JobCleanup', $JobCleanup)
$NewRunspace.SessionStateProxy.SetVariable('Jobs', $Jobs)
$JobCleanup.PowerShell = [PowerShell]::Create().AddScript( {
        #Routine to handle completed runspaces
        do {
            foreach ($runspace in $Jobs) {
                if ($runspace.Runspace.isCompleted) {
                    $runspace.powershell.EndInvoke($runspace.Runspace) | Out-Null
                    $runspace.powershell.dispose()
                    $runspace.Runspace = $null
                    $runspace.powershell = $null
                    $Jobs.remove($runspace)
                }
            }
            Start-Sleep -Seconds 1
        } while ($JobCleanup.Flag)
    })
$JobCleanup.PowerShell.Runspace = $NewRunspace
$JobCleanup.Thread = $JobCleanup.PowerShell.BeginInvoke()
#endregion

#region Connect to controls
$DisplayHash.ActionMenu = $DisplayHash.Window.FindName('ActionMenu')
$DisplayHash.AddADContext = $DisplayHash.Window.FindName('AddADContext')
$DisplayHash.AddADMenu = $DisplayHash.Window.FindName('AddADMenu')
$DisplayHash.AddComputerContext = $DisplayHash.Window.FindName('AddComputerContext')
$DisplayHash.AddComputerMenu = $DisplayHash.Window.FindName('AddComputerMenu')
$DisplayHash.AddFileContext = $DisplayHash.Window.FindName('AddFileContext')
$DisplayHash.EnableRebootCheckBox = $DisplayHash.Window.FindName('EnableRebootCheckBox')
$DisplayHash.AutoRebootCheckBox = $DisplayHash.Window.FindName('AutoRebootCheckBox')
$DisplayHash.BrowseFileMenu = $DisplayHash.Window.FindName('BrowseFileMenu')
$DisplayHash.CheckUpdatesContext = $DisplayHash.Window.FindName('CheckUpdatesContext')
$DisplayHash.ClearComputerListMenu = $DisplayHash.Window.FindName('ClearComputerListMenu')
$DisplayHash.DownloadUpdatesContext = $DisplayHash.Window.FindName('DownloadUpdatesContext')
$DisplayHash.ExitMenu = $DisplayHash.Window.FindName('ExitMenu')
$DisplayHash.ExportListMenu = $DisplayHash.Window.FindName('ExportListMenu')
$DisplayHash.GridView = $DisplayHash.Window.FindName('GridView')
$DisplayHash.InstallUpdatesContext = $DisplayHash.Window.FindName('InstallUpdatesContext')
$DisplayHash.Listview = $DisplayHash.Window.FindName('Listview')
$DisplayHash.ListviewContextMenu = $DisplayHash.Window.FindName('ListViewContextMenu')
$DisplayHash.OfflineHostsMenu = $DisplayHash.Window.FindName('OfflineHostsMenu')
$DisplayHash.RemoteDesktopContext = $DisplayHash.Window.FindName('RemoteDesktopContext')
$DisplayHash.RemoveComputerContext = $DisplayHash.Window.FindName('RemoveComputerContext')
$DisplayHash.ReportStatusContext = $DisplayHash.Window.FindName('ReportStatusContext')
$DisplayHash.RestartContext = $DisplayHash.Window.FindName('RestartContext')
$DisplayHash.SelectAllMenu = $DisplayHash.Window.FindName('SelectAllMenu')
$DisplayHash.ShowInstalledContext = $DisplayHash.Window.FindName('ShowInstalledContext')
$DisplayHash.ShowUpdatesContext = $DisplayHash.Window.FindName('ShowUpdatesContext')
$DisplayHash.StatusTextBox = $DisplayHash.Window.FindName('StatusTextBox')
$DisplayHash.UpdateHistoryMenu = $DisplayHash.Window.FindName('UpdateHistoryMenu')
$DisplayHash.ViewErrorMenu = $DisplayHash.Window.FindName('ViewErrorMenu')
$DisplayHash.ViewUpdateLogContext = $DisplayHash.Window.FindName('ViewUpdateLogContext')
$DisplayHash.WindowsUpdateServiceMenu = $DisplayHash.Window.FindName('WindowsUpdateServiceMenu')
$DisplayHash.WURestartServiceMenu = $DisplayHash.Window.FindName('WURestartServiceMenu')
$DisplayHash.WUStartServiceMenu = $DisplayHash.Window.FindName('WUStartServiceMenu')
$DisplayHash.WUStopServiceMenu = $DisplayHash.Window.FindName('WUStopServiceMenu')
#endregion Connect to controls

#region Event ScriptBlocks
$eventWindowInit = { #Runs before opening window
    $Script:SortHash = @{}

    #Sort event handler
    [System.Windows.RoutedEventHandler]$Global:ColumnSortHandler = {
        if ($_.OriginalSource -is [System.Windows.Controls.GridViewColumnHeader]) {
            Write-Verbose ('{0}' -f $_.Originalsource.getType().FullName)
            if ($_.OriginalSource -AND $_.OriginalSource.Role -ne 'Padding') {
                $Column = $_.Originalsource.Column.DisplayMemberBinding.Path.Path
                Write-Debug ('Sort: {0}' -f $Column)
                if ($SortHash[$Column] -eq 'Ascending') {
                    $SortHash[$Column] = 'Descending'
                }
                else {
                    $SortHash[$Column] = 'Ascending'
                }
                $lastColumnsort = $Column
                $DisplayHash.Listview.Items.SortDescriptions.clear()
                Write-Verbose ('Sorting {0} by {1}' -f $Column, $SortHash[$Column])
                $DisplayHash.Listview.Items.SortDescriptions.Add((New-Object System.ComponentModel.SortDescription $Column, $SortHash[$Column]))
                $DisplayHash.Listview.Items.Refresh()
            }
        }
    }
    $DisplayHash.Listview.AddHandler([System.Windows.Controls.GridViewColumnHeader]::ClickEvent, $ColumnSortHandler)

    #Create and bind the observable collection to the GridView
    $DisplayHash.clientObservable = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    $DisplayHash.ListView.ItemsSource = $DisplayHash.clientObservable
}
$eventWindowClose = { #Runs when WUU closes
    #Halt job processing
    $JobCleanup.Flag = $false

    #Stop all runspaces
    $JobCleanup.PowerShell.Dispose()

    #Cleanup
    [gc]::Collect()
    [gc]::WaitForPendingFinalizers()
}
$eventActionMenu = { #Enable/disable action menu items
    $DisplayHash.ClearComputerListMenu.IsEnabled = ($DisplayHash.Listview.Items.Count -gt 0)
    $DisplayHash.OfflineHostsMenu.IsEnabled = ($DisplayHash.Listview.Items.Count -gt 0)
    $DisplayHash.ViewErrorMenu.IsEnabled = ($Error.Count -gt 0)
}
$eventAddAD = { #Add Computers from Active Directory
    #region OUPicker
    $OUPickerHash = [hashtable]::Synchronized(@{})
    try {
        [xml]$xaml = Get-Content .\OUPicker.xaml
        $reader = (New-Object System.Xml.XmlNodeReader $xaml)
        $OUPickerHash.Window = [Windows.Markup.XamlReader]::Load($reader)
    }
    catch {
        Write-Warning 'Unable to load XAML data for OUPicker!'
        return
    }

    $OUPickerHash.OKButton = $OUPickerHash.Window.FindName('OKButton')
    $OUPickerHash.CancelButton = $OUPickerHash.Window.FindName('CancelButton')
    $OUPickerHash.OUTree = $OUPickerHash.Window.FindName('OUTree')

    $OUPickerHash.OKButton.Add_Click( {$OUPickerHash.SelectedOU = $OUPickerHash.OUTree.SelectedItem.Tag; $OUPickerHash.Window.Close()})
    $OUPickerHash.CancelButton.Add_Click( {$OUPickerHash.Window.Close()})

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher
    $Searcher.Filter = "(objectCategory=organizationalUnit)"
    $Searcher.SearchScope = "OneLevel"

    $rootItem = New-Object System.Windows.Controls.TreeViewItem
    $rootItem.Header = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $rootItem.Tag = $Searcher.SearchRoot.distinguishedName

    function Populate-Children($node) {
        $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($node.Tag)")
        $Searcher.FindAll() | % {
            $childItem = New-Object System.Windows.Controls.TreeViewItem
            $childItem.Header = $_.Properties.name[0]
            $childItem.Tag = $_.Properties.distinguishedname
            Populate-Children($childItem)
            $node.AddChild($childItem)
        }
    }
    Populate-Children($rootItem)
    $OUPickerHash.OUTree.AddChild($rootItem)

    $OUPickerHash.Window.ShowDialog() | Out-Null
    #endregion

    #Verify user didn't hit 'cancel' before processing
    if ($OUPickerHash.SelectedOU) {
        #Update status
        $DisplayHash.StatusTextBox.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.StatusTextBox.Foreground = 'Black'
                $DisplayHash.StatusTextBox.Text = 'Querying Active Directory for Computers...'
            })

        #Search LDAP path
        $Searcher = [adsisearcher]''
        $Searcher.SearchRoot = [adsi]"LDAP://$($OUPickerHash.SelectedOU)"
        $Searcher.Filter = ('(&(objectCategory=Computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))')
        $Searcher.PropertiesToLoad.Add('name') | Out-Null
        $Results = $Searcher.FindAll()
        if ($Results) {
            #Add Computers found
            &$AddEntry ($Results | % {$_.Properties.name})

            #Update status
            $DisplayHash.StatusTextBox.Dispatcher.Invoke('Background', [action] {
                    $DisplayHash.StatusTextBox.Text = "Successfully Imported $($Results.Count) Computers from Active Directory."
                })
        }
        else {
            #Update status
            $DisplayHash.StatusTextBox.Dispatcher.Invoke('Background', [action] {
                    $DisplayHash.StatusTextBox.Foreground = 'Red'
                    $DisplayHash.StatusTextBox.Text = 'No Computers found, verify LDAP path...'
                })
        }
    }
}
$eventAddComputer = { #Add Computers by typing them in manually
    #Open prompt
    $Computer = [Microsoft.VisualBasic.Interaction]::InputBox('Enter a Computer name or names. Separate Computers with a comma (,) or semi-colon (;).', 'Add Computer(s)')

    #Verify Computers were input
    if (-Not [System.String]::IsNullOrEmpty($Computer)) {
        [string[]]$Computername = $Computer -split ',|;' #Parse
    }
    if ($Computername) {&$AddEntry $Computername} #Add Computers
}
$eventAddFile = { #Add Computers from a file
    #Open file dialog
    $dlg = new-object microsoft.win32.OpenFileDialog
    $dlg.DefaultExt = '*.txt'
    $dlg.Filter = 'Text Files |*.txt;*.csv'
    $dlg.Multiselect = $true
    $dlg.InitialDirectory = $pwd
    [void]$dlg.showdialog()
    $Files = $dlg.FileNames

    foreach ($File in $Files)
    {
        #Verify file was selected
        if (-Not ([system.string]::IsNullOrEmpty($File))) {
            $entries = (Get-Content $File | Where {$_ -ne ''}) #Parse
            &$AddEntry $entries #Add Computers

            #Update Status
            $DisplayHash.StatusTextBox.Dispatcher.Invoke('Background', [action] {
                    $DisplayHash.StatusTextBox.Foreground = 'Black'
                    $DisplayHash.StatusTextBox.Text = "Successfully Added $($entries.Count) Computers from $File."
                })
        }
    }
}
$eventGetUpdates = {
    $DisplayHash.Listview.SelectedItems | % {
        $Temp = "" | Select-Object PowerShell, Runspace
        $Temp.PowerShell = [powershell]::Create().AddScript($GetUpdates).AddArgument($_)
        $Temp.PowerShell.Runspace = $_.Runspace
        $Temp.Runspace = $Temp.PowerShell.BeginInvoke()
        $Jobs.Add($Temp) | Out-Null
    }
}
$eventDownloadUpdates = {
    $DisplayHash.Listview.SelectedItems | % {
        #Don't bother downloading if nothing available.
        if ($_.Available -eq $_.Downloaded) {
            #Update status
            $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                    $DisplayHash.Listview.Items.EditItem($_)
                    $_.Status = 'There are no updates available to download.'
                    $DisplayHash.Listview.Items.CommitEdit()
                    $DisplayHash.Listview.Items.Refresh()
                })
            return
        }

        $Temp = "" | Select-Object PowerShell, Runspace
        $Temp.PowerShell = [powershell]::Create().AddScript($DownloadUpdates).AddArgument($_)
        $Temp.PowerShell.Runspace = $_.Runspace
        $Temp.Runspace = $Temp.PowerShell.BeginInvoke()
        $Jobs.Add($Temp) | Out-Null
    }
}
$eventInstallUpdates = {
    $DisplayHash.Listview.SelectedItems | % {
        #Check if there are any updates that are downloaded and don't require user input
        if (-not ($UpdatesHash[$_.Computer] | Where-Object {$_.IsDownloaded -and $_.InstallationBehavior.CanRequestUserInput -eq $false})) {
            #Update status
            $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                    $DisplayHash.Listview.Items.EditItem($_)
                    $_.Status = 'There are no updates available that can be installed remotely.'
                    $DisplayHash.Listview.Items.CommitEdit()
                    $DisplayHash.Listview.Items.Refresh()
                })

            #No need to continue if there are no updates to install.
            return
        }

        $Temp = "" | Select-Object PowerShell, Runspace
        $Temp.PowerShell = [powershell]::Create().AddScript($InstallUpdates).AddArgument($_)
        # $Temp.PowerShell.AddScript($RestartComputer).AddArgument($_).AddArgument($true)
        # $Temp.PowerShell.AddScript($GetUpdates).AddArgument($_)
        $Temp.PowerShell.Runspace = $_.Runspace
        $Temp.Runspace = $Temp.PowerShell.BeginInvoke()
        $Jobs.Add($Temp) | Out-Null
    }
}
$eventRemoveOfflineComputer = {
    $DisplayHash.Listview.Items | % {
        $Temp = "" | Select-Object PowerShell, Runspace
        $Temp.PowerShell = [powershell]::Create().AddScript($RemoveOfflineComputer).AddArgument($_).AddArgument($RemoveEntry)
        $Temp.PowerShell.Runspace = $_.Runspace
        $Temp.Runspace = $Temp.PowerShell.BeginInvoke()
        $Jobs.Add($Temp) | Out-Null
    }
}
$eventRestartComputer = {
    $DisplayHash.Listview.SelectedItems | % {
        $Temp = "" | Select-Object PowerShell, Runspace
        $Temp.PowerShell = [powershell]::Create().AddScript($RestartComputer).AddArgument($_).AddArgument($false)
        $Temp.PowerShell.AddScript($GetUpdates).AddArgument($_)
        $Temp.PowerShell.Runspace = $_.Runspace
        $Temp.Runspace = $Temp.PowerShell.BeginInvoke()
        $Jobs.Add($Temp) | Out-Null
    }
}
$eventReportStatus = {
    $DisplayHash.Listview.SelectedItems | % {
        $Temp = "" | Select-Object PowerShell, Runspace
        $Temp.PowerShell = [powershell]::Create().AddScript($ReportStatus).AddArgument($_)
        $Temp.PowerShell.Runspace = $_.Runspace
        $Temp.Runspace = $Temp.PowerShell.BeginInvoke()
        $Jobs.Add($Temp) | Out-Null
    }
}
$eventKeyDown = {
    if ([System.Windows.Input.Keyboard]::IsKeyDown('RightCtrl') -OR [System.Windows.Input.Keyboard]::IsKeyDown('LeftCtrl')) {
        Switch ($_.Key) {
            'A' {$DisplayHash.Listview.SelectAll()}
            'O' {&$eventAddFile}
            'S' {&$eventSaveComputerList}
            Default {$Null}
        }
    }
    elseif ($_.Key -eq 'Delete') {&$removeEntry @($DisplayHash.Listview.SelectedItems)}
}
$eventRightClick = {
    #Set default values
    $DisplayHash.RemoveComputerContext.IsEnabled = $false
    $DisplayHash.RemoteDesktopContext.IsEnabled = $false
    $DisplayHash.CheckUpdatesContext.IsEnabled = $false
    $DisplayHash.DownloadUpdatesContext.IsEnabled = $false
    $DisplayHash.InstallUpdatesContext.IsEnabled = $false
    $DisplayHash.RestartContext.IsEnabled = $false
    $DisplayHash.ReportStatusContext.IsEnabled = $false
    $DisplayHash.ShowInstalledContext.IsEnabled = $false
    $DisplayHash.ShowUpdatesContext.IsEnabled = $false
    $DisplayHash.UpdateHistoryMenu.IsEnabled = $false
    $DisplayHash.ViewUpdateLogContext.IsEnabled = $false
    $DisplayHash.WindowsUpdateServiceMenu.IsEnabled = $false
    if ($DisplayHash.Listview.SelectedItems.count -eq 1) {
        $DisplayHash.RemoteDesktopContext.IsEnabled = $true
        $DisplayHash.ShowInstalledContext.IsEnabled = $true
        $DisplayHash.ShowUpdatesContext.IsEnabled = $true
        $DisplayHash.UpdateHistoryMenu.IsEnabled = $true
        $DisplayHash.ViewUpdateLogContext.IsEnabled = $true
    }
    if ($DisplayHash.Listview.SelectedItems.count -ge 1) {
        $DisplayHash.RemoveComputerContext.IsEnabled = $true
        $DisplayHash.CheckUpdatesContext.IsEnabled = $true
        $DisplayHash.DownloadUpdatesContext.IsEnabled = $true
        $DisplayHash.ReportStatusContext.IsEnabled = $true
        $DisplayHash.WindowsUpdateServiceMenu.IsEnabled = $true
    }

    if ($DisplayHash.Listview.SelectedItems.count -ge 1 -and
        $DisplayHash.EnableRebootCheckBox.IsChecked -eq $true) {
        $DisplayHash.InstallUpdatesContext.IsEnabled = $true
        $DisplayHash.RestartContext.IsEnabled = $true
    }
}
$eventSaveComputerList = {
    if ($DisplayHash.Listview.Items.count -gt 0) {
        #Save dialog
        $dlg = new-object Microsoft.Win32.SaveFileDialog
        $dlg.FileName = 'Computer List'
        $dlg.DefaultExt = '*.txt'
        $dlg.Filter = 'Text files (*.txt)|*.txt|CSV files (*.csv)|*.csv'
        $dlg.InitialDirectory = $pwd
        [void]$dlg.showdialog()
        $filePath = $dlg.FileName

        #Verify file was selected
        if (-Not ([system.string]::IsNullOrEmpty($filepath))) {
            #Save file
            $DisplayHash.Listview.Items | Select -Expand Computer | Out-File $filePath -Force

            #Update status
            $DisplayHash.StatusTextBox.Dispatcher.Invoke('Background', [action] {
                    $DisplayHash.StatusTextBox.Foreground = 'Black'
                    $DisplayHash.StatusTextBox.Text = "Computer List saved to $filePath"
                })
        }
    }
    else {
        #No items selected
        #Update status
        $DisplayHash.StatusTextBox.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.StatusTextBox.Foreground = 'Red'
                $DisplayHash.StatusTextBox.Text = 'Computer List not saved, there are no Computers in the list!'
            })
    }
}
$eventShowAvailableUpdates = {
    foreach ($Computer in $DisplayHash.Listview.SelectedItems) {
        $UpdatesHash[$Computer.Computer] | Select Title, Description, IsDownloaded, IsMandatory, IsUninstallable, @{n = 'CanRequestUserInput'; e = {$_.InstallationBehavior.CanRequestUserInput}}, LastDeploymentChangeTime, @{n = 'MaxDownloadSize (MB)'; e = {'{0:N2}' -f ($_.MaxDownloadSize / 1MB)}}, @{n = 'MinDownloadSize (MB)'; e = {'{0:N2}' -f ($_.MinDownloadSize / 1MB)}}, RecommendedCpuSpeed, RecommendedHardDiskSpace, RecommendedMemory, DriverClass, DriverManufacturer, DriverModel, DriverProvider, DriverVerDate | Out-GridView -Title "$($Computer.Computer)'s Available Updates"
    }
}
$eventShowInstalledUpdates = {
    foreach ($Computer in $DisplayHash.Listview.SelectedItems) {
        $UpdateSession = [activator]::CreateInstance([type]::GetTypeFromProgID('Microsoft.Update.Session', $Computer.Computer))
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        $UpdateSearcher.Search('IsInstalled=1').Updates | Select Title, Description, IsUninstallable, SupportUrl | Out-GridView -Title "$($Computer.Computer)'s Installed Updates"
    }
}
$eventShowUpdateHistory = {
    Try {
        $Computer = $DisplayHash.Listview.SelectedItems | Select -First 1
        #Get installed hotfix, create popup
        $UpdateSession = [activator]::CreateInstance([type]::GetTypeFromProgID('Microsoft.Update.Session', $Computer.Computer))
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        $updates = $updateSearcher.QueryHistory(1, $updateSearcher.GetTotalHistoryCount())
        $updates | Select-Object -Property `
        @{name = "Operation"; expression = {switch ($_.Operation) {1 {"Installation"}; 2 {"Uninstallation"}; 3 {"Other"}}}}, `
        @{name = "Result"; expression = {switch ($_.ResultCode) {1 {"Success"}; 2 {"Success (reboot required)"}; 4 {"Failure"}}}}, `
        @{n = 'HResult'; e = {'0x' + [Convert]::ToString($_.HResult, 16)}}, `
            Date, Title, Description, SupportUrl | Out-GridView -Title "$($Computer.Computer)'s Update History"
    }
    catch {
        $DisplayHash.ListView.Dispatcher.Invoke('Background', [action] {
                $DisplayHash.Listview.Items.EditItem($Computer)
                $Computer.Status = "Error Occured: $($_.exception.Message)"
                $DisplayHash.Listview.Items.CommitEdit()
                $DisplayHash.Listview.Items.Refresh()
            })
    }
}
$eventViewUpdateLog = {
    $DisplayHash.Listview.SelectedItems | % {
        &"\\$($_.Computer)\c$\windows\windowsupdate.log"
    }
}
$eventWUServiceAction = {
    Param ($Action)
    $DisplayHash.Listview.SelectedItems | % {
        $Temp = "" | Select-Object PowerShell, Runspace
        $Temp.PowerShell = [powershell]::Create().AddScript($WUServiceAction).AddArgument($_).AddArgument($Action)
        $Temp.PowerShell.Runspace = $_.Runspace
        $Temp.Runspace = $Temp.PowerShell.BeginInvoke()
        $Jobs.Add($Temp) | Out-Null
    }
}
#endregion Event ScriptBlocks

#region Event Handlers
$DisplayHash.ActionMenu.Add_SubmenuOpened($eventActionMenu) #Action Menu
$DisplayHash.AddADContext.Add_Click($eventAddAD) #Add Computers From AD (Context)
$DisplayHash.AddADMenu.Add_Click($eventAddAD) #Add Computers From AD (Menu)
$DisplayHash.AddComputerContext.Add_Click($eventAddComputer) #Add Computers (Context)
$DisplayHash.AddComputerMenu.Add_Click($eventAddComputer) #Add Computers (Menu)
$DisplayHash.AddFileContext.Add_Click($eventAddFile) #Add Computers From File (Context)
$DisplayHash.BrowseFileMenu.Add_Click($eventAddFile) #Add Computers From File (Menu)
$DisplayHash.CheckUpdatesContext.Add_Click($eventGetUpdates) #Check For Updates (Context)
$DisplayHash.ClearComputerListMenu.Add_Click($clearComputerList) #Clear Computer List
$DisplayHash.DownloadUpdatesContext.Add_Click($eventDownloadUpdates) #Download Updates
$DisplayHash.ExitMenu.Add_Click( {$DisplayHash.Window.Close()}) #Exit
$DisplayHash.UpdateHistoryMenu.Add_Click($eventShowUpdateHistory) #Get Update History
$DisplayHash.ExportListMenu.Add_Click($eventSaveComputerList) #Exports Computer To File
$DisplayHash.InstallUpdatesContext.Add_Click($eventInstallUpdates) #Install Updates
$DisplayHash.Listview.Add_MouseRightButtonUp($eventRightClick) #On Right Click
$DisplayHash.OfflineHostsMenu.Add_Click($eventRemoveOfflineComputer) #Remove Offline Computers
$DisplayHash.RemoteDesktopContext.Add_Click( {mstsc.exe /v $DisplayHash.Listview.SelectedItems.Computer}) #RDP
$DisplayHash.RemoveComputerContext.Add_Click( {&$removeEntry @($DisplayHash.Listview.SelectedItems)}) #Delete Computers
$DisplayHash.RestartContext.Add_Click($eventRestartComputer) #Restart Computer
$DisplayHash.ReportStatusContext.Add_Click($eventReportStatus) #Report to WSUS
$DisplayHash.SelectAllMenu.Add_Click( {$DisplayHash.Listview.SelectAll()}) #Select All
$DisplayHash.ShowUpdatesContext.Add_Click($eventShowAvailableUpdates) #Show Available Updates
$DisplayHash.ShowInstalledContext.Add_Click($eventShowInstalledUpdates) #Show Installed Updates
$DisplayHash.ViewUpdateLogContext.Add_Click($eventViewUpdateLog) #Show Installed Updates
$DisplayHash.Window.Add_Closed($eventWindowClose) #On Window Close
$DisplayHash.Window.Add_SourceInitialized($eventWindowInit) #On Window Open
$DisplayHash.Window.Add_KeyDown($eventKeyDown) #On key down
$DisplayHash.WURestartServiceMenu.Add_Click( {&$eventWUServiceAction 'Restart'}) #Restart Windows Update Service
$DisplayHash.WUStartServiceMenu.Add_Click( {&$eventWUServiceAction 'Start'}) #Start Windows Update Service
$DisplayHash.WUStopServiceMenu.Add_Click( {&$eventWUServiceAction 'Stop'}) #Stop Windows Update Service
$DisplayHash.ViewErrorMenu.Add_Click( {&$GetErrors | Out-GridView}) #View Errors
#endregion

#Start the GUI
$DisplayHash.Window.ShowDialog() | Out-Null

# .ExternalHelp Microsoft.SystemCenter.OperationsManagerV10.Commands.dll-Help.xml
function Get-SCOMCommand
{
    [CmdletBinding(DefaultParameterSetName='CmdletSet')]
    param(
    [Parameter(ParameterSetName='AllCommandSet', Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [ValidateNotNullOrEmpty()]
    [System.String[]]
    ${Name},

    [Parameter(ParameterSetName='CmdletSet', ValueFromPipelineByPropertyName=$true)]
    [System.String[]]
    ${Verb},

    [Parameter(ParameterSetName='CmdletSet', ValueFromPipelineByPropertyName=$true)]
    [System.String[]]
    ${Noun},
   
    [Parameter(ParameterSetName='AllCommandSet', ValueFromPipelineByPropertyName=$true)]
    [Alias('Type')]
    [System.Management.Automation.CommandTypes]
    ${CommandType})
    
    process {
        Get-Command @psboundParameters -Module OperationsManager
    }
}

# .ExternalHelp Microsoft.SystemCenter.OperationsManagerV10.Commands.dll-Help.xml
function Write-SCOMCommand
{
    [CmdletBinding(DefaultParameterSetName='Name')]
    param(    
    [Parameter(Mandatory=$true,ParameterSetName='Name')]
    [String]$Name,
    [Parameter(Mandatory=$true,ParameterSetName='NoName')]
    [Switch]$NoName    
    )
    
    process {
        if ($psCmdlet.ParameterSetName -eq 'Name') {
@"
function $Name {
    param(
    [ValidateNotNullOrEmpty()]
    [Microsoft.SystemCenter.Core.Connection.Connection[]]
    `${SCSession},

    [ValidateNotNullOrEmpty()]
    [System.String[]]
    `${ComputerName},
    
    [System.Management.Automation.PSCredential]
    `${Credential}
    )
    
    process {
        `$managementGroupParameters = @{} + `$psBoundParameters
        foreach (`$k in @(`$managementGroupParameters.Keys)) {
            if ('SCSession', 'ComputerName', 'Credential' -notcontains `$k) {
                `$null = `$managementGroupParameters.Remove(`$k)
            }
        }
        
        `$Group = Get-SCOMManagementGroup @managementGroupParameters
        `$connection = [Microsoft.SystemCenter.OperationsManagerV10.Commands.OMV10Utility]::GetConnectionForManagementGroup(`$Group)        
        # Use `$group to work with the SCOM API: http://msdn.microsoft.com/en-us/library/microsoft.enterprisemanagement.managementgroup.aspx
    }
}
"@
        } else {
@"
param(
[ValidateNotNullOrEmpty()]
[Microsoft.SystemCenter.Core.Connection.Connection[]]
`${SCSession},

[ValidateNotNullOrEmpty()]
[System.String[]]
`${ComputerName},

[System.Management.Automation.PSCredential]
`${Credential}
)

`$managementGroupParameters = @{} + `$psBoundParameters
foreach (`$k in @(`$managementGroupParameters.Keys)) {
    if ('SCSession', 'ComputerName', 'Credential' -notcontains `$k) {
        `$null = `$managementGroupParameters.Remove(`$k)
    }
}

`$Group = Get-SCOMManagementGroup @managementGroupParameters
`$connection = [Microsoft.SystemCenter.OperationsManagerV10.Commands.OMV10Utility]::GetConnectionForManagementGroup(`$Group)        
# Use `$group to work with the SCOM API: http://msdn.microsoft.com/en-us/library/microsoft.enterprisemanagement.managementgroup.aspx
"@
        }
    }
}

# .ExternalHelp Microsoft.SystemCenter.OperationsManagerV10.Commands.dll-Help.xml
function Add-SCOMRunAsAccount
{
    [CmdletBinding(DefaultParameterSetName='Windows', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(

    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName = 'Windows')]
    [Switch]
    ${Windows},

    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName = 'CommunityString')]
    [Switch]
    ${CommunityString},

    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName = 'Basic')]
    [Switch]
    ${Basic},

    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName = 'Digest')]
    [Switch]
    ${Digest},

    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName = 'Simple')]
    [Switch]
    ${Simple},

    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName = 'ActionAccount')]
    [Switch]
    ${ActionAccount},

    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName = 'Binary')]
    [Switch]
    ${Binary},

    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName = 'SnmpV3')]
    [Switch]
    ${SnmpV3},

    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName = 'SCXMonitoring')]
    [Switch]
    ${SCXMonitoring},

    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName = 'SCXMaintenanceSSHKeyPriv')]
    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName = 'SCXMaintenanceSSHKeyNoPrivSudo')]
    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName = 'SCXMaintenanceSSHKeyNoPrivSu')]
    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName = 'SCXMaintenanceUserPassPriv')]
    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName = 'SCXMaintenanceUserPassNoPrivSudo')]
    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName = 'SCXMaintenanceUserPassNoPrivSu')]
    [Switch]
    ${SCXMaintenance},

    [Parameter(Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
    [Alias('DisplayName')]
    [ValidateNotNullOrEmpty()]
    [System.String]
    ${Name},

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [System.String]
    ${Description},

    [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='Windows')]
    [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='Basic')]
    [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='Simple')]
    [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='Digest')]
    [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='ActionAccount')]
    [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMonitoring')]
    [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMaintenanceUserPassPriv')]
    [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMaintenanceUserPassNoPrivSudo')]
    [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMaintenanceUserPassNoPrivSu')]
    [Alias('User')]
    [ValidateNotNullOrEmpty()]
    [System.Management.Automation.PSCredential]
    ${RunAsCredential},

    [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='Binary')]
    [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMaintenanceSSHKeyPriv')]
    [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMaintenanceSSHKeyNoPrivSudo')]
    [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMaintenanceSSHKeyNoPrivSu')]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({ $executionContext.SessionState.Path.GetResolvedPSPathFromPSPath($_) })]
    [System.String]
    ${Path},

    [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='CommunityString')]
    [ValidateNotNullOrEmpty()]
    [System.Security.SecureString]
    ${String},

    [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='SnmpV3')]
    [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMaintenanceSSHKeyPriv')]
    [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMaintenanceSSHKeyNoPrivSudo')]
    [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMaintenanceSSHKeyNoPrivSu')]
    [ValidateNotNullOrEmpty()]
    [System.String]
    ${UserName},
    
    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='SnmpV3')]
    [ValidateNotNullOrEmpty()]
    [System.Management.Automation.PSCredential]
    ${AuthProtocolAndKey},

    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='SnmpV3')]
    [ValidateNotNullOrEmpty()]
    [System.Management.Automation.PSCredential]
    ${PrivacyProtocolAndKey},

    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='SnmpV3')]
    [ValidateNotNullOrEmpty()]
    [System.String]
    ${Context},

    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMaintenanceSSHKeyPriv')]
    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMaintenanceSSHKeyNoPrivSudo')]
    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMaintenanceSSHKeyNoPrivSu')]
    [ValidateNotNullOrEmpty()]
    [System.Security.SecureString]
    ${Passphrase} = (new-object System.Security.SecureString),

    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMaintenanceSSHKeyPriv')]
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMaintenanceUserPassPriv')]
    [Switch]
    ${Privileged},

    [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMonitoring')]
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMaintenanceSSHKeyNoPrivSudo')]
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMaintenanceUserPassNoPrivSudo')]
    [Switch]
    ${Sudo},

    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMaintenanceSSHKeyNoPrivSu')]
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMaintenanceUserPassNoPrivSu')]
    [Switch]
    ${Su},

    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMaintenanceSSHKeyNoPrivSu')]
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName=$true, ParameterSetName='SCXMaintenanceUserPassNoPrivSu')]
    [ValidateNotNullOrEmpty()]
    [System.Security.SecureString]
    ${SuPassword},

    [ValidateNotNullOrEmpty()]
    [Microsoft.SystemCenter.Core.Connection.Connection[]]
    ${SCSession},

    [ValidateNotNullOrEmpty()]
    [System.String[]]
    ${ComputerName},
    
    [System.Management.Automation.PSCredential]
    ${Credential}
    )

    begin
    {
        $MaintenanceFactory = [Microsoft.SystemCenter.CrossPlatform.ClientLibrary.CredentialManagement.MaintenanceRunAsAccount]::MaintenanceAuthenticationDataFactory
        $MonitoringFactory = [Microsoft.SystemCenter.CrossPlatform.ClientLibrary.CredentialManagement.MonitorRunAsAccount]::MonitorAuthenticationDataFactory
    }    
    process
    {
        $managementGroupParameters = @{} + $psBoundParameters
        foreach ($k in @($managementGroupParameters.Keys))
        {
            if ('SCSession', 'ComputerName', 'Credential' -notcontains $k)
            {
                $null = $managementGroupParameters.Remove($k)
            }
        }

        $Group = Get-SCOMManagementGroup @managementGroupParameters
        $connection = [Microsoft.SystemCenter.OperationsManagerV10.Commands.OMV10Utility]::GetConnectionForManagementGroup($Group)

        if (-not $psCmdlet.ShouldProcess($Name))
        {
            return
        }
        
        if (-not $psBoundParameters.description)
        {
            $description = $name 
        }

        $accountProperties = @{
                Name = $name
                Description = $Description
            }

        $networkCredential = $null
        $typeName = $null

        if($psBoundParameters.ContainsKey("RunAsCredential"))
        {
            $networkCredential = $RunAsCredential.GetNetworkCredential()
            $accountProperties.UserName = $networkCredential.UserName
            $accountProperties.Data = $RunAsCredential.Password
        }

        $errorActionPreference = 'Stop'
        try
        {
            $accountData = $null

            # standard scom accounts
            if($psCmdlet.ParameterSetName -notlike 'SCX*')
            {
                switch ($psCmdlet.ParameterSetName)
                {
                    'Windows'
                    {
                       $typeName = 'WindowsCredentialSecureData'
                       if( $networkCredential.Domain)
                       {
                          $accountProperties.Domain = $networkCredential.Domain
                       }
                    }
                    'Basic' {$typeName = 'BasicCredentialSecureData'}
                    'Simple'{$typeName = 'SimpleCredentialSecureData'}
                    'Digest'{$typeName = 'DigestCredentialSecureData'}
                    'ActionAccount'
                    {
                       $typeName = 'ActionAccountSecureData'
                       if( $networkCredential.Domain)
                       {
                          $accountProperties.Domain = $networkCredential.Domain
                       }
                    }
                    'Binary'
                    {
                       $typeName = 'GenericSecureData'
                       $data = new-object System.Security.SecureString
                       $binPath = $psCmdlet.GetUnresolvedProviderPathFromPSPath($Path)
                       [byte[]]$bytes = [System.IO.File]::ReadAllBytes($binPath)
                       $encoded = [System.Convert]::ToBase64String($bytes)
                       $encoded.ToCharArray() |%{ $data.AppendChar($_) }
                       $accountProperties.Data = $data
                    }
                    'CommunityString'
                    {
                       $typeName = 'CommunityStringSecureData'
                       $accountProperties.Data = $String
                    }
                    'SnmpV3'
                    {
                       $typeName = 'SnmpV3SecureData'
                       $accountProperties.UserName = $UserName
                       $accountProperties.AuthenticationProtocol = 'None'
                       $accountProperties.AuthenticationKey = (new-object System.Security.SecureString)
                       $accountProperties.PrivacyProtocol = 'None'
                       $accountProperties.PrivacyKey = (new-object System.Security.SecureString)

                       if($psBoundParameters.ContainsKey("AuthProtocolAndKey"))
                       {
                          $accountProperties.AuthenticationProtocol = [Microsoft.EnterpriseManagement.Security.SnmpV3AuthenticationFunction] $AuthProtocolAndKey.GetNetworkCredential().UserName
                          $accountProperties.AuthenticationKey = $AuthProtocolAndKey.Password
              
                          if($psBoundParameters.ContainsKey("PrivacyProtocolAndKey"))
                          {
                             $accountProperties.PrivacyProtocol = [Microsoft.EnterpriseManagement.Security.SnmpV3EncryptionAlgorithm ]$PrivacyProtocolAndKey.GetNetworkCredential().UserName
                             $accountProperties.PrivacyKey = $PrivacyProtocolAndKey.Password
                          }
                       }
           
                       if($psBoundParameters.ContainsKey('Context'))
                       {
                           $accountProperties.ContextName = $Context 
                       }
                    }
                }
         
                $accountData = New-Object "Microsoft.EnterpriseManagement.Security.${typeName}" -Property $accountProperties
                Write-Debug 'Inserting Account Data'
                $Group.Security.insertSecureData($accountdata)
                $accountData = $Group.Security.GetSecureData($accountData.Id) | Add-Member -Name 'AccountType' -Value "SCOM${typeName}" -MemberType NoteProperty -PassThru
                              
            }
            # x-plat accounts
            else
            {
                $accountData = $null
                if($psCmdlet.ParameterSetName -eq 'SCXMonitoring')
                {
                    $authenticationData = $MonitoringFactory.Invoke($RunAsCredential.Password, $Sudo.IsPresent)
                    $AccountData = 
                    [Microsoft.SystemCenter.CrossPlatform.ClientLibrary.CredentialManagement.CmdletSupport]::NewMonitorAccount($Connection, $Name, $Description, 
                        $networkCredential.Username, $authenticationData, [guid[]]@())
                }
                elseif ($psCmdlet.ParameterSetName -like 'SCXMaintenance*')
                {
                    Write-Debug 'Creating Maintenance Account Data'
                    $keyFile = $null
                    if($psCmdlet.ParameterSetName -like '*SSHKey*')
                    {
                       $keyFile = $psCmdlet.GetUnresolvedProviderPathFromPSPath($Path) | select -last 1
                    }

                    $authenticationData = 
                        switch($psCmdlet.ParameterSetName)
                        {
                           'SCXMaintenanceSSHKeyPriv'
                           {
                               $MaintenanceFactory.Invoke($keyFile, $PassPhrase, $false)
                           }
                           'SCXMaintenanceSSHKeyNoPrivSudo'
                           {
                               $MaintenanceFactory.Invoke($keyFile, $PassPhrase, $true)
                           }
                           'SCXMaintenanceSSHKeyNoPrivSu'
                           {
                               $MaintenanceFactory.Invoke($keyFile, $PassPhrase, $SuPassword)
                           }
                           'SCXMaintenanceUserPassPriv'
                           {
                               $MaintenanceFactory.Invoke($RunAsCredential.Password, $false)
                           }
                           'SCXMaintenanceUserPassNoPrivSudo'
                           {
                               $MaintenanceFactory.Invoke($RunAsCredential.Password, $true)
                           }
                           'SCXMaintenanceUserPassNoPrivSu'
                           {
                              $MaintenanceFactory.Invoke($RunAsCredential.Password, $SuPassword)
                           }
                        }


                    $AccountData = 
                       [Microsoft.SystemCenter.CrossPlatform.ClientLibrary.CredentialManagement.CmdletSupport]::NewMaintenanceAccount($Connection, $Name, $Description, 
                          $networkCredential.Username, $authenticationData, [guid[]]@())        
                }
                       
            }

            $accountData
        }
        catch
        {
           Write-Error $_
        }       
    }
}

# .ExternalHelp Microsoft.SystemCenter.OperationsManagerV10.Commands.dll-Help.xml
function Update-SCOMRunAsAccount 
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(   
       [Parameter(ValueFromPipeline=$true, Position=0, Mandatory=$true, ParameterSetName='WindowsAccount')]
       [ValidateNotNullOrEmpty()]
       [Microsoft.EnterpriseManagement.Security.WindowsCredentialSecureData]
       $WindowsAccount,
       
       [Parameter(ValueFromPipeline=$true, Position=0, Mandatory=$true, ParameterSetName='BasicAccount')]
       [ValidateNotNullOrEmpty()]
       [Microsoft.EnterpriseManagement.Security.BasicCredentialSecureData]
       $BasicAccount,
       
       [Parameter(ValueFromPipeline=$true, Position=0, Mandatory=$true, ParameterSetName='SimpleAccount')]
       [ValidateNotNullOrEmpty()]
       [Microsoft.EnterpriseManagement.Security.SimpleCredentialSecureData]
       $SimpleAccount,
       
       [Parameter(ValueFromPipeline=$true, Position=0, Mandatory=$true, ParameterSetName='DigestAccount')]
       [ValidateNotNullOrEmpty()]
       [Microsoft.EnterpriseManagement.Security.SimpleCredentialSecureData]
       $DigestAccount,
       
       [Parameter(ValueFromPipeline=$true, Position=0, Mandatory=$true, ParameterSetName='ActionAccount')]
       [ValidateNotNullOrEmpty()]
       [Microsoft.EnterpriseManagement.Security.ActionAccountSecureData]
       $ActionAccount,
       
       [Parameter(ValueFromPipeline=$true, Position=0, Mandatory=$true, ParameterSetName='CommunityStringAccount')]
       [ValidateNotNullOrEmpty()]
       [Microsoft.EnterpriseManagement.Security.CommunityStringSecureData]
       $CommunityStringAccount,
       
       [Parameter(ValueFromPipeline=$true, Position=0, Mandatory=$true, ParameterSetName='BinaryAccount')]
       [ValidateNotNullOrEmpty()]
       [Microsoft.EnterpriseManagement.Security.GenericSecureData]
       $BinaryAccount,

       [Parameter(Mandatory=$true, Position=1, ParameterSetName='WindowsAccount')]
       [Parameter(Mandatory=$true, Position=1, ParameterSetName='BasicAccount')]
       [Parameter(Mandatory=$true, Position=1, ParameterSetName='SimpleAccount')]
       [Parameter(Mandatory=$true, Position=1, ParameterSetName='DigestAccount')]
       [Parameter(Mandatory=$true, Position=1, ParameterSetName='ActionAccount')]
       [ValidateNotNullOrEmpty()]
       [System.Management.Automation.PSCredential]
       ${RunAsCredential},
       
       [Parameter(Mandatory=$true, Position=1, ParameterSetName='CommunityStringAccount')]
       [ValidateNotNullOrEmpty()]
       [System.Security.SecureString]
       ${CommunityString},

       [Parameter(Mandatory=$true, Position=1, ParameterSetName='BinaryAccount')]
       [ValidateNotNullOrEmpty()]
       [ValidateScript({ $executionContext.SessionState.Path.GetResolvedPSPathFromPSPath($_) })]
       [System.String]
       ${Path},

       [Parameter(ValueFromPipelineByPropertyName=$true)]
       [ValidateScript({$_ -notlike "SCX*"})]
       [string]
       $AccountType,
       
       [Parameter()]
       [switch]
       $PassThru,
       
       [ValidateNotNullOrEmpty()]
       [Microsoft.SystemCenter.Core.Connection.Connection[]]
       ${SCSession},

       [ValidateNotNullOrEmpty()]
       [System.String[]]
       ${ComputerName},

       [ValidateNotNullOrEmpty()]
       [System.Management.Automation.PSCredential]
       ${Credential}
    )

    process {
        
        $runAsAccount = Get-Variable $psCmdlet.ParameterSetName -ValueOnly
        
        if($psCmdlet.ShouldProcess($runAsAccount.Name))
        {
        
           if ($psCmdlet.ParameterSetName -eq 'BinaryAccount')
           {
               $data = new-object System.Security.SecureString
               $binPath = $psCmdlet.GetUnresolvedProviderPathFromPSPath($Path)
               [byte[]]$bytes = [System.IO.File]::ReadAllBytes($binPath)
               $encoded = [System.Convert]::ToBase64String($bytes)
               foreach($_ in $encoded.ToCharArray()) { $data.AppendChar($_) }
               $runAsAccount.Data = $data
           } 
           elseif ($psCmdlet.ParameterSetName -eq 'CommunityStringAccount')
           {
               $runAsAccount.Data = $CommunityString
           }
           else
           {
              $networkCredential = $runAsCredential.GetNetworkCredential()
              $runAsAccount.UserName = $networkCredential.UserName
              $runAsAccount.Data = $runAsCredential.Password
              
              if('WindowsAccount','ActionAccount' -contains $psCmdlet.ParameterSetName)
              {
                  if($networkCredential.Domain)
                  {
                    $runAsAccount.Domain = $networkCredential.Domain
                  }
              }
           }
                       
           $runAsAccount.Update()
           
           if($PassThru)
           {
              $runAsAccount
           }
        }
    }
} 


# .ExternalHelp Microsoft.SystemCenter.OperationsManagerV10.Commands.dll-Help.xml
function Get-SCOMRunAsAccount
{
    [CmdletBinding(DefaultParametersetName='EmptyParameterSet')]
    param(
    [Parameter(ParameterSetName='FromRunAsAccountName', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [System.String[]]
    ${Name},

    [Parameter(ParameterSetName='FromId', Mandatory=$true, ValueFromPipeline=$true)]
    [System.Guid[]]
    ${Id},

    [ValidateNotNullOrEmpty()]
    [Microsoft.SystemCenter.Core.Connection.Connection[]]
    ${SCSession},

    [ValidateNotNullOrEmpty()]
    [System.String[]]
    ${ComputerName},

    [ValidateNotNullOrEmpty()]
    [System.Management.Automation.PSCredential]
    ${Credential})
    
    process
    {
        $managementGroupParameters = @{} + $psBoundParameters
        foreach ($k in @($managementGroupParameters.Keys))
        {
            if ('SCSession', 'ComputerName', 'Credential' -notcontains $k)
            {
                $null = $managementGroupParameters.Remove($k)
            }
        }

        $Group=  Get-SCOMManagementGroup @managementGroupParameters
        $connection = [Microsoft.SystemCenter.OperationsManagerV10.Commands.OMV10Utility]::GetConnectionForManagementGroup($Group)
        
        $refs = @(if ($psBoundParameters.ContainsKey("Name"))
                {
                   foreach ($ref in $Group.Security.GetSecureData())
                   {
                      foreach($nameWildCard in $name)
                      {
                         if ($Ref.Name -like $nameWildCard)
                         {
                            $ref
                         }
                      }
                   }
                } 
                elseif ($psBoundParameters.ContainsKey("Id"))
                {
                     foreach($refId in $id)
                     {
                         $Group.Security.GetSecureData($refId)
                     }
                }
                else
                {
                    $Group.Security.GetSecureData()
                }
              )
        foreach($ref in $refs)
        {
           $unixRunAs = try {  [Microsoft.SystemCenter.CrossPlatform.ClientLibrary.CredentialManagement.CmdletSupport]::GetScxRunAsAccount($connection, $ref.Id) }
                        catch { }

           $accoutType = ''  
                     
           if ($unixRunAs)
           { 
               $accountType = 'SCX' + $unixRunAs.GetType().Name
           }
           else
           {
               $accountType = 'SCOM' + $ref.GetType().Name
           }
           
           Add-Member -InputObject $ref -Name 'AccountType' -Value $accountType -MemberType NoteProperty -PassThru
        }     
    }
}

# .ExternalHelp Microsoft.SystemCenter.OperationsManagerV10.Commands.dll-Help.xml
function Remove-SCOMRunAsAccount
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
    [Parameter(ValueFromPipeline=$true,Position=0,Mandatory=$true)]
    [Microsoft.EnterpriseManagement.Security.SecureData[]]
    $RunAsAccount,
    
    [ValidateNotNullOrEmpty()]
    [Microsoft.SystemCenter.Core.Connection.Connection[]]
    ${SCSession},

    [ValidateNotNullOrEmpty()]
    [System.String[]]
    ${ComputerName},

    [ValidateNotNullOrEmpty()]
    [System.Management.Automation.PSCredential]
    ${Credential})
    
    process
    {
        $managementGroupParameters = @{} + $psBoundParameters
        foreach ($k in @($managementGroupParameters.Keys))
        {
            if ('SCSession', 'ComputerName', 'Credential' -notcontains $k)
            {
                $null = $managementGroupParameters.Remove($k)
            }
        }

        $Group=  Get-SCOMManagementGroup @managementGroupParameters
        $connection = [Microsoft.SystemCenter.OperationsManagerV10.Commands.OMV10Utility]::GetConnectionForManagementGroup($Group)

        foreach($account in $RunAsAccount)
        {
           if ($psCmdlet.ShouldProcess($account.Name))
           {
               $unixRunAs = try {  [Microsoft.SystemCenter.CrossPlatform.ClientLibrary.CredentialManagement.CmdletSupport]::GetScxRunAsAccount($connection, $account.Id) }
                            catch { }
               if ($unixRunAs)
               {
                  [Microsoft.SystemCenter.CrossPlatform.ClientLibrary.CredentialManagement.CmdletSupport]::RemoveScxRunAsAccount($connection, $account.Id)    
               }
               else
               {
                  $Group.Security.DeleteSecureData($account)
               }
           }
        }        
    }
}

# .ExternalHelp Microsoft.SystemCenter.OperationsManagerV10.Commands.dll-Help.xml
function Get-SCOMRunAsDistribution
{
    param(   
       [Parameter(ValueFromPipeline=$true,Position=0,Mandatory=$true)]
       [ValidateNotNullOrEmpty()]
       [Microsoft.EnterpriseManagement.Security.SecureData[]]
       $RunAsAccount,
       
       [ValidateNotNullOrEmpty()]
       [Microsoft.SystemCenter.Core.Connection.Connection[]]
       ${SCSession},

       [ValidateNotNullOrEmpty()]
       [System.String[]]
       ${ComputerName},

       [ValidateNotNullOrEmpty()]
       [System.Management.Automation.PSCredential]
       ${Credential}
    )

   process
   {
      foreach($runAs in $runAsAccount)
      {
         $group = $runAs.ManagementGroup
         $lessSecure = $true
         [Microsoft.EnterpriseManagement.Monitoring.MonitoringObject[]] $distributionList =
                    [Microsoft.SystemCenter.OperationsManagerV10.Commands.OMV10Utility]::GetSecureDistribution($runAs, [ref] $lessSecure)

         $security  = if($lessSecure){'LessSecure'}else{'MoreSecure'}
          new-object psobject -prop @{
                                       Security = $security
                                       SecureDistribution = $distributionList
                                       RunAsAccount = $runAs
                                     }
       }
   }    
}

# .ExternalHelp Microsoft.SystemCenter.OperationsManagerV10.Commands.dll-Help.xml
function Set-SCOMRunAsDistribution
{

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(   
       [Parameter(ValueFromPipeline=$true,Position=0,Mandatory=$true)]
       [ValidateNotNullOrEmpty()]
       [Microsoft.EnterpriseManagement.Security.SecureData]
       $RunAsAccount,
       
       [Parameter(Mandatory = $true, ParameterSetname = 'LessSecure')]
       [switch]
       $LessSecure,
       
       [Parameter(Mandatory = $true, ParameterSetname = 'MoreSecure')]
       [switch]
       $MoreSecure,

       [Parameter(Mandatory = $true, ParameterSetName = 'Security', ValueFromPipelineByPropertyName = $true)]
       [ValidateSet('MoreSecure', 'LessSecure')]
       [string]
       $Security,
       
       [Parameter(ParameterSetname = 'MoreSecure', ValueFromPipelineByPropertyName = $true)]
       [Parameter(ParameterSetname = 'Security', ValueFromPipelineByPropertyName = $true)]
       [ValidateNotNull()]
       [Object[]]
       $SecureDistribution,
       
       [switch]
       $PassThru,    
       
       [ValidateNotNullOrEmpty()]
       [Microsoft.SystemCenter.Core.Connection.Connection[]]
       ${SCSession},

       [ValidateNotNullOrEmpty()]
       [System.String[]]
       ${ComputerName},

       [ValidateNotNullOrEmpty()]
       [System.Management.Automation.PSCredential]
       ${Credential}
    )

   process {

        $Group=  $runAsAccount.ManagementGroup
        $connection = [Microsoft.SystemCenter.OperationsManagerV10.Commands.OMV10Utility]::GetConnectionForManagementGroup($Group)

        $hsClass = $group.EntityTypes.GetClasses("Name = 'Microsoft.SystemCenter.Healthservice'") |%{ $_ }
        $poolClass = $group.EntityTypes.GetClasses("Name = 'Microsoft.SystemCenter.ManagementServicePool'") |%{ $_ }

        [Microsoft.EnterpriseManagement.Monitoring.MonitoringObject[]] $distributionList = @()
        if($MoreSecure -or ($Security -eq 'MoreSecure'))
        {
           foreach($o in $SecureDistribution)
           {
               if($destination = ($o -as [Microsoft.EnterpriseManagement.Administration.AgentManagedComputer]))
               {
                  $distributionList += $destination.HostedHealthservice
               }
               elseif($destination = ($o -as [Microsoft.EnterpriseManagement.Administration.ManagementServer]))
               {
                  $distributionList += $destination.HostedHealthservice
               }
               elseif($destination = ($o -as [Microsoft.EnterpriseManagement.Administration.ManagementServicePool]))
               {
                  $distributionList += ( Get-SCOMClassInstance -Id $destination.Id -ScSession $connection )
               }
               elseif(($destination = ($o -as [Microsoft.EnterpriseManagement.Monitoring.MonitoringObject])) -and
                       ($destination.IsInstanceOf($hsClass) -or $destination.IsInstanceOf($poolClass)))
               {
                  $distributionList += $destination
               }
               else
               {
                  # write some error
               }
           }
        }
        elseif($LessSecure -or ($Security -eq 'LessSecure'))
        {
           $distributionList = $null
        }

        if($psCmdlet.ShouldProcess($RunAsAccount.Name))
        {
           [Microsoft.SystemCenter.OperationsManagerV10.Commands.OMV10Utility]::ApproveRunasAccountForDistribution($Group, $runAsAccount, $distributionList)

            if($PassThru)
            {
               $runAsAccount                              
            }
        }        
    }    
}

# .ExternalHelp Microsoft.SystemCenter.OperationsManagerV10.Commands.dll-Help.xml
function Get-SCOMTieredManagementGroup
{
    [CmdletBinding(DefaultParameterSetName='Empty', SupportsShouldProcess = $true)]
    param(    
       [Parameter(Mandatory = $true, Position = 0, ParameterSetname = 'Name')]
       [String[]] $Name,
       
       [Parameter(Mandatory = $true, ParameterSetname = 'Id')]
       [Guid[]] $Id,    
           
       [Parameter(ParameterSetname = 'Empty')]
       [Switch]$OnlyForConnector,
       
       [ValidateNotNullOrEmpty()]
       [Microsoft.SystemCenter.Core.Connection.Connection[]]
       ${SCSession},

       [ValidateNotNullOrEmpty()]
       [System.String[]]
       ${ComputerName},

       [ValidateNotNullOrEmpty()]
       [System.Management.Automation.PSCredential]
       ${Credential}
    )
    
    process {
    
        $managementGroupParameters = @{} + $psBoundParameters
        foreach ($k in @($managementGroupParameters.Keys)) {
            if ('SCSession', 'ComputerName', 'Credential' -notcontains $k) {
                $null = $managementGroupParameters.Remove($k)
            }
        }
        $Group=  Get-SCOMManagementGroup @managementGroupParameters
        
        if($pscmdlet.ParameterSetname -eq 'Empty')
        {
           if (-not $onlyForConnector) {        
               $group.Tiering.GetTiers()  
           } else {
               $group.Tiering.GetTiersForConnectors()
           }
        }
        elseif($pscmdlet.ParameterSetname -eq 'Name')
        {
           foreach($tier in $group.Tiering.GetTiers())
           {
              foreach($tierName in $Name)
              {
                 if($tier.Name -like $tierName)
                 {
                    $tier
                 }
              }
           }           
        }
        elseif($pscmdlet.ParameterSetname -eq 'Id')
        {
           foreach($tier in $group.Tiering.GetTiers())
           {
              foreach($tierId in $id)
              {
                 if($tier.Id -eq $tierId)
                 {
                    $tier
                 }
              }
           }
        }
    }
}

# .ExternalHelp Microsoft.SystemCenter.OperationsManagerV10.Commands.dll-Help.xml
function Add-SCOMTieredManagementGroup
{
    [CmdletBinding(DefaultParameterSetName='SimpleAccountTier', SupportsShouldProcess = $true)]
    param(
       [Parameter(Mandatory=$true)]
       [String]$Name,
       
       [Parameter(Mandatory=$true)]
       [String]$ServerName,
       
       [Parameter(Mandatory=$true)]
       [System.Management.Automation.PSCredential] $ConnectionCredential,
       
       [Timespan]$InactivityTimeout = "1:0:0",
       
       [Timespan]$SendReceiveTimeout = "0:30:0",
       
       [Microsoft.EnterpriseManagement.Common.CacheMode]$CacheMode,
       
       [Microsoft.EnterpriseManagement.Common.CacheConfiguration]$CacheConfiguration,
       
       [Parameter(Mandatory=$true,ParameterSetName='RunAsAccountTier')]
       [Microsoft.EnterpriseManagement.Security.WindowsCredentialSecureData]$RunAsAccount,
       
       [Parameter(ParameterSetName='RunAsAccountTier')]
       [Switch]$AvailableForConnectors,
       
       [ValidateNotNullOrEmpty()]
       [Microsoft.SystemCenter.Core.Connection.Connection[]]
       ${SCSession},

       [ValidateNotNullOrEmpty()]
       [System.String[]]
       ${ComputerName},

       [ValidateNotNullOrEmpty()]
       [System.Management.Automation.PSCredential]
       ${Credential}
    )
    
    process {
        $managementGroupParameters = @{} + $psBoundParameters
        foreach ($k in @($managementGroupParameters.Keys)) {
            if ('SCSession', 'ComputerName', 'Credential' -notcontains $k) {
                $null = $managementGroupParameters.Remove($k)
            }
        }
        $Group=  Get-SCOMManagementGroup @managementGroupParameters
        
        $netCred = $connectionCredential.GetNetworkCredential()
   
        $props = @{} + $psBoundParameters
        $null = $props.Remove('AvailableForConnectors')
        $null = $props.Remove('RunAsAccount')
        $null = $props.Remove('Name')
        $null = $props.Remove('ServerName')
        $null = $props.Remove('SCSession')
        $null = $props.Remove('ComputerName')
        $null = $props.Remove('Credential')
        $null = $props.Remove('ConnectionCredential')
        $props.Add('UserName', $netCred.UserName)
        $props.Add('Domain', $netCred.Domain)
        $props.Add('Password', $connectionCredential.Password)
        
        $newTier = New-Object Microsoft.EnterpriseManagement.ManagementGroupConnectionSettings $ServerName -Property $props
        
        if($pscmdlet.ShouldProcess($name))
        {
           if ($RunAsAccount) {
               $group.Tiering.AddTier($name, $newTier, $RunAsAccount, $AvailableForConnectors)
           } else {
               $group.Tiering.AddTier($name, $newTier)
           }
        }
    }
}

# .ExternalHelp Microsoft.SystemCenter.OperationsManagerV10.Commands.dll-Help.xml
function Remove-SCOMTieredManagementGroup
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
       [ValidateNotNullOrEmpty()]
       [Microsoft.EnterpriseManagement.Tiering.TieredManagementGroup[]]
       $Tier,
       
       [ValidateNotNullOrEmpty()]
       [Microsoft.SystemCenter.Core.Connection.Connection[]]
       ${SCSession},

       [ValidateNotNullOrEmpty()]
       [System.String[]]
       ${ComputerName},

       [ValidateNotNullOrEmpty()]
       [System.Management.Automation.PSCredential]
       ${Credential}        
    )
    
    process {
        $managementGroupParameters = @{} + $psBoundParameters
        foreach ($k in @($managementGroupParameters.Keys)) {
            if ('SCSession', 'ComputerName', 'Credential' -notcontains $k) {
                $null = $managementGroupParameters.Remove($k)
            }
        }
        $Group=  Get-SCOMManagementGroup @managementGroupParameters
        
        foreach($tmg in $tier)
        {
           if ($pscmdlet.ShouldProcess($tmg.Name)) {        
               $group.Tiering.RemoveTier($tmg)
           }
        }
    }
}

# .ExternalHelp Microsoft.SystemCenter.OperationsManagerV10.Commands.dll-Help.xml
function Get-SCOMTierConnector
{
    [CmdletBinding(DefaultParameterSetName = 'Empty')]
    param(
       [Parameter(Mandatory=$true, ParameterSetName = 'Name')]
       [ValidateNotNullOrEmpty()]
       [string[]]
       $Name,
       
       [Parameter(Mandatory=$true, Position = 0, ParameterSetName = 'DisplayName')]
       [ValidateNotNullOrEmpty()]
       [string[]]
       $DisplayName,
    
       [Parameter(Mandatory=$true, ParameterSetName = 'Id')]
       [ValidateNotNullOrEmpty()]
       [Guid[]]
       $Id,
       
       [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
       [ValidateNotNullOrEmpty()]
       [Microsoft.EnterpriseManagement.Tiering.TieredManagementGroup]
       $Tier,
       
       [ValidateNotNullOrEmpty()]
       [Microsoft.SystemCenter.Core.Connection.Connection[]]
       ${SCSession},

       [ValidateNotNullOrEmpty()]
       [System.String[]]
       ${ComputerName},

       [ValidateNotNullOrEmpty()]
       [System.Management.Automation.PSCredential]
       ${Credential}        
    )
    
    process {
       $errorActionPreference = 'Stop'
       try
       {
            $settings = New-Object Microsoft.EnterpriseManagement.TieredManagementGroupConnectionSettings
            $settings.ConnectForConnector = $true
            $settings.CacheMode = 'None'
            
            $mg = $tier.Connect($settings)
            
            if($pscmdlet.ParameterSetName -eq 'Empty')
            {
               $mg.ConnectorFramework.GetConnectors()
            }
            elseif($psCmdlet.ParameterSetName -eq 'Name')
            {
               foreach($connector in $mg.ConnectorFramework.GetConnectors())
               {
                  foreach($connName in $Name)
                  {
                     if($connector.Name -like $connName)
                     {
                        $connector
                     }
                  }
               }
            }
            elseif($psCmdlet.ParameterSetName -eq 'DisplayName')
            {
               foreach($connector in $mg.ConnectorFramework.GetConnectors())
               {
                  foreach($connName in $DisplayName)
                  {
                     if($connector.DisplayName -like $connName)
                     {
                        $connector
                     }
                  }
               }
            }
            elseif($psCmdlet.ParameterSetName -eq 'Id')
            {
               foreach($connector in $mg.ConnectorFramework.GetConnectors())
               {
                  foreach($connId in $Id)
                  {
                     if($connector.Id -eq $connId)
                     {
                        $connector
                     }
                  }
               }
            }            
        }
        catch
        {
           Write-Error $_
        }         
    }
}

# .ExternalHelp Microsoft.SystemCenter.OperationsManagerV10.Commands.dll-Help.xml
function Add-SCOMTierConnector
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
       [ValidateNotNullOrEmpty()]
       [Microsoft.EnterpriseManagement.ConnectorFramework.MonitoringConnector]
       $Connector,
    
       [Parameter(Mandatory=$true)]
       [ValidateNotNullOrEmpty()]
       [ValidateScript( {$_.IsAvailableForConnectors} )]
       [Microsoft.EnterpriseManagement.Tiering.TieredManagementGroup]
       $Tier,
       
       [switch] $PassThru,
       
       [ValidateNotNullOrEmpty()]
       [Microsoft.SystemCenter.Core.Connection.Connection[]]
       ${SCSession},

       [ValidateNotNullOrEmpty()]
       [System.String[]]
       ${ComputerName},

       [ValidateNotNullOrEmpty()]
       [System.Management.Automation.PSCredential]
       ${Credential}        
    )
    
    process {
       $errorActionPreference = 'Stop'
       try
       {
            $settings = New-Object Microsoft.EnterpriseManagement.TieredManagementGroupConnectionSettings
            $settings.ConnectForConnector = $true
            $settings.CacheMode = 'None'
            
            $mg = $tier.Connect($settings)
            
            $connectorInfo = new-object Microsoft.EnterpriseManagement.ConnectorFramework.ConnectorInfo
            $connectorInfo.Description = $connector.Description
            $connectorInfo.DiscoveryDataIsManaged = $connector.DiscoveryDataIsManaged
            $connectorInfo.DisplayName = $connector.DisplayName
            $connectorInfo.Name = $connector.Name
            
            if($psCmdlet.ShouldProcess($tier.Name))
            {   
              $tieredConnector = $mg.ConnectorFramework.Setup($connectorInfo, $connector.Id)
              
              if($passThru)
              {
                 $tieredConnector
              }        
            }
        }
        catch
        {
           Write-Error $_
        }         
    }
}

# .ExternalHelp Microsoft.SystemCenter.OperationsManagerV10.Commands.dll-Help.xml
function Remove-SCOMTierConnector
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
       [ValidateNotNullOrEmpty()]
       [Microsoft.EnterpriseManagement.ConnectorFramework.MonitoringConnector]
       $Connector,
    
       [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
       [ValidateNotNullOrEmpty()]
       [ValidateScript( {$_.IsAvailableForConnectors} )]
       [Microsoft.EnterpriseManagement.Tiering.TieredManagementGroup]
       $Tier,
       
       [ValidateNotNullOrEmpty()]
       [Microsoft.SystemCenter.Core.Connection.Connection[]]
       ${SCSession},

       [ValidateNotNullOrEmpty()]
       [System.String[]]
       ${ComputerName},

       [ValidateNotNullOrEmpty()]
       [System.Management.Automation.PSCredential]
       ${Credential}        
    )
    
    process { 
       $errorActionPreference = 'Stop'
       try
       {
            $settings = New-Object Microsoft.EnterpriseManagement.TieredManagementGroupConnectionSettings
            $settings.ConnectForConnector = $true
            $settings.CacheMode = 'None'
           
            $mg = $tier.Connect($settings)
           
            $tieredConnector = $mg.ConnectorFramework.GetConnector($connector.Id)
           
            if($psCmdlet.ShouldProcess($tier.Name))
            {     
              $mg.ConnectorFramework.Cleanup($tieredConnector)        
            }
        }
        catch
        {
           Write-Error $_
        }   
    }
}

. $psScriptRoot\Functions.ps1


Import-Module $psScriptRoot\OM10.CoreCommands\OM10.CoreCommands.psd1
Import-Module $psScriptRoot\OM10.Commands\OM10.Commands.psd1
. $psScriptRoot\OM10.CrossPlatform.Start.ps1

New-Alias Export-SCOMManagementPack Export-SCManagementPack
New-Alias Get-SCOMClass Get-SCClass
New-Alias Get-SCOMDiscovery Get-SCDiscovery
New-Alias Get-SCOMManagementPack Get-SCManagementPack
New-Alias Get-SCOMRelationship Get-SCRelationship
New-Alias Get-SCOMRelationshipInstance Get-SCRelationshipInstance
New-Alias Import-SCOMManagementPack Import-SCManagementPack
New-Alias Remove-SCOMManagementPack Remove-SCManagementPack
New-Alias Get-SCOMManagementGroupConnection Get-SCManagementGroupConnection
New-Alias New-SCOMManagementGroupConnection New-SCManagementGroupConnection
New-Alias Remove-SCOMManagementGroupConnection Remove-SCManagementGroupConnection
New-Alias Set-SCOMManagementGroupConnection Set-SCManagementGroupConnection
New-Alias Get-SCOMMonitoringObject Get-SCOMClassInstance

$parentParent = Split-Path $psScriptRoot
$assemblyNames = [AppDomain]::CurrentDomain.GetAssemblies() |%{ $_.GetName().Name }

if($assemblyNames -cnotcontains 'Microsoft.SystemCenter.CrossPlatform.ClientLibrary.CredentialManagement')
{
   $xPlatDll = Get-ChildItem $psScriptRoot -Recurse -Filter 'Microsoft.SystemCenter.CrossPlatform.ClientLibrary.CredentialManagement.dll' -ErrorAction 0 |
       Select-Object -ExpandProperty Fullname | select-object -first 1

   if($xPlatDll)
   {
      Add-Type -Path $xPlatDll
   }
}

if($assemblyNames -cnotcontains 'Microsoft.Mom.Common')
{
   $consoleMomCommon = Get-ChildItem "$psScriptRoot\..\..\Console" -Recurse -Filter 'Microsoft.Mom.Common.dll' -ErrorAction 0 |
       Select-Object -ExpandProperty Fullname | select-object -first 1
       
   $serverMomCommon = Get-ChildItem "$psScriptRoot\..\..\Server" -Recurse -Filter 'Microsoft.Mom.Common.dll' -ErrorAction 0 |
       Select-Object -ExpandProperty Fullname | select-object -first 1
       
   if($consoleMomCommon -and $serverMomCommon)
   {
      Add-Type -Path $serverMomCommon
   }
   elseif($serverMomCommon)
   {
      Add-Type -Path $serverMomCommon
   }
   elseif($consoleMomCommon)
   {
      Add-Type -Path $consoleMomCommon
   }
}

if($assemblyNames -cnotcontains 'Microsoft.EnterpriseManagement.DataAccessLayer')
{
   $serverDataAccessLayer = Get-ChildItem "$psScriptRoot\..\..\Server" -Recurse -Filter 'Microsoft.EnterpriseManagement.DataAccessLayer.dll' -ErrorAction 0 |
       Select-Object -ExpandProperty Fullname | select-object -first 1
       
   if($serverDataAccessLayer)
   {
      Add-Type -Path $serverDataAccessLayer
   }
}

if($assemblyNames -cnotcontains 'Microsoft.EnterpriseManagement.DataAccessService.Core')
{
   $serverDASCore = Get-ChildItem "$psScriptRoot\..\..\Server" -Recurse -Filter 'Microsoft.EnterpriseManagement.DataAccessService.Core.dll' -ErrorAction 0 |
       Select-Object -ExpandProperty Fullname | select-object -first 1
       
   if($serverDASCore)
   {
      Add-Type -Path $serverDASCore
   }
}

Export-ModuleMember -Alias * -Function * -Cmdlet *

$myInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
    Remove-Module OM10.CoreCommands
    Remove-Module OM10.Commands
}


# SIG # Begin signature block
# MIIa5AYJKoZIhvcNAQcCoIIa1TCCGtECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUO5siOZvEWft62lPR8rx8gGkz
# q3WgghWCMIIEwzCCA6ugAwIBAgITMwAAADPlJ4ajDkoqgAAAAAAAMzANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTMwMzI3MjAwODIz
# WhcNMTQwNjI3MjAwODIzWjCBszELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNO
# OkY1MjgtMzc3Ny04QTc2MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyt7KGQ8fllaC
# X9hCMtQIbbadwMLtfDirWDOta4FQuIghCl2vly2QWsfDLrJM1GN0WP3fxYlU0AvM
# /ZyEEXmsoyEibTPgrt4lQEWSTg1jCCuLN91PB2rcKs8QWo9XXZ09+hdjAsZwPrsi
# 7Vux9zK65HG8ef/4y+lXP3R75vJ9fFdYL6zSDqjZiNlAHzoiQeIJJgKgzOUlzoxn
# g99G+IVNw9pmHsdzfju0dhempaCgdFWo5WAYQWI4x2VGqwQWZlbq+abLQs9dVGQv
# gfjPOAAPEGvhgy6NPkjsSVZK7Jpp9MsPEPsHNEpibAGNbscghMpc0WOZHo5d7A+l
# Fkiqa94hLwIDAQABo4IBCTCCAQUwHQYDVR0OBBYEFABYGz7txfEGk74xPTa0rAtd
# MvCBMB8GA1UdIwQYMBaAFCM0+NlSRnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEsw
# SaBHoEWGQ2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsG
# AQUFBzAChjxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFRpbWVTdGFtcFBDQS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggEBAAL/44wD6u9+OLm5fJ87UoOk+iM41AO4alm16uBviAP0b1Fq
# lTp1hegc3AfFTp0bqM4kRxQkTzV3sZy8J3uPXU/8BouXl/kpm/dAHVKBjnZIA37y
# mxe3rtlbIpFjOzJfNfvGkTzM7w6ZgD4GkTgTegxMvjPbv+2tQcZ8GyR8E9wK/EuK
# IAUdCYmROQdOIU7ebHxwu6vxII74mHhg3IuUz2W+lpAPoJyE7Vy1fEGgYS29Q2dl
# GiqC1KeKWfcy46PnxY2yIruSKNiwjFOPaEdHodgBsPFhFcQXoS3jOmxPb6897t4p
# sETLw5JnugDOD44R79ECgjFJlJidUUh4rR3WQLYwggTsMIID1KADAgECAhMzAAAA
# sBGvCovQO5/dAAEAAACwMA0GCSqGSIb3DQEBBQUAMHkxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBMB4XDTEzMDEyNDIyMzMzOVoXDTE0MDQyNDIyMzMzOVowgYMxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIx
# HjAcBgNVBAMTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAOivXKIgDfgofLwFe3+t7ut2rChTPzrbQH2zjjPmVz+l
# URU0VKXPtIupP6g34S1Q7TUWTu9NetsTdoiwLPBZXKnr4dcpdeQbhSeb8/gtnkE2
# KwtA+747urlcdZMWUkvKM8U3sPPrfqj1QRVcCGUdITfwLLoiCxCxEJ13IoWEfE+5
# G5Cw9aP+i/QMmk6g9ckKIeKq4wE2R/0vgmqBA/WpNdyUV537S9QOgts4jxL+49Z6
# dIhk4WLEJS4qrp0YHw4etsKvJLQOULzeHJNcSaZ5tbbbzvlweygBhLgqKc+/qQUF
# 4eAPcU39rVwjgynrx8VKyOgnhNN+xkMLlQAFsU9lccUCAwEAAaOCAWAwggFcMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBRZcaZaM03amAeA/4Qevof5cjJB
# 8jBRBgNVHREESjBIpEYwRDENMAsGA1UECxMETU9QUjEzMDEGA1UEBRMqMzE1OTUr
# NGZhZjBiNzEtYWQzNy00YWEzLWE2NzEtNzZiYzA1MjM0NGFkMB8GA1UdIwQYMBaA
# FMsR6MrStBZYAck3LjMWFrlMmgofMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY0NvZFNpZ1BDQV8w
# OC0zMS0yMDEwLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljQ29kU2lnUENBXzA4LTMx
# LTIwMTAuY3J0MA0GCSqGSIb3DQEBBQUAA4IBAQAx124qElczgdWdxuv5OtRETQie
# 7l7falu3ec8CnLx2aJ6QoZwLw3+ijPFNupU5+w3g4Zv0XSQPG42IFTp8263Os8ls
# ujksRX0kEVQmMA0N/0fqAwfl5GZdLHudHakQ+hywdPJPaWueqSSE2u2WoN9zpO9q
# GqxLYp7xfMAUf0jNTbJE+fA8k21C2Oh85hegm2hoCSj5ApfvEQO6Z1Ktwemzc6bS
# Y81K4j7k8079/6HguwITO10g3lU/o66QQDE4dSheBKlGbeb1enlAvR/N6EXVruJd
# PvV1x+ZmY2DM1ZqEh40kMPfvNNBjHbFCZ0oOS786Du+2lTqnOOQlkgimiGaCMIIF
# vDCCA6SgAwIBAgIKYTMmGgAAAAAAMTANBgkqhkiG9w0BAQUFADBfMRMwEQYKCZIm
# iZPyLGQBGRYDY29tMRkwFwYKCZImiZPyLGQBGRYJbWljcm9zb2Z0MS0wKwYDVQQD
# EyRNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTAwODMx
# MjIxOTMyWhcNMjAwODMxMjIyOTMyWjB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBD
# QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJyWVwZMGS/HZpgICBC
# mXZTbD4b1m/My/Hqa/6XFhDg3zp0gxq3L6Ay7P/ewkJOI9VyANs1VwqJyq4gSfTw
# aKxNS42lvXlLcZtHB9r9Jd+ddYjPqnNEf9eB2/O98jakyVxF3K+tPeAoaJcap6Vy
# c1bxF5Tk/TWUcqDWdl8ed0WDhTgW0HNbBbpnUo2lsmkv2hkL/pJ0KeJ2L1TdFDBZ
# +NKNYv3LyV9GMVC5JxPkQDDPcikQKCLHN049oDI9kM2hOAaFXE5WgigqBTK3S9dP
# Y+fSLWLxRT3nrAgA9kahntFbjCZT6HqqSvJGzzc8OJ60d1ylF56NyxGPVjzBrAlf
# A9MCAwEAAaOCAV4wggFaMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFMsR6MrS
# tBZYAck3LjMWFrlMmgofMAsGA1UdDwQEAwIBhjASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBT90TFO0yaKleGYYDuoMW+mPLzYLTAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTAfBgNVHSMEGDAWgBQOrIJgQFYnl+UlE/wq4QpTlVnk
# pDBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
# L2NybC9wcm9kdWN0cy9taWNyb3NvZnRyb290Y2VydC5jcmwwVAYIKwYBBQUHAQEE
# SDBGMEQGCCsGAQUFBzAChjhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY3Jvc29mdFJvb3RDZXJ0LmNydDANBgkqhkiG9w0BAQUFAAOCAgEAWTk+
# fyZGr+tvQLEytWrrDi9uqEn361917Uw7LddDrQv+y+ktMaMjzHxQmIAhXaw9L0y6
# oqhWnONwu7i0+Hm1SXL3PupBf8rhDBdpy6WcIC36C1DEVs0t40rSvHDnqA2iA6VW
# 4LiKS1fylUKc8fPv7uOGHzQ8uFaa8FMjhSqkghyT4pQHHfLiTviMocroE6WRTsgb
# 0o9ylSpxbZsa+BzwU9ZnzCL/XB3Nooy9J7J5Y1ZEolHN+emjWFbdmwJFRC9f9Nqu
# 1IIybvyklRPk62nnqaIsvsgrEA5ljpnb9aL6EiYJZTiU8XofSrvR4Vbo0HiWGFzJ
# NRZf3ZMdSY4tvq00RBzuEBUaAF3dNVshzpjHCe6FDoxPbQ4TTj18KUicctHzbMrB
# 7HCjV5JXfZSNoBtIA1r3z6NnCnSlNu0tLxfI5nI3EvRvsTxngvlSso0zFmUeDord
# EN5k9G/ORtTTF+l5xAS00/ss3x+KnqwK+xMnQK3k+eGpf0a7B2BHZWBATrBC7E7t
# s3Z52Ao0CW0cgDEf4g5U3eWh++VHEK1kmP9QFi58vwUheuKVQSdpw5OPlcmN2Jsh
# rg1cnPCiroZogwxqLbt2awAdlq3yFnv2FoMkuYjPaqhHMS+a3ONxPdcAfmJH0c6I
# ybgY+g5yjcGjPa8CQGr/aZuW4hCoELQ3UAjWwz0wggYHMIID76ADAgECAgphFmg0
# AAAAAAAcMA0GCSqGSIb3DQEBBQUAMF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAX
# BgoJkiaJk/IsZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0wNzA0MDMxMjUzMDlaFw0yMTA0MDMx
# MzAzMDlaMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAf
# BgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQTCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAJ+hbLHf20iSKnxrLhnhveLjxZlRI1Ctzt0YTiQP7tGn
# 0UytdDAgEesH1VSVFUmUG0KSrphcMCbaAGvoe73siQcP9w4EmPCJzB/LMySHnfL0
# Zxws/HvniB3q506jocEjU8qN+kXPCdBer9CwQgSi+aZsk2fXKNxGU7CG0OUoRi4n
# rIZPVVIM5AMs+2qQkDBuh/NZMJ36ftaXs+ghl3740hPzCLdTbVK0RZCfSABKR2YR
# JylmqJfk0waBSqL5hKcRRxQJgp+E7VV4/gGaHVAIhQAQMEbtt94jRrvELVSfrx54
# QTF3zJvfO4OToWECtR0Nsfz3m7IBziJLVP/5BcPCIAsCAwEAAaOCAaswggGnMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFCM0+NlSRnAK7UD7dvuzK7DDNbMPMAsG
# A1UdDwQEAwIBhjAQBgkrBgEEAYI3FQEEAwIBADCBmAYDVR0jBIGQMIGNgBQOrIJg
# QFYnl+UlE/wq4QpTlVnkpKFjpGEwXzETMBEGCgmSJomT8ixkARkWA2NvbTEZMBcG
# CgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UEAxMkTWljcm9zb2Z0IFJvb3Qg
# Q2VydGlmaWNhdGUgQXV0aG9yaXR5ghB5rRahSqClrUxzWPQHEy5lMFAGA1UdHwRJ
# MEcwRaBDoEGGP2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1
# Y3RzL21pY3Jvc29mdHJvb3RjZXJ0LmNybDBUBggrBgEFBQcBAQRIMEYwRAYIKwYB
# BQUHMAKGOGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljcm9z
# b2Z0Um9vdENlcnQuY3J0MBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEB
# BQUAA4ICAQAQl4rDXANENt3ptK132855UU0BsS50cVttDBOrzr57j7gu1BKijG1i
# uFcCy04gE1CZ3XpA4le7r1iaHOEdAYasu3jyi9DsOwHu4r6PCgXIjUji8FMV3U+r
# kuTnjWrVgMHmlPIGL4UD6ZEqJCJw+/b85HiZLg33B+JwvBhOnY5rCnKVuKE5nGct
# xVEO6mJcPxaYiyA/4gcaMvnMMUp2MT0rcgvI6nA9/4UKE9/CCmGO8Ne4F+tOi3/F
# NSteo7/rvH0LQnvUU3Ih7jDKu3hlXFsBFwoUDtLaFJj1PLlmWLMtL+f5hYbMUVbo
# nXCUbKw5TNT2eb+qGHpiKe+imyk0BncaYsk9Hm0fgvALxyy7z0Oz5fnsfbXjpKh0
# NbhOxXEjEiZ2CzxSjHFaRkMUvLOzsE1nyJ9C/4B5IYCeFTBm6EISXhrIniIh0EPp
# K+m79EjMLNTYMoBMJipIJF9a6lbvpt6Znco6b72BJ3QGEe52Ib+bgsEnVLaxaj2J
# oXZhtG6hE6a/qkfwEm/9ijJssv7fUciMI8lmvZ0dhxJkAj0tr1mPuOQh5bWwymO0
# eFQF1EEuUKyUsKV4q7OglnUa2ZKHE3UiLzKoCG6gW4wlv6DvhMoh1useT8ma7kng
# 9wFlb4kLfchpyOZu6qeXzjEp/w7FW1zYTRuh2Povnj8uVRZryROj/TGCBMwwggTI
# AgEBMIGQMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xIzAh
# BgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBAhMzAAAAsBGvCovQO5/d
# AAEAAACwMAkGBSsOAwIaBQCggeUwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFLay
# 7MsYtZ6fUPYkgV/Rqi31G2PoMIGEBgorBgEEAYI3AgEMMXYwdKBWgFQAUwB5AHMA
# dABlAG0AIABDAGUAbgB0AGUAcgAgADIAMAAxADIAIABSADIAIAAtACAATwBwAGUA
# cgBhAHQAaQBvAG4AcwAgAE0AYQBuAGEAZwBlAHKhGoAYaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tMA0GCSqGSIb3DQEBAQUABIIBAIp3HdLJWISBDq2qbcYFAi5eMlnl
# VuG8Sv4UCWldSVzUiYm7OoOsqwfjmkX+38s9QnzDc5UrmtWDc/vgHaHZNXaqplyL
# 2/q8i2hCJB34WOn+APIdgzCpnY1dAVDu3WhlRfpltvd9JjPKCXIcA1yTxsHxI1gh
# POEeDB/og5E9ns26OPbVfQearotNCAaADy/t68I4PRDo0dWRipvrBCcvrHij67H2
# UejjtYOfug5uvzuCYSDC6hJBHapF6zHGj/vWG/qnqNgLvdYcEqRlPW39SUEGfabO
# eTLxscJopONHDkYghD9F/x3AWerNvF3CriJlZiU1q6bah/C8ixNAlvzXSlKhggIo
# MIICJAYJKoZIhvcNAQkGMYICFTCCAhECAQEwgY4wdzELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEhMB8GA1UEAxMYTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBAhMzAAAAM+UnhqMOSiqAAAAAAAAzMAkGBSsOAwIaBQCgXTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xMzA5MDYyMzE5MDJa
# MCMGCSqGSIb3DQEJBDEWBBQXwp0LKVkysqYJvf3+p1pVzpIu6TANBgkqhkiG9w0B
# AQUFAASCAQBwKLQZarEszYKqspOzs2oDwvEUKMCUUIhkiQ3BEEmPWN4oyCZJEbJY
# LvIOe/aIZTqy8DAoHlHklYVcMnMmdo5B4DA3CgkNQkbXT3Y7cnFIGrJiia2jiLgV
# c88oHcPPjGmeyR6a+D4AeJQXH0BRRKGj2Yv+b9TMqFo1QClK7lHo7WW9q9mQxJ+W
# iu/AOONjVHg9rlN5sUbZcwpqLQRVXb00nvcuFlIzp9k3qE+9dNaT/N0WPqkBq2ll
# vwgZiPtr/X9KoJ1o1Ppr921IhhaxHa2zZkwl58WsW+po40u1GOQPFzrfZqKWuiWz
# yY5Ty1QSqNFrB71p2z98ds1QdRqQUAhF
# SIG # End signature block

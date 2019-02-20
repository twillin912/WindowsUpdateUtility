# WUU2 #
*Windows Update Utility (WUU) Enhanced.*

This was an update of the PoshPIAG project updated by Tyler Siegrist and Fixed by Phaere in the comment. HanSolo71 put it all together here for others to take over.

***So I did.***

I changed this GUI to fit the needs of my server admins to minimize the toolset they need to perform the work of updating.

## To make this work make sure you ##

- download PSExec and put it in the WUU2 folder.
- create SCOMServer.txt file that holds the name of your SCOM server
  - only on premise tested
- TEST
  - TEST
    - TEST

**Current status:**
- Added Automatic services checks
- Added special services start and stop
- Added SCOM 2012R2 'integration' (place server in maintenance mode before you are able to reboot)
- Added client troubleshooting menu (eventvwr, services, compmgmt)
- Added import computers from WSUS server groups (allow multiple wsus servers)
- Added script to adjust local server firewall to allow inbound connectivity to WSUS client.
  - This also removes any proxy configured for the system account
- 

**Known Issues**
- GUI freezes at 'Install Updates' on servers with high latency connection (accross the globe)

https://docs.microsoft.com/en-us/sysinternals/downloads/psexec


Forked from https://github.com/twillin912/WindowsUpdateUtility



Original Project.

https://gallery.technet.microsoft.com/scriptcenter/Windows-Update-Utility-WUU-1d72e520?fbclid=IwAR0NthM8UCW-ecNrASTC4VDiBROqfpHD_oUpTRU6uEL8PjO8TgEuji7EhKk

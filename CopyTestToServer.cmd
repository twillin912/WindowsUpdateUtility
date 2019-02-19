@ECHO OFF
robocopy c:\test\wuu2 \\VRCWU001.vdlgroep.local\c$\Users\Public\Desktop\WUU2\ /MIR /R:1 /W:1 /Z /MON:1 /XF .git* /XD .git*

pause
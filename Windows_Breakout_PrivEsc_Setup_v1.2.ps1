#------------------
#SYNOPSIS
#   DefCon 24, workshop setup script! The script will create a number of user accounts
#   in various configurations to accompany the course material.
#
#USAGE
#   (1) Download a Windows 10 Virtual Machine from:
#       https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/
#   (2) Boot the machine and log in as IEUser.
#   (3) Launch PowerShell (Desktop App) as Administrator, execute this script and wait
#       for the machine to reboot!
#
#NOTES
#   (1) All user account have their password set to "123" for convenience.
#   (2) Both "restricted1" and "kiosk2" have startup scripts which will log the user
#       out after authenticating for the first time. Be patient, allow this to complete!
#   (3) A tools folder will be provided during the workshop with any tools/scripts
#       which may be required to exploit configuration weaknesses. It is recommended
#       that this folder is put in the "C:" drive to give all accounts access to the
#       files.
#	
#DESCRIPTION
#	Author: Ruben Boonen (@FuzzySec) & Francesco Mifsud (@GradiusX)
#	License: BSD 3-Clause
#	Required Dependencies: None
#	Optional Dependencies: None
#	
#EXAMPLE
#   PS C:\Users\IEUser\Desktop> .\Windows_Breakout_PrivEsc_Setup_v1.2.ps1
#------------------

# Let's make the box insecure!
#--------------
# Disable NotificationCentre
echo "[+] Disabling Notification Centre"
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer |Out-Null
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableNotificationCenter -Value 0x00000001 -Force
# Windows Defender
echo "[+] Disabling Windows Defender"
Set-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 0x00000001 -Force
# Disable SmartScreen
echo "[+] Disabling SmartScreen"
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -Value Off -Force
# Disable WUSA Service
echo "[+] Disabling Windows Update"
Set-Service -Name wuauserv -StartupType Disabled
C:\Windows\system32\sc.exe stop wuauserv | Out-Null

# Optimize
#--------------
# Disable AutoAdminLogon
echo "[+] Disabling AutoLogin for Admin"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -Value 0 -Force
# Disable Sign-in animation
echo "[+] Disabling Sign-in Animation"
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableFirstLogonAnimation -Value 0x00000000 -Force
# Set UI to "Best Performance"
echo "[+] Setting UI to Best Performance"
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects -Name 'VisualFXSetting' -Value 2 -Force

# RunAs user bootstrap
#--------------
# Hax ScriptBlock, some users need a profile to be changed by the script!
$ScriptBlock = {
	param ($username, $password)

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	[StructLayout(LayoutKind.Sequential)]
	public struct PROCESS_INFORMATION
	{
		public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId;
	}
	
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	public struct STARTUPINFO
	{
		public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle;
		public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize; public uint dwXCountChars;
		public uint dwYCountChars; public uint dwFillAttribute; public uint dwFlags; public short wShowWindow;
		public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput;
		public IntPtr hStdError;
	}
	public static class Advapi32
	{
		[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
		public static extern bool CreateProcessWithLogonW(
			String userName,
			String domain,
			String password,
			int logonFlags,
			String applicationName,
			String commandLine,
			int creationFlags,
			int environment,
			String currentDirectory,
			ref  STARTUPINFO startupInfo,
			out PROCESS_INFORMATION processInformation);
    }
"@
	# StartupInfo Struct
	$StartupInfo = New-Object STARTUPINFO
	$StartupInfo.dwFlags = 0x00000001
	$StartupInfo.wShowWindow = 0x0006 # minimize cmd.exe
	$StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo)
	
	# ProcessInfo Struct
	$ProcessInfo = New-Object PROCESS_INFORMATION
	
	# CreateProcessWithLogonW --> lpCurrentDirectory
	$GetCurrentPath = (Get-Item -Path ".\" -Verbose).FullName
	$CallResult = [Advapi32]::CreateProcessWithLogonW($username, ".", $password, 0x1, "C:\Windows\System32\cmd.exe", "", 0x04000000, $null, $GetCurrentPath, [ref]$StartupInfo, [ref]$ProcessInfo)
}

# Helper functions
#--------------

# Create user => pass 123
function Create-User {
    param ($username)
	echo "[+] Creating $username user"
    net user $username /del 2>&1 | Out-Null
    net user $username 123 /add | Out-Null
}

# RunAs user to create profile
function Invoke-User {
    param ($username)
	echo "[+] Invoking $username"
    Start-Job -Name $username -ScriptBlock $ScriptBlock -ArgumentList @($username, "123")| Out-Null
    Wait-Job -Name $username| Out-Null
}

# Get user SID
function Get-SID {
    param ($username)
    (New-Object System.Security.Principal.NTAccount($username)).Translate([System.Security.Principal.SecurityIdentifier]).Value
}

#------------------[AppLocker]

# Create Applocker exempt group
echo "[+] Creating NoApplocker group"
net localgroup NoAppLocker /add | Out-Null
$NoAppSID = Get-SID NoAppLocker

# Create Applocker users
Create-User AppLocker1 | Out-Null
Create-User AppLocker2 | Out-Null

# Get user SID's
$AppSID1 = Get-SID AppLocker1
$AppSID2 = Get-SID AppLocker2

# Fix AppLocker services(Set-Service not reliable here..)
echo "[+] Fixing Applocker Services"
C:\Windows\system32\sc.exe config AppIDSvc start= auto | Out-Null
C:\Windows\system32\sc.exe config AppID start= auto | Out-Null
C:\Windows\system32\sc.exe config CryptSvc start= auto | Out-Null
echo "[+] Starting AppIDSvc service"
Start-Service -Name AppIDSvc

# Applocker Policy XML
#----
# PublisherConditions : {*\*\*,0.0.0.0-*}
# PublisherExceptions : {}
# PathExceptions      : {}
# HashExceptions      : {}
# Id                  : a9e18c21-ff8f-43cf-b9fc-db40eed693ba
# Name                : (Default Rule) All signed packaged apps
# Description         : Allows members of the Everyone group to run packaged apps that are signed.
# UserOrGroupSid      : S-1-1-0
# Action              : Allow
# 
# PathConditions      : {%SYSTEM32%\WindowsPowerShell\v1.0\powershell_ise.exe}
# PathExceptions      : {}
# PublisherExceptions : {}
# HashExceptions      : {}
# Id                  : 492d0ec1-82a2-4770-9641-d195a74391e0
# Name                : %SYSTEM32%\WindowsPowerShell\v1.0\powershell_ise.exe
# Description         : Stop Applocker2 from using powershell_ise
# UserOrGroupSid      : S-1-5-21-1116692041-1164204812-2329106322-1004
# Action              : Deny
# 
# PathConditions      : {%SYSTEM32%\rundll32.exe}
# PathExceptions      : {}
# PublisherExceptions : {}
# HashExceptions      : {}
# Id                  : 4defea71-2dc6-4a01-9f10-198577c6e7e4
# Name                : %SYSTEM32%\rundll32.exe
# Description         : Stop Applocker2 from using rundll
# UserOrGroupSid      : S-1-5-21-1116692041-1164204812-2329106322-1004
# Action              : Allow
# 
# PathConditions      : {%OSDRIVE%\Users\AppLocker1\ProjectFolder\*}
# PathExceptions      : {}
# PublisherExceptions : {}
# HashExceptions      : {}
# Id                  : 560d03c2-b277-4331-8c59-bc7d4eb08359
# Name                : %OSDRIVE%\Users\AppLocker1\ProjectFolder\*
# Description         : Allow AppLocker1 developer access to his project folder!
# UserOrGroupSid      : S-1-5-21-1116692041-1164204812-2329106322-1003
# Action              : Allow
# 
# PathConditions      : {%SYSTEM32%\WindowsPowerShell\v1.0\powershell.exe}
# PathExceptions      : {}
# PublisherExceptions : {}
# HashExceptions      : {}
# Id                  : 626d4d6b-d5b1-46a4-aa1a-d51257af1716
# Name                : %SYSTEM32%\WindowsPowerShell\v1.0\powershell.exe
# Description         : Stop AppLocker1 from using powershell
# UserOrGroupSid      : S-1-5-21-1116692041-1164204812-2329106322-1003
# Action              : Deny
# 
# PathConditions      : {%PROGRAMFILES%\*}
# PathExceptions      : {}
# PublisherExceptions : {}
# HashExceptions      : {}
# Id                  : 921cc481-6e17-4653-8f75-050b80acca20
# Name                : (Default Rule) All files located in the Program Files folder
# Description         : Allows members of the Everyone group to run applications that are located in the Program Files folder.
# UserOrGroupSid      : S-1-1-0
# Action              : Allow
# 
# PathConditions      : {%SYSTEM32%\WindowsPowerShell\v1.0\powershell.exe}
# PathExceptions      : {}
# PublisherExceptions : {}
# HashExceptions      : {}
# Id                  : a0dbe0d9-f8ae-42d9-b75d-095faadf1130
# Name                : %SYSTEM32%\WindowsPowerShell\v1.0\powershell.exe
# Description         : Stop AppLocker2 from using powershell
# UserOrGroupSid      : S-1-5-21-1116692041-1164204812-2329106322-1004
# Action              : Deny
# 
# PathConditions      : {%WINDIR%\*}
# PathExceptions      : {}
# PublisherExceptions : {}
# HashExceptions      : {}
# Id                  : a61c8b2c-a319-4cd0-9690-d2177cad7b51
# Name                : (Default Rule) All files located in the Windows folder
# Description         : Allows members of the Everyone group to run applications that are located in the Windows folder.
# UserOrGroupSid      : S-1-1-0
# Action              : Allow
# 
# PathConditions      : {%SYSTEM32%\cmd.exe}
# PathExceptions      : {}
# PublisherExceptions : {}
# HashExceptions      : {}
# Id                  : bc8480c4-e7d2-433e-bac5-4221b5cb3d5e
# Name                : %SYSTEM32%\cmd.exe
# Description         : Stop AppLocker2 from using cmd
# UserOrGroupSid      : S-1-5-21-1116692041-1164204812-2329106322-1004
# Action              : Deny
# 
# PathConditions      : {%SYSTEM32%\cmd.exe}
# PathExceptions      : {}
# PublisherExceptions : {}
# HashExceptions      : {}
# Id                  : c59717b3-2e65-4f3f-ad61-f0935186b650
# Name                : %SYSTEM32%\cmd.exe
# Description         : Stop AppLocker1 from using cmd
# UserOrGroupSid      : S-1-5-21-1116692041-1164204812-2329106322-1003
# Action              : Deny
# 
# PathConditions      : {%SYSTEM32%\rundll32.exe}
# PathExceptions      : {}
# PublisherExceptions : {}
# HashExceptions      : {}
# Id                  : d99d3b9a-9807-435a-bd4c-9525f6336c77
# Name                : %SYSTEM32%\rundll32.exe
# Description         : Stop Applocker1 from using rundll
# UserOrGroupSid      : S-1-5-21-1116692041-1164204812-2329106322-1003
# Action              : Deny
# 
# PathConditions      : {*}
# PathExceptions      : {}
# PublisherExceptions : {}
# HashExceptions      : {}
# Id                  : f7bf7535-6c0d-4eb4-9778-96131f6771ff
# Name                : *
# Description         : Allow AppLocker exempt users to run everything
# UserOrGroupSid      : S-1-5-21-1116692041-1164204812-2329106322-1010
# Action              : Allow
# 
# PathConditions      : {*}
# PathExceptions      : {}
# PublisherExceptions : {}
# HashExceptions      : {}
# Id                  : fd686d83-a829-4351-8ff4-27c7de5755d2
# Name                : (Default Rule) All files
# Description         : Allows members of the local Administrators group to run all applications.
# UserOrGroupSid      : S-1-5-32-544
# Action              : Allow
#----
$ApplockerPolicy = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Appx" EnforcementMode="NotConfigured">
    <FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba" Name="(Default Rule) All signed packaged apps" Description="Allows members of the Everyone group to run packaged apps that are signed." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>
  <RuleCollection Type="Dll" EnforcementMode="NotConfigured" />
  <RuleCollection Type="Exe" EnforcementMode="NotConfigured">
    <FilePathRule Id="492d0ec1-82a2-4770-9641-d195a74391e0" Name="%SYSTEM32%\WindowsPowerShell\v1.0\powershell_ise.exe" Description="Stop Applocker2 from using powershell_ise" UserOrGroupSid="$AppSID2" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\WindowsPowerShell\v1.0\powershell_ise.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="560d03c2-b277-4331-8c59-bc7d4eb08359" Name="%OSDRIVE%\Users\AppLocker1\ProjectFolder\*" Description="Allow AppLocker1 developer access to his project folder!" UserOrGroupSid="$AppSID1" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%OSDRIVE%\Users\AppLocker1\ProjectFolder\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="626d4d6b-d5b1-46a4-aa1a-d51257af1716" Name="%SYSTEM32%\WindowsPowerShell\v1.0\powershell.exe" Description="Stop AppLocker1 from using powershell" UserOrGroupSid="$AppSID1" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\WindowsPowerShell\v1.0\powershell.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="a0dbe0d9-f8ae-42d9-b75d-095faadf1130" Name="%SYSTEM32%\WindowsPowerShell\v1.0\powershell.exe" Description="Stop AppLocker2 from using powershell" UserOrGroupSid="$AppSID2" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\WindowsPowerShell\v1.0\powershell.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="bc8480c4-e7d2-433e-bac5-4221b5cb3d5e" Name="%SYSTEM32%\cmd.exe" Description="Stop AppLocker2 from using cmd" UserOrGroupSid="$AppSID2" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\cmd.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="c59717b3-2e65-4f3f-ad61-f0935186b650" Name="%SYSTEM32%\cmd.exe" Description="Stop AppLocker1 from using cmd" UserOrGroupSid="$AppSID1" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\cmd.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="(Default Rule) All files located in the Program Files folder" Description="Allows members of the Everyone group to run applications that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="(Default Rule) All files located in the Windows folder" Description="Allows members of the Everyone group to run applications that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="(Default Rule) All files" Description="Allows members of the local Administrators group to run all applications." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="f7bf7535-6c0d-4eb4-9778-96131f6771ff" Name="*" Description="Allow AppLocker exempt users to run everything" UserOrGroupSid="$NoAppSID" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="d99d3b9a-9807-435a-bd4c-9525f6336c77" Name="%SYSTEM32%\rundll32.exe" Description="Stop Applocker1 from using rundll" UserOrGroupSid="$AppSID1" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\rundll32.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="4defea71-2dc6-4a01-9f10-198577c6e7e4" Name="%SYSTEM32%\rundll32.exe" Description="Stop Applocker2 from using rundll" UserOrGroupSid="$AppSID2" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%SYSTEM32%\rundll32.exe" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="NotConfigured" />
  <RuleCollection Type="Script" EnforcementMode="NotConfigured" />
</AppLockerPolicy>
"@

echo "[+] Applying AppLocker Policy"
$ApplockerPolicy > $Env:USERPROFILE\AppLockerPolicy.xml
Set-AppLockerPolicy -XmlPolicy $Env:USERPROFILE\AppLockerPolicy.xml

#------------------[restricted]

# Create restricted users
Create-User restricted1 | Out-Null
Create-User restricted2 | Out-Null

# Exempt restricted from AppLocker
echo "[+] Adding restricted1 and restricted2 users to NoAppLocker group"
net localgroup NoAppLocker restricted1 /add | Out-Null
net localgroup NoAppLocker restricted2 /add | Out-Null

# Get restricted2 SID & Invoke
$RestrictedSID = Get-SID restricted2
Invoke-User restricted2

# Allow only notepad.exe for restricted2
echo "[+] Applying restrictions to restricted2"
reg add HKU\$RestrictedSID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v RestrictRun /t REG_DWORD /d 1  | Out-Null
reg add HKU\$RestrictedSID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\RestrictRun /v notepad.exe /t REG_SZ /d notepad.exe | Out-Null

#------------------[Kiosk]

# Create Kiosk users
Create-User Kiosk1 | Out-Null
Create-User Kiosk2 | Out-Null

# Exempt kiosk from AppLocker
echo "[+] Adding Kiosk1 and Kiosk2 users to NoAppLocker group"
net localgroup NoAppLocker Kiosk1 /add | Out-Null
net localgroup NoAppLocker Kiosk2 /add | Out-Null

# Get kiosk1 SID & Invoke
$KioskSID1 = Get-SID Kiosk1
Invoke-User Kiosk1

# Poor lockdown, set kiosk1 login shell to "iexplore -k"
echo "[+] Applying kiosk lockdown to kiosk1"
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
New-Item -Path HKU:\$KioskSID1\Software\Microsoft\Windows\CurrentVersion\Policies\System | Out-Null
Set-ItemProperty -Path HKU:\$KioskSID1\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name Shell -Value "C:\Program Files\Internet Explorer\iexplore.exe -k" -Force | Out-Null

#------------------[Schtasks bootstrap for restricted1 & kiosk2]

$PSSchtasksScript = @"

function Get-SID {
	param (`$username)
	(New-Object System.Security.Principal.NTAccount(`$username)).Translate([System.Security.Principal.SecurityIdentifier]).Value
}

`$LoggedOn = (Get-WMIObject -class Win32_ComputerSystem).username

if (`$(`$LoggedOn -match "kiosk2") -eq `$true){
	if (!(Get-AssignedAccess)) {
		Set-AssignedAccess -UserName Kiosk2 -AppUserModelId Microsoft.Windows.Photos_8wekyb3d8bbwe!App
		
		`$KioskID = ((quser) -replace '\s{2,}', ',' |ConvertFrom-Csv |Where-Object {`$_.USERNAME -match "kiosk2"}).ID
		logoff `$KioskID
	}
}
if (`$(`$LoggedOn -match "restricted1") -eq `$true){
	`$SID = Get-SID restricted1
	New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
	`$settingsApplied = Test-Path -Path HKU:\`$SID\Software\Policies\Microsoft\Windows\System
	if (`$settingsApplied -eq `$false) {	
		reg add HKU\`$SID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoViewContextMenu /t REG_DWORD /d 0x00000001
		reg add HKU\`$SID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoTrayContextMenu /t REG_DWORD /d 0x00000001
		reg add HKU\`$SID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoRecentDocsNetHood /t REG_DWORD /d 0x00000001
		reg add HKU\`$SID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v DisallowCPL /t REG_DWORD /d 0x00000001
		reg add HKU\`$SID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoChangeKeyboardNavigationIndicators /t REG_DWORD /d 0x00000001
		reg add HKU\`$SID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoFind /t REG_DWORD /d 0x00000001
		reg add HKU\`$SID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoShellSearchButton /t REG_DWORD /d 0x00000001
		reg add HKU\`$SID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDriveAutoRun /t REG_DWORD /d 0x00000001
		reg add HKU\`$SID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoNetHood /t REG_DWORD /d 0x00000001
		reg add HKU\`$SID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoSetTaskbar /t REG_DWORD /d 0x00000001
		reg add HKU\`$SID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoStartMenuSubFolders /t REG_DWORD /d 0x00000001
		reg add HKU\`$SID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoClose /t REG_DWORD /d 0x00000001
		reg add HKU\`$SID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDesktop /t REG_DWORD /d 0x00000001
		reg add HKU\`$SID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDrives /t REG_DWORD /d 0x00000001
		reg add HKU\`$SID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoRun /t REG_DWORD /d 0x00000001
		reg add HKU\`$SID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoCommonGroups /t REG_DWORD /d 0x00000001
		reg add HKU\`$SID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoSetFolders /t REG_DWORD /d 0x00000001
		reg add HKU\`$SID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoControlPanel /t REG_DWORD /d 0x00000001
		reg add HKU\`$SID\Software\Policies\Microsoft\Windows\System /v DisableCMD /t REG_DWORD /d 0x00000002
		reg add HKU\`$SID\Software\Microsoft\Windows\CurrentVersion\Search /v SearchboxTaskbarMode /t REG_DWORD /d 0x00000000
		
		gpupdate
		`$restricted1ID = ((quser) -replace '\s{2,}', ',' |ConvertFrom-Csv |Where-Object {`$_.USERNAME -match "restricted1"}).ID
		logoff `$restricted1ID
	}
}
"@

echo "[+] Creating onlogon scheduled task for restricted1 and kiosk2"
$PSSchtasksScript.replace("`n", "`r`n") | Out-File -FilePath "C:\Users\IEUser\schtasks.ps1" -Encoding ascii
schtasks /create /ru "NT AUTHORITY\SYSTEM" /rp "" /tn "SetupTask" /tr "powershell -File C:\Users\IEUser\schtasks.ps1" /sc onlogon  | Out-Null

#------------------[Setup Lowpriv]

# Create & invoke lowpriv user
Create-User lowpriv | Out-Null
Invoke-User lowpriv

# Exempt lowpriv from AppLocker
echo "[+] Adding lowpriv to NoAppLocker group"
net localgroup NoAppLocker lowpriv /add | Out-Null

# Vulnerable Services
#--------------
echo "[+] Creating folder structures for vulnerable services"
New-Item -ItemType Directory -Path "C:\Defcon\Vuln Folder 1" -Force | Out-Null
New-Item -ItemType Directory -Path "C:\Defcon\VulnFolder2" -Force | Out-Null
New-Item -ItemType Directory -Path "C:\Defcon\VulnFolder3" -Force | Out-Null

copy C:\Windows\System32\snmptrap.exe "C:\Defcon\Vuln Folder 1\anything.exe"
copy C:\Windows\System32\snmptrap.exe "C:\Defcon\VulnFolder2\anything.exe"
copy C:\Windows\System32\snmptrap.exe "C:\Defcon\VulnFolder3\anything.exe"

# Deny access to "Vuln Folder 1" & "VulnFolder3"
echo "[+] Applying folder restrictions to 'Vuln Folder 1' and 'VulnFolder3'"
$Acl = Get-Acl "C:\Defcon\Vuln Folder 1"
$ServAr = New-Object System.Security.AccessControl.FileSystemAccessRule("lowpriv", "Modify", "Deny")
$Acl.SetAccessRule($ServAr)
Set-Acl "C:\Defcon\Vuln Folder 1" $Acl

$Acl = Get-Acl "C:\Defcon\VulnFolder3"
$Acl.SetAccessRule($ServAr)
Set-Acl "C:\Defcon\VulnFolder3" $Acl

# Create Services
echo "[+] Creating vulnerable services"
New-Service vulnService1 -Description "Unquoted Service Path" "C:\Defcon\Vuln Folder 1\anything.exe" | Out-Null
New-Service vulnService2 -Description "Weak Folder Permissions" "C:\Defcon\VulnFolder2\anything.exe" | Out-Null
New-Service vulnService3 -Description "Weak Service Permissions" "C:\Defcon\VulnFolder3\anything.exe" | Out-Null

# vulnService3 give Everyone all permissions
#----
# accesschk.exe -ucqv vulnService3
# vulnService3
#   Medium Mandatory Level (Default) [No-Write-Up]
#   RW NT AUTHORITY\SYSTEM
#         SERVICE_ALL_ACCESS
#   RW Everyone
#         SERVICE_ALL_ACCESS
#   RW BUILTIN\Administrators
#         SERVICE_ALL_ACCESS
#   R  NT AUTHORITY\INTERACTIVE
#         SERVICE_QUERY_STATUS
#         SERVICE_QUERY_CONFIG
#         SERVICE_INTERROGATE
#         SERVICE_ENUMERATE_DEPENDENTS
#         SERVICE_USER_DEFINED_CONTROL
#         READ_CONTROL
#   R  NT AUTHORITY\SERVICE
#         SERVICE_QUERY_STATUS
#         SERVICE_QUERY_CONFIG
#         SERVICE_INTERROGATE
#         SERVICE_ENUMERATE_DEPENDENTS
#         SERVICE_USER_DEFINED_CONTROL
#         READ_CONTROL
#----
echo "[+] Modifying permissions on vulnService3"
C:\Windows\System32\sc.exe sdset vulnService3 "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;DCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"    | Out-Null

# Registry Password
#--------------
echo "[+] Inserting password in registry"
Set-ItemProperty -Path HKLM:\SYSTEM\Setup -Name Administrator -Value "password:U3VwZXJMZWdpdFBhc3N3b3JkIQ=="

# Unattended Install Example
#--------------
echo "[+] Creating Unattend folder and file"
New-Item -ItemType Directory -Path C:\Windows\Panther\Unattend -Force | Out-Null

$UnattendXML = @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
   <settings pass="generalize" wasPassProcessed="true">
      <component name="Microsoft-Windows-PnpSysprep" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
         <PersistAllDeviceInstalls>true</PersistAllDeviceInstalls>
      </component>
   </settings>
   <settings pass="oobeSystem" wasPassProcessed="true">
      <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
         <OOBE>
            <SkipMachineOOBE>true</SkipMachineOOBE>
            <HideEULAPage>true</HideEULAPage>
            <SkipUserOOBE>true</SkipUserOOBE>
            <ProtectYourPC>1</ProtectYourPC>
         </OOBE>
         <TimeZone>W. Europe Standard Time</TimeZone>
         <UserAccounts>
            <AdministratorPassword>U3VwZXJMZWdpdFBhc3N3b3JkIQ==</AdministratorPassword>
         </UserAccounts>
      </component>
   </settings>
   <settings pass="specialize" wasPassProcessed="true">
      <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
         <RegisteredOwner>TheDevil</RegisteredOwner>
         <RegisteredOrganization>Evil_Inc</RegisteredOrganization>
         <ProductKey>Bogus-Product-Key</ProductKey>
         <ComputerName>BSides-Workshop</ComputerName>
      </component>
      <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
         <Identification>
            <JoinWorkgroup>WORKGROUP</JoinWorkgroup>
         </Identification>
      </component>
      <component name="Microsoft-Windows-TCPIP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
         <Interfaces>
            <Interface wcm:action="add">
               <Ipv4Settings>
                  <DhcpEnabled>false</DhcpEnabled>
               </Ipv4Settings>
               <UnicastIpAddresses>
                  <IpAddress wcm:action="add" wcm:keyValue="1">10.0.0.1/24</IpAddress>
               </UnicastIpAddresses>
               <Ipv6Settings>
                  <DhcpEnabled>true</DhcpEnabled>
               </Ipv6Settings>
               <Identifier>00-50-56-9e-69-fc</Identifier>
               <Routes>
                  <Route wcm:action="add">
                     <Identifier>1</Identifier>
                     <Prefix>0.0.0.0/0</Prefix>
                     <NextHopAddress>10.0.0.1</NextHopAddress>
                  </Route>
               </Routes>
            </Interface>
         </Interfaces>
      </component>
      <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
         <Interfaces>
            <Interface wcm:action="add">
               <Identifier>00-50-56-9e-69-fc</Identifier>
               <DNSServerSearchOrder>
                  <IpAddress wcm:action="add" wcm:keyValue="1">8.8.8.8</IpAddress>
               </DNSServerSearchOrder>
            </Interface>
         </Interfaces>
      </component>
      <component name="Microsoft-Windows-NetBT" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
         <Interfaces>
            <Interface wcm:action="add">
               <Identifier>00-50-56-9e-69-fc</Identifier>
               <NetbiosOptions>0</NetbiosOptions>
            </Interface>
         </Interfaces>
      </component>
   </settings>
</unattend>
"@

$UnattendXML.replace("`n", "`r`n") | Out-File -FilePath "C:\Windows\Panther\Unattend\unattend.xml" -Encoding ascii | Out-Null

# Scheduled task
#--------------
echo "[+] Creating folder structure for vulnerable scheduled task"
New-Item -ItemType Directory -Path C:\Backup\LogOutput -Force | Out-Null

# Create mock log files
echo "[+] Creating mock log files"
for($i=0; $i -lt 4; $i++){
    echo "Mock backup log data!" > C:\Backup\LogOutput\FTP_logs_$i.txt
}

# Sample FTP conf file
echo "[+] Creating sample FTP config file"
echo "open 10.1.1.10 21" > C:\Backup\connect.txt
echo "username" >> C:\Backup\connect.txt
echo "password" >> C:\Backup\connect.txt
echo "GET C:\SystemCheck\dailyLogs.log C:\Backup\LogOutput\FTP_logs.txt" >> C:\Backup\connect.txt
echo "bye" >> C:\Backup\connect.txt

# Create FTP backup task (some hax for the taskname..)
echo "[+] Creating vulnerable scheduled task"
copy "C:\Windows\system32\ftp.exe" "C:\Backup\ftp.exe"
schtasks /create /ru "NT AUTHORITY\SYSTEM" /rp "" /tn "\Microsoft\Windows Defender\FTP_Backup" /tr "C:\Backup\ftp.exe -s:C:\Backup\connect.txt" /sc daily /st 12:34   | Out-Null

# Possible Patches for MS16-032, only 1 will actually be installed
#--------------
$Patches = @("3140743", "3135174", "3140768", "3140745")
$DSIMPackages = dism /online /get-packages
ForEach ($Patch in $Patches) {
	if ($(wmic qfe |findstr $Patch)){
		echo "[+] Uninstalling KB$Patch"
		$Uninstall = $DSIMPackages.split(":").split(" ") |findstr $Patch
		dism /online /remove-package /packagename:$Uninstall /quiet /norestart # wusa not working silently..
	}
}

# AlwaysInstallElevated
#--------------
$LowprivSID = Get-SID lowpriv

echo "[+] Enabling AlwaysInstallElevated registry key"
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer |Out-Null
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -Value 0x00000001 -Force
New-Item -Path HKU:\$LowprivSID\SOFTWARE\Policies\Microsoft\Windows\Installer |Out-Null
Set-ItemProperty -Path HKU:\$LowprivSID\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -Value 0x00000001 -Force

#------------------[Rename Administrator]

# Rename standard IEUser -> Admin & set password -> 123 [HomeDir still: C:\Users\IEUser\*]
#--------------
echo "[+] Renaming IEUser to Admin and changing password to '123'"
([adsi]"WinNT://./IEUser").psbase.Rename("Admin") |Out-Null
net user Admin 123 /fullname:"Admin" |Out-Null

echo "[+] Done"

#------------------[Reboot]

Restart-Computer
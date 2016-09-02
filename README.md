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
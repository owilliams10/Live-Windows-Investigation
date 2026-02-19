# Live Windows Investigation with PowerShell

## Introduction

In this project, I used PowerShell commands to check a Windows system for compromise. Here is what I accomplished:

- Show which programs are running
- Show the network connections and listening ports
- Determine if any user accounts were added on the system
- Identify registry keys associated with Auto Start Extensibility Points (ASEPs)
- Determine if any scheduled tasks were added to the system
- Determine if any services were added to the system
- Remove malware from the system

# Live Windows Investigation with PowerShell

Run various PS commands to check a Windows computer for signs of a possible compromise, and remove malware.

These commands can also be helpful for building a baseline of the system; this baseline can be compared against to help identify anomalous or malicious activity.

Open an admin PowerShell session:

<img width="547" height="502" alt="image" src="https://github.com/user-attachments/assets/2dfb7a6f-5873-4037-9895-a61e8bac0fc1" />


# Process Enumeration

Investigate the running processes on a Windows system.

Goal: Show running processes

Command: Get-Process

<img width="698" height="826" alt="image" src="https://github.com/user-attachments/assets/bbde5ed6-a08b-4165-b5be-b0f04f2d2026" />

<p>&nbsp;</p>

Goal: Get more details about a specific process

Command: Get-Process lsass

<img width="642" height="118" alt="image" src="https://github.com/user-attachments/assets/0d63fddf-883f-4d10-baed-48f4dc863622" />

<p>&nbsp;</p>

Goal: Output all process fields for a specific process to see all available info

Command: Get-Process lsass | Select-Object -Property *

<img width="982" height="868" alt="image" src="https://github.com/user-attachments/assets/ffa5b9b1-ba39-4386-b9ad-1df8e4764150" />

<p>&nbsp;</p>

Goal: Display more concise and easier to parse process data by requesting specific attributes that are common to attacker TTPs

Command: Get-Process | Select-Object -Property Path, Name, Id

<img width="1217" height="721" alt="image" src="https://github.com/user-attachments/assets/104ef8b7-0eff-4270-923e-348add83cf6f" />

<p>&nbsp;</p>

Goal: Filter results to match a certain condition

Command: Get-Process | Select-Object -Property Path, Name, Id | Where-Object -Property Name -eq explorer

<img width="1141" height="116" alt="image" src="https://github.com/user-attachments/assets/0d9aa503-3344-4b28-a0b6-6944175125b3" />

<p>&nbsp;</p>

Goal: Filter for processes running from temporary directories

Command: Get-Process | Select-Object -Property Path, Name, Id | Where-Object -Property Path -Like “*temp*”

<img width="1082" height="144" alt="image" src="https://github.com/user-attachments/assets/151e78d7-2400-43f2-a574-87ad0c1b1562" />


# Network Enumeration

Investigate the network listeners and connections on a Windows system.

Goal: Display a list of network connections on the host.

Command: Get-NetTCPConnection

<img width="1213" height="507" alt="image" src="https://github.com/user-attachments/assets/7750e298-175d-4c4d-969a-d158e05acc63" />

<p>&nbsp;</p>

Goal: Map local TCP sockets to their owning process IDs and identify which processes are listening or have active network connections.

Command: Get-NetTCPConnection | Select-Object -Property LocalAddress, LocalPort, State, OwningProcess

<img width="1108" height="504" alt="image" src="https://github.com/user-attachments/assets/117e7573-3712-4377-bde5-847a38ccc416" />
_note the process ID listening on port 4444 which is associated with Metasploit_

<p>&nbsp;</p>

Goal: Use the process ID from the process listening on the suspicious port (4444) to find the name of the process

Command: Get-Process | Select-Object -Property Path, Name, ID | Where-Object -Property Id -eq 6800

<img width="1082" height="105" alt="image" src="https://github.com/user-attachments/assets/74af814c-b8a4-438a-87a9-9f5dda513eee" />
_calcache is the same process we found earlier to be running from a temporary directory0_

<p>&nbsp;</p>

Goal: Terminate the suspicious process then confirm that it has stopped.

Command: Get-Process | Select-Object -Property Path, Name, ID | Where-Object -Property Id -eq 6800 | Stop-Process

Command: Get-Process calcache

<img width="1218" height="164" alt="image" src="https://github.com/user-attachments/assets/b1731bae-5f99-4809-9e4f-b471671ac443" />


# Registry Startup Keys

Investigate processes that start automatically to determine how the attacker launched the suspicious process we discovered in previous steps.

Processes can be started automatically by creating a registry value in the Windows **Run** or **RunOnce** **registry keys.**

These are **ASEP (Autostart Extensibility Points) registry keys** which are used to automatically start Windows processes when the system boots or when a user logs in.

4 Common ASEP registry keys:

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce

Goal: Enumerate the PowerShell drive HKCU:.

Command: Get-ChildItem HKCU:

<img width="687" height="409" alt="image" src="https://github.com/user-attachments/assets/6b03ca9e-c8e2-4c48-b70d-80ceca3e82db" />
_Name = key, Property = key value; registry values in top-level keys for the HKEY_CURRENT_USER hive_

<p>&nbsp;</p>

Goal: Enumerate registry values in a specific key; check for processes in the ASEP registry keys.

Command: Get-ItemProperty “HKLM:\Software\Microsoft\Windows\CurrentVersion\Run”

<img width="1105" height="211" alt="image" src="https://github.com/user-attachments/assets/d651bc80-de55-4053-a7f1-0767cbb660ca" />
_2 programs present: “SecurityHealth” & “VMware User Process”_

Command: Get-ItemProperty “HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce”

<img width="966" height="62" alt="image" src="https://github.com/user-attachments/assets/6193450e-d69c-454a-8be4-559bcf2aa15b" />
_no registry values present_

Command: Get-ItemProperty “HKCU:\Software\Microsoft\Windows\CurrentVersion\Run”

<img width="1458" height="221" alt="image" src="https://github.com/user-attachments/assets/bc53cad6-0c9e-4815-b3e5-9c003a7d212c" />
_there’s a “Calcache” program here that corresponds with the calcache process we discovered earlier_

Command: Get-ItemProperty “HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce”

<img width="952" height="52" alt="image" src="https://github.com/user-attachments/assets/2a12887e-31fd-46c3-82de-1615c321eb9b" />
_no registry values present_

<p>&nbsp;</p>

Goal: Remove the calcache ASEP value from the Run key, then confirm it was successfully removed.

Command: Remove-ItemProperty -Path “HKCU:\Software\Microsoft\Windows\CurrentVersion\Run” -Name “Calcache”

Command: Get-ItemProperty “HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\Calcache” -Name “Calcache”

<img width="1174" height="172" alt="image" src="https://github.com/user-attachments/assets/e5d60707-8b85-4e03-8c61-24bfb15bd29b" />

<p>&nbsp;</p>

Goal: Remove the calcache.exe program, then confirm it was successfully removed.

Command: Remove-Item $env:temp\calcache.exe

Command: Get-ChildItem $env:temp\calcache.exe

<img width="1150" height="171" alt="image" src="https://github.com/user-attachments/assets/cd307302-87cc-434d-8664-b480e7818d71" />


# Differential Analysis

Taking a snapshot of a known-good baseline state for a system, then comparing it against the current environment to **look for other ways the adversary could have deployed malware on the system.**

Goal: List the files that store known-good states for the Services, Scheduled Tasks, and User Accounts.

Command: Get-ChildItem baseline

<img width="620" height="225" alt="image" src="https://github.com/user-attachments/assets/09ef55af-658e-40b6-8cdc-107b69793005" />

<p>&nbsp;</p>

Goal: Capture the current state of the system’s Services, Scheduled Tasks, and User Accounts in separate files to later be compared to the baseline files.

Command: Get-Service | Select-Object -ExpandProperty Name | Out-File services.txt

Command: Get-ScheduledTask | Select-Object -ExpandProperty TaskName | Out-File scheduledtasks.txt

Command: Get-LocalUser | Select-Object -ExpandProperty Name | Out-File localusers.txt

<img width="1074" height="89" alt="image" src="https://github.com/user-attachments/assets/99785cb1-540f-40cb-a83b-12628419ec1c" />


## Services Differential Analysis

Goal: Save the current state of the system’s services into a variable.

Command: $servicesnow = Get-Content .\services.txt

<img width="656" height="20" alt="image" src="https://github.com/user-attachments/assets/c231be69-e3ae-4cd4-9e1f-2c4b7ee99c2b" />

<p>&nbsp;</p>

Goal: Save the known-good baseline state of the services into a variable.

Command: $servicesbaseline = Get-Content baseline\services.txt

<img width="765" height="48" alt="image" src="https://github.com/user-attachments/assets/769ce9ce-fa94-4088-8c0d-c4fda01d8edf" />

<p>&nbsp;</p>

Goal: Compare the 2 variables to find the differences

Command: Compare-Object $servicesbaseline $servicesnow

<img width="696" height="110" alt="image" src="https://github.com/user-attachments/assets/971c0a01-b09c-4aea-8b14-f1ead5eaddb8" />
_a new service called Dynamics was found_

## Users Differential Analysis

Goal: Save the current state of the system’s user accounts into a variable.

Command: $usersnow = Get-Content .\localusers.txt

<img width="646" height="30" alt="image" src="https://github.com/user-attachments/assets/68aeb799-536c-4811-b667-ef9ef5bc7b36" />

<p>&nbsp;</p>

Goal: Save the known-good baseline state of the user accounts into a variable.

Command: $usersbaseline = Get-Content .\baseline\localusers.txt

<img width="767" height="28" alt="image" src="https://github.com/user-attachments/assets/f16ca915-2de6-47a9-9c70-ec5e2d5ba1f6" />

<p>&nbsp;</p>

Goal: Compare the 2 variables to find the differences

Command: Compare-Object $usersbaseline $usersnow

<img width="636" height="108" alt="image" src="https://github.com/user-attachments/assets/802eef95-c5e7-4c80-aded-1ec6f96cc02e" />
_there’s an added username: dynamics_

## Scheduled Tasks Differential Analysis

Goal: Display a list of scheduled tasks on the system.

Command: Get-ScheduledTask

<img width="816" height="427" alt="image" src="https://github.com/user-attachments/assets/60b4e9fe-f698-40de-9c4c-c61bec6b9ae8" />

<p>&nbsp;</p>

Goal: Save the current state of the system’s scheduled tasks into a variable.

Command: $scheduledtasksnow = Get-Content .\localusers.txt

<img width="765" height="26" alt="image" src="https://github.com/user-attachments/assets/6201d65b-033a-4ab9-b197-7f8aa343b9aa" />

<p>&nbsp;</p>

Goal: Save the known-good baseline state of the scheduled tasks into a variable.

Command: $scheduledtasksbaseline = Get-Content .\baseline\scheduledtasks.txt

<img width="883" height="23" alt="image" src="https://github.com/user-attachments/assets/4240962e-e088-41b9-a756-e5ec6f2307e5" />

<p>&nbsp;</p>

Goal: Compare the 2 variables to find the differences

Command: Compare-Object $scheduledtasksbaseline $scheduledtasksnow

<img width="801" height="138" alt="image" src="https://github.com/user-attachments/assets/7be39fd8-9510-4ac0-baa9-eee68c27dafc" />
_a Microsoft Dynamics scheduled task was added_

# Scheduled Task Detail

Goal: Examine the contents of the scheduled task.

Command: Export-ScheduledTask -TaskName “Microsoft eDynamics”

<img width="748" height="846" alt="image" src="https://github.com/user-attachments/assets/377c20e4-8d78-4c70-a178-d2a704287608" />

<p>&nbsp;</p>

- In the Actions closing tag we can see a command is launched: C:\WINDOWS\dynamics.exe
- sc.exe is used to start the service “dynamics” whenever this task is executed
- Confirm with stakeholders if this is expected or anomalous behavior

# Cleaning up the system; Removing Microsoft eDynamics

Complete the steps necessary to clean up the system.

Here are the components of the malicious software that we discovered via scheduled task analysis and differential analysis techniques:

- a service named dynamics via differential analysis
- a process named dynamics via detailed scheduled task analysis
- a program named C:\WINDOWS\dynamics.exe via detailed scheduled task analysis
- a scheduled task named Microsoft eDynamics via differential analysis
- a local user account named dynamics via differential analysis

Goal: Stop the Dynamics service.

Command: Stop-Service -Name Dynamics

<img width="532" height="28" alt="image" src="https://github.com/user-attachments/assets/58ff5399-0315-4e22-b51e-cebe5649b1a9" />

<p>&nbsp;</p>

Goal: Stop the Dynamics process.

Command: Get-Process dynamics | Stop-Process

<img width="597" height="30" alt="image" src="https://github.com/user-attachments/assets/824550e6-6e46-42d0-af0f-9502e439a5b4" />

<p>&nbsp;</p>

Goal: Remove the dynamics.exe folder from the C:\WINDOWS directory.

Command: Remove-Item C:\Windows\Dynamics.exe

<img width="602" height="27" alt="image" src="https://github.com/user-attachments/assets/197ec88d-23ce-404f-b70f-f3b2348eb9c4" />

<p>&nbsp;</p>

Goal: Remove the the service.

Command: Remove-CimInstance: Get-CimInstance -ClassName Win32_Service -Filter “Name= ‘Dynamics’ ” | Remove-CimInstance
**this is the command for Windows 10 w/ PS versions before 6.0**

Goal: Delete the the service.

Command: sc.exe delete dynamics

<img width="486" height="48" alt="image" src="https://github.com/user-attachments/assets/7b6d1f95-475b-47c0-82b2-8a868f2dca40" />
_this is a legacy Windows CMD utility_

<p>&nbsp;</p>

Goal: Remove the scheduled task.

Command: Unregister-ScheduledTask -TaskName “Microsoft eDynamics”

<img width="813" height="131" alt="image" src="https://github.com/user-attachments/assets/7142f0ff-7d6a-45ba-9209-3c01b4ffd579" />

<p>&nbsp;</p>

Goal: Remove the local user account.

Command: Remove-LocalUser -Name dynamics

<img width="558" height="28" alt="image" src="https://github.com/user-attachments/assets/be715634-fc0d-4b83-a8f5-e80dc2f39518" />

<p>&nbsp;</p>

## Conclusion

In this project, we used several different PowerShell techniques, including differential analysis, to identify Indicators of Compromise (IOC) and remove malware from our system. 

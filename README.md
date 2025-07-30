# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Varshithakumble/Threat-Hunting-Scenario-Tor-Browser-Usage-/blob/main/threat-hunting-scenario-tor-event-creation.md)

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>



## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "varshitha" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-07-11T03:17:35.7200269Z`. These events began at `2025-07-11T03:05:37.9271247Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
|where DeviceName == "var-windowsmach"
|where InitiatingProcessAccountName == "varshitha"
| where FileName contains "tor"
|where Timestamp >= datetime(2025-07-11T03:05:37.9271247Z)
|order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="1081" height="496" alt="image" src="https://github.com/user-attachments/assets/b73ed014-2b31-480c-a9d5-773f93a46798" />





---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.4.exe". Based on the logs returned, at `2025-07-14T00:30:16.568659Z`, an employee on the "var-windowsmach" device ran the file `tor-browser-windows-x86_64-portable-14.5.4.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
|where DeviceName == "var-windowsmach"
|where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.4"
|project Timestamp, DeviceName, ActionType,AccountName, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1114" height="387" alt="image" src="https://github.com/user-attachments/assets/189b2cbd-c0cb-4c7f-9393-178ff827d73a" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "varshitha" actually opened the TOR browser. There was evidence that they did open it at `2025-07-14T00:31:08.8102828Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
|where DeviceName == "var-windowsmach"
|where FileName  has_any ("tor.exe","tor-browser.exe","firefox.exe")
|project Timestamp, DeviceName, ActionType,AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
|order by Timestamp desc
```
<img width="1053" height="498" alt="image" src="https://github.com/user-attachments/assets/f6571860-e2ec-4563-9101-2a3d39aa4891" />




 
---


### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-07-14T00:31:14.5409513Z`, an employee on the "varshitha" device successfully established a connection to the remote IP address `127.0.0.1 on port 9150`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\varshitha\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At 2025-07-14T00:31:14.5409513Z, an user “varshitha” on the ""var-windowsmach"" device successfully established a connection to the remote IP address 127.0.0.1 on port 9150. The connection was initiated by the process tor.exe, located in the folder c:\users\varshitha\desktop\tor browser\browser\torbrowser\tor\tor.exe. There were a couple of other connections to sites over port 443....

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1090" height="496" alt="image" src="https://github.com/user-attachments/assets/409f859b-8ee8-40ef-a95d-0a6fd2f467bc" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-07-11T03:05:37.9271247Z`
- **Event:** The user "varshitha" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.4.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\varshitha\Downloads\tor-browser-windows-x86_64-portable-14.5.4.exe `

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-07-14T00:30:16.568659Z`
- **Event:** The user "varshitha" executed the file `tor-browser-windows-x86_64-portable-14.5.4.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.4.exe /S`
- **File Path:** `C:\Users\varshitha\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-07-14T00:31:08.8102828Z.`
- **Event:** User "varshitha" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\varshitha\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\varshitha\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `65.109.0.210` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "varshitha" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-07-11T03:17:35.7200269Z`
- **Event:** The user "varshitha" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\varshitha\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---

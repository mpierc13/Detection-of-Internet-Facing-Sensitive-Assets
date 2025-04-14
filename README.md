# **Detection of Internet-facing sensitive assets**

![image](https://github.com/user-attachments/assets/a4744b95-b3d0-4da0-888d-f292e9789277)



## Example Scenario:
During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources. Internal shared services device (e.g., a domain controller) is mistakenly exposed to the internet due to misconfiguration.

---

## Table:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceInfo|
| **Info**| [Microsoft Defender Info](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table)|
| **Purpose**| The DeviceInfo table in the advanced hunting schema contains information about devices in the organization, including OS version, active users, and computer name.|

---

### **Timeline Overview**  
1. **Archiving Activity:**  
   - **Observed Behavior:**  Windows-target-1 has been internet-facing for several days, the public IPAddress was in the Logs. Last Internet facing time: `2025-04-07T14:15:12.261765Z`
  
   - **Detection Query:**
```kql
DeviceFileEvents
| top 20 by Timestamp desc
```
```kql
DeviceNetworkEvents
| top 20 by Timestamp desc
```
```kql
DeviceProcessEvents
| top 20 by Timestamp desc
```
```kql
  DeviceInfo
| where DeviceName == "windows-target-1" 
| where IsInternetFacing == true
| order by Timestamp desc
```

## Sample Output:

![image](https://github.com/user-attachments/assets/f5925fc4-2988-411f-b01d-1af7c6d801bf)




---

### Brute Force Attempts Detection

Several bad actors have been discovered attempting to log into the target machine.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```

![image](https://github.com/user-attachments/assets/b972a094-9fe7-40a8-baac-a7cfc5487644)



---

The top 5 most failed login attempt IP addresses have not been able to successfully break into VM.

```kql
let RemoteIPsInQuestion = dynamic(["91.238.181.40","88.214.25.117", "147.45.112.29", "185.42.12.205", "88.214.25.112"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

**<Query no results>**

---

The only successful remote/network logins in the last 30 days for 'labuser' account (8 total):

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize count()
```

There were zero (0) failed logons for the 'labuser' account, indicating that a brute force attempt for this account didn't take place, and a 1-time password guess is unlikely.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser"
| summarize count()
```

---

I checked all of the successful login IP addresses for the 'labuser' account to see if any of them were unusual or from an unexpected location. All were normal.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```

![image](https://github.com/user-attachments/assets/9e99e711-bc15-4e82-be69-29fc8b70f25c)


---

Though the device was exposed to the internet and clear brute force attempts have taken place, there is no evidence of any brute force success or unauthorized access from the legitimate account 'labuser'.

Here's how the relevant TTPs and detection elements can be organized into a chart for easy reference:

---

# MITRE ATT&CK TTPs for Incident Detection

| Technique ID | Technique Name                       | Description                                                                                          | Detection Notes                                                                 |
|--------------|--------------------------------------|------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| T1190        | Exploit Public-Facing Application    | Due to the internet-facing nature of the machine, it was targeted using a known or suspected exploit.| Indicates initial access via vulnerabilities in public-facing applications.     |
| T1110        | Brute Force                          | Failed login attempts from multiple IP addresses suggest credential guessing attempts.               | Detects brute-force attempts based on repeated failed logins from various IPs.   |
| T1078        | Valid Accounts                       | Successful logons by legitimate account 'labuser'.                                                   | Monitors use of valid credentials potentially compromised through brute force.   |
| T1587.001    | Develop Capabilities: Exploit Code   | Indirect inference from multiple bad actors attempting logins using automated tools or shared code.  | Suggests adversaries are leveraging shared or custom exploit code/tooling.       |
---

This chart clearly organizes the MITRE ATT&CK techniques (TTPs) used in this incident, detailing their relevance to the detection process.

**Response:**  
- Did a Audit, Malware Scan, Vulnerability Management Scan, Hardened the NSG attached to windows-target-1 to allow only RDP traffic from specific endpoints (no public internet access), Implemented account lockout policy, Implemented MFA, awaiting further instructions.

---

## Steps to Reproduce:
1. Provision a virtual machine with a public IP address.
2. Ensure the device is actively communicating or available on the internet. (Test ping, etc.)
3. Onboard the device to Microsoft Defender for Endpoint.
4. Verify the relevant logs (e.g., network traffic logs, exposure alerts) are being collected in MDE.
5. Execute the KQL query in the MDE advanced hunting to confirm detection.
---

## Created By:
- **Author Name**: Marcel Pierce 
- **Author Contact**: [LinkedIn](https://www.linkedin.com/in/marcel-pierce-1a49b52a5/)  
- **Date**: Apr 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---


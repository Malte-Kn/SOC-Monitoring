# SOC-Monitoring of two Honeypots with a SQL Server before and after recommended security controls
## Overview
We created a network in Azure with two different virtual machines as honeypots to monitor the traffic. A Windows 10 VM with an SQL database and a Linux VM. We aggregated all interesting logs from both machines via the Log Analytics Workspace and monitored them in our Security Information and Event Manager Sentinel. For the first period of time, we left both VMs open to the Internet with, respectively, RDP and SSH. For the second period we implemented recommended security practices from the Defender for Cloud to monitor and evaluate the differences.
## Setup
![SOC Overview](https://github.com/user-attachments/assets/bca890c9-8b97-4430-b8a0-72912af26376)
### Windows Virtual Machine 
  - Open Remote Desktop Protocol
  - MSSQL Server
  - Disabled Firewalls
  - Sending Security Event Logs (Windows Event Logs)
### Linux Virtual Machine
  - Open SSH port
  - Sending Syslog to Log Analytics
### Azure Log Analytics Workspace
  - Network Security Groups Flow logs (AzureNetworkAnalytics_CL)
  - Security Alerts/Incidents
### Microsoft Sentinel
  - Workbook for visualization based on attacks and location
  - Alert rules
### Monitored Attacks
 - Failed RDP connection to the Windows machine and RDP brute-force attacks
 - Failed MSSQL connection to the Windows machine and MSSQL brute-force attacks
 - Failed SSH connection to the Linux machine and SSH brute-force attacks
 - General Malicious Flow in the AzureNetworkAnalytics_CL Logs
## Monitoring without implemented security controls
![image](https://github.com/user-attachments/assets/ddfd506e-3e02-4556-923c-1b561d55bd74)
We monitored the network for a period of 15 hours from 14:00 on 15/01/2025 to 5:00 on 16/01/2025.
For the maps, only the first 100 rows are considered, giving us a slight difference in the two results.
### Failed RDP Login Attempts
![rdp-Fail-Login](https://github.com/user-attachments/assets/2d84b0b8-5358-4582-996c-8c043ba5c91a)
KQL query code:
```
SecurityEvent 
| where TimeGenerated  between (datetime(2025-01-15T14:00:00) ..datetime(2025-01-16T05:00:00))
| where EventID == 4625
| order by TimeGenerated desc
| project TimeGenerated, Account, AccountType, Computer, EventID, Activity, IpAddress, LogonTypeName
```
Results: 8734 Attempts
### Failed MSSQL Login Attempts
![MSSQL-Fail-Login](https://github.com/user-attachments/assets/0e3e67eb-79e6-4864-b388-b2495c5126f3)
KQL query code:
```
Event 
| where TimeGenerated  between (datetime(2025-01-15T14:00:00) ..datetime(2025-01-16T05:00:00))
| where EventID == 18456
| order by TimeGenerated desc
| project TimeGenerated, Computer, RenderedDescription
```
Results: 503 Attempts
### Failed SSH Login Attempts
![ssh-login-fail](https://github.com/user-attachments/assets/884592b2-5268-4992-998d-ca2fea8895ec)
KQL query code:
```
Syslog
| where SyslogMessage startswith "Failed password"
| where TimeGenerated  between (datetime(2025-01-15T14:00:00) ..datetime(2025-01-16T05:00:00))
| order by TimeGenerated desc
| project TimeGenerated,HostName,HostIP, Facility, SyslogMessage, ProcessName, SeverityLevel, Type
```
Results: 1984 Attempts
###  Network Security Groups malicious Flow
![Newtwork-group-securityFlows1](https://github.com/user-attachments/assets/aa91d5e0-bc2c-498f-910f-e63588eacc5b)
KQL query code:
```
AzureNetworkAnalytics_CL 
| where FlowType_s == "MaliciousFlow"
| where TimeGenerated  between (datetime(2025-01-15T14:00:00) ..datetime(2025-01-16T05:00:00))
| project TimeGenerated, FlowType_s,SrcIP_s, DestIP_s, DestinationPort = DestPort_d, L7Protocol_s, NSGRules_s
```
Results: 766 Attempts
## Implementation of Security Controls
![image](https://github.com/user-attachments/assets/d8fc1e8f-e342-491c-aff6-8af770c02e1a)
- Creation of a Private Subnetwork
- Restriction of allowed IP addresses
- Implementation of Firewalls for Azure
- Activation of Firewalls on the Windows Machine

## Monitoring with implemented security controls
![image](https://github.com/user-attachments/assets/cd8c317f-11fa-4abc-9e2d-7dfc70e6bc24)
We monitored the network for a period of 15 hours from 14:00 on 17/01/2025 to 5:00 on 18/01/2025.
After the implementation, the login attempts by unwanted IP addresses via RDP, SSH, or MSSQL could be prevented.

###  Network Security Groups Malicious Flow
![Newtwork-group-securityFlows2](https://github.com/user-attachments/assets/1bf56308-68a6-429b-85e9-0af45282ad37)
KQL query code:
```
AzureNetworkAnalytics_CL 
| where FlowType_s == "MaliciousFlow"
| where TimeGenerated  between (datetime(2025-01-17T14:00:00) ..datetime(2025-01-18T05:00:00))
| project TimeGenerated, FlowType_s,SrcIP_s, DestIP_s, DestinationPort = DestPort_d, L7Protocol_s, NSGRules_s
```
Results: 1537 Attempts

### General Comparison of Logs
#### Syslogs before security controls by ProcessID
![Syslog1](https://github.com/user-attachments/assets/566c1849-a622-401f-83f9-629aee3d0ab9)
#### Syslogs after security controls by ProcessID
There were no results for the Syslogs with implemented security controls 
#### SecurityEvent logs before security controls by Task
![SecurityEventChart1](https://github.com/user-attachments/assets/b072e71c-ecc5-49b7-9757-16522d38fddf)
#### SecurityEvent logs after security controls by Task
![SecurityEventChart2](https://github.com/user-attachments/assets/3feb1758-d0e6-42f2-8a35-a4367fcedd77)

#### Network Security malicious Flow logs before security controls by DestPort
![MalFlow1](https://github.com/user-attachments/assets/525eaecd-0391-4e67-9037-974c7eec04e0)
#### Network Security malicious Flow logs after security controls by DestPort
![MalFlow2](https://github.com/user-attachments/assets/e1122f36-1dad-4af3-bdc8-c6329ca76aa6)

## Conclusion
We opened different honeypots to the Internet to compare the attacks before and after implementing security control.
With the Microsoft Azure Stack, we were able to deploy two VMs on Azure, utilize their Log Analytic Workspaces, and use Microsoft Sentinel as our SIEM solution.
In our experiment, we mapped the attacks based on the IP addresses to the location on a world map to give an overview of their origin.
We can see the expected reduction in attacks after enabling and implementing recommended security controls.
With the visualization, we observe all kinds of different origins for brute-force attacks against our honeypots. 

### Inspiration and Adaptation
This experiment/lab was inspired and adapted from:

[1] [Josh Madakor](https://github.com/joshmadakor1/Sentinel-Lab)

[2] [Phillip K.](https://github.com/kphillip1/azure-soc-honeynet) 


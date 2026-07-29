# Administrative Directory — GPO & SIEM

An Active Directory security project completed at **42 Mulhouse** (in partnership with Microsoft). The goal is to harden user access with **Group Policy Objects (GPO)** and monitor network activity with a **SIEM**, using the built-in features of Windows Server Active Directory.

## Overview

The fictional client *Domolia* wanted to strengthen access control and gain visibility over network events. This project delivers a full Active Directory setup: organizational units, security groups, shared disks, folder permissions enforced through GPO, event auditing, and a set of scripts to analyze the resulting logs.

## Features

### Directory structure
- **Organizational Units:** `Workspace`, `Administration`
- **Groups:** `Worker`, `Direction`, `Secretary`, `Administrator`
- **Disks:** `D:`, `E:` (auto-mapped per group)
- **Shared folders:** `WorkPlan`, `Management`, `HumanResources`, `Estimate`, `Client`

### GPOs
- Desktop and screen configuration
- On-demand OpenOffice deployment
- Mandatory Slack installation for new users
- Automatic disk mapping per group
- Granular NTFS permissions (access / edit / create / delete) enforced per group and folder

### SIEM — event auditing
Auditing enabled for the activities Domolia requested:
- Computer / User account management
- Distribution & security group management
- Directory service access
- Logon / Logoff events

### Log analysis scripts
- List users connected between two timestamps
- Show all events for a given user between two timestamps
- Isolate access & modifications on a specific folder
- List IP addresses used by users
- List security incidents

## Permission matrix

| Group | Access | Edit | Create | Delete |
|-------|--------|------|--------|--------|
| Worker | WorkPlan, Management, HumanResources | WorkPlan | WorkPlan | — |
| Direction | WorkPlan, HumanResources, Estimate, Client | WorkPlan, Management, HumanResources, Estimate, Client | all above | all above |
| Secretary | Management, HumanResources, Estimate, Client | Management, HumanResources, Estimate, Client | same | same |
| Administrator | All folders | All folders | All folders | All folders |

## Tech stack

- Windows Server — Active Directory Domain Services
- Group Policy Management
- Windows Event Log / Auditing (SIEM)
- PowerShell (log analysis scripts)

## Notes

Built and tested on the VMs provided for the subject. The scripts read from the Windows Security event log and are meant to be run on the domain controller.

---

*Project realized as part of the 42 cursus — 42 Mulhouse.*

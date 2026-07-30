# Group Policy Objects — Reference

This document describes every GPO created for the project: what it configures,
where it is linked, and the reasoning behind each linking decision. Because the
actual configuration lives inside the (locked) VM, this file serves as the
reproducible record of the GPO design.

## Linking principle

Every GPO has two halves — **Computer Configuration** and **User
Configuration** — and each targets a different kind of object based on the OU it
is linked to:

- **Computer Configuration** settings apply to *computer* objects → link to the
  OU holding the machines.
- **User Configuration** settings apply to *user* objects → link to the OU
  holding the users.

This single distinction drives every linking choice below. Folder permissions
and auditing target the DC (where the folders and directory live), so they link
to **Domain Controllers**. Drive mapping, software, and desktop settings target
users, so they link to **Workspace** / **Administration**. The Slack startup
script targets the client machines, so it links to **Clients**.

## GPO summary

| GPO | Config scope | Linked to | Purpose |
|-----|--------------|-----------|---------|
| `GPO-FolderPermissions` | Computer | Domain Controllers | NTFS ACLs on the shared folders |
| `GPO-DriveMapping` | User | Workspace, Administration | Auto-connect D: and E: at logon |
| `GPO-LibreOffice` | User | Workspace, Administration | Optional office suite deployment |
| `GPO-Slack` | Computer | Clients | Provision Slack MSIX via startup script |
| `GPO-Desktop` | User | Workspace, Administration | Standard desktop wallpaper |
| `GPO-Audit` | Computer | Domain Controllers | Security event auditing |
| `GPO-AccountLockout` | Computer | Domain root | Lock accounts after failed logons (bonus) |

## GPO details

### GPO-FolderPermissions

Delivers the per-group NTFS permissions on the shared folders, configured under
Computer Configuration → Windows Settings → Security Settings → File System. Each
folder is added and its ACL defined per the permission matrix (see README). Uses
"Propagate inheritable permissions" so existing SYSTEM/Administrators access is
preserved. Linked to Domain Controllers because the folders live on the DC.

The one folder needing advanced (non-preset) permissions is `D:\WorkPlan` for
the Worker group: create-and-edit but *not* delete, achieved by granting the
create/write rights while leaving both Delete rights unchecked.

### GPO-DriveMapping

Auto-connects the two shared disks as network drives at user logon. Configured
under User Configuration → Preferences → Windows Settings → Drive Maps, with one
mapped drive each for D: and E:, action "Update", Reconnect enabled. Points at
the UNC shares (`\\<dc-fqdn>\Data_D`, `\\<dc-fqdn>\Data_E`). Linked to the user
OUs because drive maps follow the user to whichever client they log into.

### GPO-LibreOffice

Deploys LibreOffice via Software Installation under User Configuration → Software
Settings. Published (optional / "if required by each user"). The vendor MSI
initially failed to add (see troubleshooting in README); resolved by trimming the
MSI to a single language with Orca so its deployment metadata could be parsed.

### GPO-Slack

Provisions the Slack MSIX package via a Computer Configuration startup script
(`Install-Slack.ps1`), because MSIX cannot be deployed through Software
Installation. The script runs `Add-AppxProvisionedPackage -Online` as SYSTEM at
boot, provisioning Slack for every user on the machine. Linked to the Clients OU
(a dedicated OU created for the workstations, since the default Computers
container cannot have GPOs linked to it).

### GPO-Desktop

Sets a standard desktop wallpaper under User Configuration → Administrative
Templates → Desktop → Desktop Wallpaper, pointing at a UNC path on a readable
share. Linked to the user OUs.

### GPO-Audit

Enables security auditing (see `audit-policy.md` for the full category and Event
ID reference). Configured under Computer Configuration → Windows Settings →
Security Settings → Advanced Audit Policy Configuration. Linked to Domain
Controllers, which is where the account/group/directory events occur and where
the audited folders live.

### GPO-AccountLockout (bonus)

Locks accounts after repeated failed logons. Configured under Account Policies →
Account Lockout Policy (threshold, duration, reset window). Linked at the
**domain root**, not an OU — account and password policies for domain accounts
only take effect from a domain-linked GPO. Pairs with the incident-response
script, which escalates persistent failures to a permanent account disable.

## Shares referenced by the GPOs

| Share | Path | Purpose |
|-------|------|---------|
| `D` | `D:\` | Drive-mapping target (disk D) |
| `E` | `E:\` | Drive-mapping target (disk E) |
| `Software` | `C:\Shares\Software` | LibreOffice MSI, Slack MSIX |
| `Wallpaper` | `C:\Shares\Wallpaper` | Desktop wallpaper image |

Share-level permissions are kept permissive; NTFS permissions carry the real
access control (the two-layer share/NTFS model, where the more restrictive of the
two wins). UNC paths use the DC's FQDN rather than its IP, so authentication uses
Kerberos and survives any IP change.
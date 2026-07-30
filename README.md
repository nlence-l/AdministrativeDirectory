# Administrative Directory — GPO & SIEM

An Active Directory security project completed at **42 Mulhouse** (in partnership with Microsoft). The goal is to harden user access with **Group Policy Objects (GPO)** and monitor network activity with **SIEM auditing**, using the built-in features of Windows Server Active Directory.

The fictional client *Domolia* wanted to strengthen access control and gain visibility over network events. This project delivers a full Active Directory setup: organizational units, security groups, shared disks, folder permissions, software deployment, and event auditing — all driven by Group Policy and PowerShell.

## Environment

Built on a lab of four VMs:

- **Domain Controller** — Windows Server, `domolia.local` domain, hosts the shared disks and all GPO configuration
- **Member server** — spare, unused for the mandatory part
- **Two Windows 11 clients** — domain-joined workstations where user-facing policies are tested

All configuration is performed on the DC; the clients are where the user experience (drive maps, software, wallpaper) is demonstrated.

## Directory structure

| Object type | Objects |
|-------------|---------|
| Organizational Units | `Workspace` (users), `Administration` (admin users), `Clients` (workstations) |
| Security groups | `Worker`, `Direction`, `Secretary`, `Administrator` |
| Disks | `D:`, `E:` (partitioned from the DC's disk, shared over the network) |
| Shared folders | `WorkPlan`, `Management` (on D:); `HumanResources`, `Estimate`, `Client` (on E:) |

Users and groups live in `Workspace` / `Administration`; the client machines live in a dedicated `Clients` OU. This separation keeps user-targeted GPOs and computer-targeted GPOs cleanly distinct.

## Group Policy Objects

| GPO | Config scope | Linked to | Purpose |
|-----|--------------|-----------|---------|
| `GPO-FolderPermissions` | Computer | Domain Controllers | NTFS ACLs on the shared folders (per-group access) |
| `GPO-DriveMapping` | User | Workspace, Administration | Auto-connects D: and E: for all users at logon |
| `GPO-LibreOffice` | User | Workspace, Administration | Optional software deployment (Published) |
| `GPO-Slack` | Computer | Clients | Provisions Slack MSIX via startup script |
| `GPO-Desktop` | User | Workspace, Administration | Standard desktop wallpaper |

The Computer-vs-User distinction drives every linking decision: computer-config GPOs target the OU holding the machines, user-config GPOs target the OUs holding the users.

## Permission matrix

Access rules enforced via NTFS ACLs (delivered through the File System GPO):

| Group | Access | Edit | Create | Delete |
|-------|--------|------|--------|--------|
| Worker | WorkPlan, Management, HumanResources | WorkPlan | WorkPlan | — |
| Direction | WorkPlan, HumanResources, Estimate, Client | + Management | same | same |
| Secretary | Management, HumanResources, Estimate, Client | same | same | same |
| Administrator | All folders | All folders | All folders | All folders |

The Worker/WorkPlan cell is the one case requiring *advanced* NTFS permissions: create-but-not-delete, achieved by granting the create/write rights while leaving both Delete rights unchecked.

## SIEM — event auditing

Auditing configured through **Advanced Audit Policy Configuration** for the activities Domolia requested:

- Computer / User account management
- Distribution & security group management
- Directory service access
- Logon / Logoff events

## Log-analysis scripts

PowerShell scripts to read the Windows Security event log:

- List users connected between two timestamps
- Show all events for a given user between two timestamps
- Isolate access & modifications on a specific folder
- List IP addresses used by users
- List security incidents

## Troubleshooting log

The most instructive parts of the project were the problems that didn't work first try. Documenting them here because the diagnosis mattered more than the fix.

### `Administrator` group — "The specified account already exists"

Creating a security group named `Administrator` failed even though no group by that name existed. **Cause:** the built-in Administrator *account* already owns the `Administrator` **SamAccountName** domain-wide, and SamAccountName must be unique across all object types. The existence check (filtering on `Name` among groups) passed, but the create failed on the hidden SamAccountName collision.

### LibreOffice MSI — "Unable to extract deployment information from the package"

GPO Software Installation rejected the LibreOffice `.msi`, even though the file installed fine manually and was referenced via the correct UNC path. **Cause:** LibreOffice's `.msi` ships with many embedded language transforms, and its deployment metadata was structured in a way the Software Installation parser couldn't resolve to a single deployable target. **Fix:** opened the `.msi` in **Orca** (Microsoft's MSI table editor) and stripped it down to a single language (English), simplifying the language metadata to something GPO could parse. The trimmed package deployed cleanly through the proper Software Installation route — no scripting fallback needed.

### Slack MSIX — can't deploy via Software Installation

Slack ships as an **MSIX** package, which GPO Software Installation cannot handle (it only understands `.msi`). **Fix:** deployed via a **Computer-config startup script** using `Add-AppxProvisionedPackage -Online`, which provisions the package for every user on the machine — matching the "for each new user" requirement. This required creating a dedicated `Clients` OU, because computer-config GPOs can't target the default `Computers` container, and startup scripts run as SYSTEM (with the admin rights MSIX provisioning needs).

## Key concepts applied

- **NTFS permissions** — ACLs, ACEs, SIDs, inheritance, basic vs advanced rights
- **Share vs NTFS permissions** — the two-layer model and why NTFS should carry the access logic
- **Computer vs User Configuration** — the distinction that governs every GPO linking decision

## Tech stack

Windows Server · Active Directory Domain Services · Group Policy Management · NTFS / Advanced Auditing · PowerShell · Orca (MSI editing)

---

*Project realized as part of the 42 cursus — 42 Mulhouse.*

# BetterIntuneUI

BetterIntuneUI is a collection of userscripts that adds focused workflows to the Microsoft Intune and Microsoft Entra admin portals. The scripts run in the current browser session and use Microsoft Graph or portal data that the signed-in administrator can already access.

## Scripts

### [Entra - Add Selected Members To Another Group.user.js](<scripts/Entra - Add Selected Members To Another Group/Entra - Add Selected Members To Another Group.user.js>)

Adds selected users or devices from one Entra group to another group. It supports a logical Select All operation resolved through Microsoft Graph.

![Add selected members menu](<scripts/Entra - Add Selected Members To Another Group/Entra - Add Selected Members To Another Group.user-2.png>)

![Add selected members dialog](<scripts/Entra - Add Selected Members To Another Group/Entra - Add Selected Members To Another Group.user.png>)

### [Entra - Group Device Info Columns.user.js](<scripts/Entra - Group Device Info Columns/Entra - Group Device Info Columns.user.js>)

Adds Entra, Intune, and Windows Autopilot details such as join type, compliance, management, operating system, model, owner, and Autopilot state to group member tables.

![Enriched device information columns](<scripts/Entra - Group Device Info Columns/Entra - Group Device Info Columns.user.png>)

### [Entra Group Members - Host List Graph Add-Remove.user.js](<scripts/Entra Group Members - Host List Graph Add-Remove/Entra Group Members - Host List Graph Add-Remove.user.js>)

Resolves a pasted list of hostnames through Microsoft Graph and adds or removes the matching devices from the current Entra group.

![Host list group actions](<scripts/Entra Group Members - Host List Graph Add-Remove/Entra Group Members - Host List Graph Add-Remove.user-2.png>)

![Host list dialog](<scripts/Entra Group Members - Host List Graph Add-Remove/Entra Group Members - Host List Graph Add-Remove.user.png>)

### [Intune & Entra Naming Designer.user.js](<scripts/Intune & Entra Naming Designer/Intune & Entra Naming Designer.user.js>)

Builds reusable naming templates for Entra groups, Intune policies, profiles, applications, scripts, updates, and assignment filters. Templates are stored locally by the userscript manager.

![Naming template designer](<scripts/Intune & Entra Naming Designer/Intune & Entra Naming Designer.user-2.png>)

![Naming designer in a configuration workflow](<scripts/Intune & Entra Naming Designer/Intune & Entra Naming Designer.user-3.png>)

![Naming designer in a group workflow](<scripts/Intune & Entra Naming Designer/Intune & Entra Naming Designer.user.png>)

### [Intune - Autopatch Calendar.user.js](<scripts/Intune - Autopatch Calendar/Intune - Autopatch Calendar.user.js>)

Displays quality, feature, and driver update rollout dates in a calendar grouped by Windows Autopatch deployment rings.

![Autopatch calendar](<scripts/Intune - Autopatch Calendar/Intune - Autopatch Calendar.user-2.png>)

![Autopatch update rings](<scripts/Intune - Autopatch Calendar/Intune - Autopatch Calendar.user.png>)

### [Intune - Driver Impact.user.js](<scripts/Intune - Driver Impact/Intune - Driver Impact.user.js>)

Shows devices affected by Intune or Windows Autopatch driver updates, including driver status, model distribution, and device details.

![Driver Impact overview](<scripts/Intune - Driver Impact/Intune - Driver Impact.user.png>)

### [Intune - Device Group Membership.user.js](<scripts/Intune - Device Group Membership/Intune - Device Group Membership.user.js>)

Adds or removes the current Intune device from Entra groups directly in the device group membership view. Only direct memberships can be removed.

![Device group membership](<scripts/Intune - Device Group Membership/Intune - Device Group Membership.user.png>)

### [Intune - Group Assignments.user.js](<scripts/Intune - Group Assignments/Intune - Group Assignments.user.js>)

Lists direct Include and Exclude Intune assignments for the currently opened Entra group and supports CSV export.

![Intune group assignments](<scripts/Intune - Group Assignments/Intune - Group Assignments.user.png>)

## Installation

1. Install a userscript manager such as Tampermonkey or Violentmonkey.
2. Open the required `.user.js` file and install it in the userscript manager.
3. Sign in to the Microsoft Intune or Entra admin center and open the view supported by the script.

There is no build step or package dependency. Install only the scripts you need. Portal markup and Graph beta endpoints can change, so validate each script after an Intune portal update.

## Browser requirements

Use one userscript manager browser extension:

- [Tampermonkey](https://www.tampermonkey.net/)
- [Violentmonkey](https://violentmonkey.github.io/)

No additional browser add-on is required. Depending on the script, the userscript manager may ask for access to the current page, `unsafeWindow`, cross-origin requests to Microsoft Graph, or local userscript storage. These permissions are declared in each script's metadata header; review them before installation.

## Interface language

The userscripts are designed for the English-language Microsoft Intune and Microsoft Entra admin center interface. Portal labels, selectors, and localized response text can differ when another interface language is selected.

## Permissions and data handling

The scripts use the existing signed-in Microsoft Graph session. Access tokens are kept in memory while a script is running and are not written to the repository or to userscript storage. The naming designer stores its templates locally so they survive a browser restart; it does not store access tokens.

The membership and assignment scripts can read or change tenant data when the signed-in account has the required permissions. Review the source and your Graph permissions before installing a script in a production tenant.

## Maintainer

Xento — [1299397+Xento@users.noreply.github.com](mailto:1299397+Xento@users.noreply.github.com)

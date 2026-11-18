# Endpoint Administration and Compliance Assistant

## Overview
This repository contains a modular PowerShell CLI utility designed for Active Directory governance, remote endpoint management, and security agent lifecycle validation. 
**Context & Scope:** 
This tool was expanded upon a legacy helpdesk script. Parts that were not authored by me have been removed.
## Security & Operational Considerations
* **Credential Hygiene:** Credentials are not hardcoded; the script utilizes dynamic `Get-Credential` prompts and secure `New-PSSession` parameters to authenticate against remote endpoints.
* **Privileged Access Boundary:** Administrative actions (such as software uninstalls or Group Policy enforcement) require explicit remote session establishment and appropriate administrative elevation.
* **Intended Use:** This script is structured for administrative review and educational reference. It enforces safety checks (such as network connectivity pings and active user verification) before executing infrastructure changes.
## Core Features & Menu Architecture
The utility is structured around an interactive command-line interface organized into two primary operational domains:
### Active Directory Governance & Onboarding
* **(2) Machine Management:** View machine OUs and AD memberships; configure GPOs, manage BitLocker encryption states and Entra ID key sync, apply security registry keys, and adjust organizational units for patch management.
* **(3) User Lifecycle & Provisioning:** Automate new hire onboarding, set up multi-field Active Directory attributes, generate department-specific first-day login guides, and export formatted IT inventory/ticket templates.
* **(4) Profile Metadata & Signatures:** Bulk-update employee Gallup strengths, MBTI types, and professional designations via clipboard parsing with built-in data validation.
* **(5) Authentication & Credentials:** Query real-time password expiration timestamps and last recorded successful sign-in dates.
### Endpoint Security & Operations (Remote/Local)
* **(8) Remote CLI Shell:** Open secure interactive PowerShell sessions to remote workstations pinned to predefined administrative directories.
* **(9) Audit Log Extraction:** Filter and export Windows Event Viewer logs (Application, Security, System, Setup) by severity and date range directly to standardized CSV audit files.
* **(12) Service Lifecycle Management:** Remotely restart stopped or disabled Windows services with built-in startup-type modification and process validation.
* **(13) System Uptime Monitor:** Quickly query remote operating system boot times and live uptime metrics.
* **(14) Security Agent Lifecycle (Carbon Black & Digital Guardian):** Remotely install, verify, or cleanly uninstall endpoint security sensors and agents with exit-code tracking.
* **(15) Storage & Cache Remediation:** Calculate logical disk utilization and safely purge bulky application caches (Adobe, Ivanti patch data, large Outlook `.ost` files).

# PowerShell
PowerShell Portfolio
## Security & Operational Considerations
* **Credential Hygiene:** Credentials are not hardcoded; the script utilizes dynamic `Get-Credential` prompts and secure `New-PSSession` parameters to authenticate against remote endpoints.
* **Privileged Access Boundary:** Administrative actions (such as software uninstalls or Group Policy enforcement) require explicit remote session establishment and appropriate administrative elevation.
* **Intended Use:** This script is structured for administrative review and educational reference. It enforces safety checks (such as network connectivity pings and active user verification) before executing infrastructure changes.

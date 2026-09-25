# Invoke-PrivEscTriage

A native Windows privilege-escalation triage script for authorized red-team and security-assessment work. It looks at the token you are already holding before it looks at anything else, decides whether escalation is even necessary and which avenue is open, and only then runs a read-only misconfiguration hunt. It is written for Windows PowerShell 5.1, uses no external tools, and does not carry out any exploitation itself.

## What it does

The core idea is that most privilege-escalation effort is wasted because the operator jumps straight to hunting for misconfigurations without first establishing what the current token can already do. This script inverts that order. It runs `whoami /groups` and `whoami /priv`, interprets the result the way an operator would, tells you plainly what situation you are in, and routes you to the correct next step. The misconfiguration hunt is treated as the fallback for the standard-user case rather than the default first move.

The decision flow is as follows. The script first parses `whoami /groups` and looks for the `BUILTIN\Administrators` group (SID `S-1-5-32-544`). If that group is present and enabled, you are holding a full administrator token and no escalation is needed. If it is present but marked deny-only, you are a local administrator running under a UAC-filtered split token, and the avenue is a UAC bypass rather than a hunt. If the group is absent, you are a standard user and the script continues.

For the standard-user case it parses `whoami /priv` and checks for dangerous privileges. `SeImpersonatePrivilege` and `SeAssignPrimaryTokenPrivilege` are highlighted as the fast path to the Potato family of escalations. Other high-value privileges such as `SeDebug`, `SeBackup`, `SeRestore`, `SeTakeOwnership`, and `SeLoadDriver` are each mapped to the avenue they open. If only default privileges are present, the script proceeds to the misconfiguration hunt.

The hunt itself is read-only. It enumerates services and checks whether the current low-privilege principals can reconfigure a service through its DACL, write over its executable, or write into its directory. It checks scheduled tasks for writable task binaries, checks unquoted service paths for a writable hijack directory, checks Run and RunOnce autorun entries for writable targets, checks Winlogon and unattend locations for stored credentials and auto-logon passwords, flags third-party and writable driver images as BYOVD candidates, and gathers OS build and installed-hotfix context so that missing-patch and known-CVE follow-up has a starting point.

## What it deliberately does not do

This tool assesses and reports. It identifies which escalation avenue is open, names the technique family, and enumerates misconfigurations read-only. It does not perform a UAC bypass, run a Potato or token-impersonation step, load a driver, decrypt or dump credentials, or modify any service, task, or file. Those steps are the operator's responsibility to carry out within the bounds of an authorized engagement. The credential, BYOVD, and CVE areas are first-pass in depth: credentials are detection-only with no SYSVOL Group Policy Preference sweep, driver findings flag candidates rather than matching them against a known-vulnerable-driver hash list, and the patch context is gathered but not yet mapped to specific CVEs. Those three areas would each benefit from a bundled reference feed.

## Requirements

Windows PowerShell 5.1 on the target host. The script runs under `Set-StrictMode -Version 2.0` and depends only on built-in Windows facilities and .NET, so nothing needs to be installed or copied onto the host. Run it as the user whose escalation options you want to assess, since the whole point is to evaluate the token you currently hold. The `whoami` attribute strings it matches are the English ones; on a localized build of Windows you will need to supply the equivalent strings.

## Usage

Run it with no arguments to assess the current token and, if you are a standard user, run the hunt:

```
.\Invoke-PrivEscTriage.ps1
```

The parameters are:

`-OutputDirectory` sets where the report and `PrivEscFindings.csv` are written. It defaults to `.\PrivEscTriage`.

`-Principals` is the set of low-privilege principals whose write access is evaluated during the hunt. It defaults to `Users`, `Authenticated Users`, and `Everyone`.

`-RunHunt` forces the misconfiguration hunt to run even when the token is already a full administrator or a split token. This is useful when the script is being used as a defensive audit of a host rather than as an operator's triage step.

`-SkipHunt` does the token and privilege assessment only and never runs the hunt.

## Output

The script writes two things to the output directory. `Summary.txt` leads with the token and privilege assessment — the situation it detected, a plain-language headline, and the recommended avenue — and then lists the hunt findings when the hunt ran. `PrivEscFindings.csv` is the machine-readable list of hunt findings, each with its finding type, target, the weak principal that grants access, and a severity rating. Errors encountered during enumeration are captured rather than thrown, so a permission failure on one item does not abort the run.

## Authorized use

This script is intended solely for security assessments that you are explicitly authorized to perform. Enumerating privilege-escalation paths on a system you do not own or do not have written permission to test may be illegal. You are responsible for staying within the scope and rules of engagement of your authorization.

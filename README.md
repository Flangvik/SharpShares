# SharpShares
Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain

Built upon [mitchmoser's SharpShares](https://github.com/mitchmoser/SharpShares), which was built upon [djhohnstein's SharpShares](https://github.com/djhohnstein/SharpShares) project
Mainly added the /username /password and /dc args, making it possible to run the tool from a non-domain joined pc!
```
> .\SharpShares.exe help

█▀ █ █ ▄▀█ █▀█ █▀█ █▀ █ █ ▄▀█ █▀█ █▀▀ █▀
▄█ █▀█ █▀█ █▀▄ █▀▀ ▄█ █▀█ █▀█ █▀▄ ██▄ ▄█

Usage:
    SharpShares.exe /username:DOMAIN\USER /DC:192.168.1.1 /password:Passw0rd!123 /threads:50 /ldap:servers /ou:"OU=Special Servers,DC=example,DC=local" /filter:SYSVOL,NETLOGON,IPC$,PRINT$ /verbose /outfile:C:\path\to\file.txt

Optional Arguments:
    /threads  - specify maximum number of parallel threads  (default=25)
    /ldap     - query hosts from the following LDAP filters (default=all)
         :all - All enabled computers with 'primary' group 'Domain Computers'
         :dc  - All enabled Domain Controllers (not read-only DCs)
         :exclude-dc - All enabled computers that are not Domain Controllers or read-only DCs
         :servers - All enabled servers
         :servers-exclude-dc - All enabled servers excluding Domain Controllers or read-only DCs
    /ou       - specify LDAP OU to query enabled computer objects from
                ex: "OU=Special Servers,DC=example,DC=local"
    /stealth  - list share names without performing read/write access checks
    /filter   - list of comma-separated shares to exclude from enumeration
                recommended: SYSVOL,NETLOGON,IPC$,print$
    /outfile  - specify file for shares to be appended to instead of printing to std out
    /username - DOMAIN\USERNAME to be used for auth
    /password - Password to be used for auth
    /dc       - Target domain controller IP
    /verbose  - return unauthorized shares
```

## Execute Assembly
```
execute-assembly /path/to/SharpShares.exe /ldap:all /filter:sysvol,netlogon,ipc$,print$
```
## Example Output
```
[+] Parsed Aguments:
        threads: 25
        ldap: all
        ou: none
        filter: SYSVOL,NETLOGON,IPC$,PRINT$
        stealth: False
        verbose: False
        outfile:

[*] Excluding SYSVOL,NETLOGON,IPC$,PRINT$ shares
[*] Starting share enumeration with thread limit of 25
[r] = Readable Share
[w] = Writeable Share
[-] = Unauthorized Share (requires /verbose flag)
[?] = Unchecked Share (requires /stealth flag)

[+] Performing LDAP query for all enabled computers with "primary" group "Domain Computers"...
[+] This may take some time depending on the size of the environment
[+] LDAP Search Results: 10
[+] Starting share enumeration against 10 hosts

[r] \\DC-01\CertEnroll
[r] \\DC-01\File History Backups
[r] \\DC-01\Folder Redirection
[r] \\DC-01\Shared Folders
[r] \\DC-01\Users
[w] \\WEB-01\wwwroot
[r] \\DESKTOP\ADMIN$
[r] \\DESKTOP\C$
[+] Finished Enumerating Shares
```
### Specifying Targets

The `/ldap` and `/ou` flags can be used together or seprately to generate a list of hosts to enumerate.

All hosts returned from these flags are combined and deduplicated before enumeration starts.

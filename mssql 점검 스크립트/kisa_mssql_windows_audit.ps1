#requires -version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

function Prompt-Value {
    param([string]$Label, [string]$Default = "")

    if ([string]::IsNullOrWhiteSpace($Default)) {
        $v = Read-Host $Label
    } else {
        $v = Read-Host "$Label [$Default]"
    }

    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    return $v.Trim()
}

function Write-Utf8Bom {
    param([string]$Path, [string]$Content)

    $enc = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}

function Append-Utf8Bom {
    param([string]$Path, [string]$Content)

    $enc = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::AppendAllText($Path, $Content, $enc)
}

function Add-Line {
    param([string]$Text = "")

    Append-Utf8Bom -Path $script:OutFile -Content ($Text + "`r`n")
}

function Convert-ToReportText {
    param([object]$Value)

    if ($null -eq $Value) { return "(empty)" }
    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return "(empty)" }
        return $Value
    }

    $text = $Value | Out-String
    if ([string]::IsNullOrWhiteSpace($text)) { return "(empty)" }
    return $text.TrimEnd()
}

function Add-Raw {
    param([string]$Title, [object]$Value)

    $script:Raw.Add("### $Title")
    $script:Raw.Add((Convert-ToReportText $Value))
    $script:Raw.Add("")
}

function Add-Count {
    param([string]$Result)

    switch ($Result) {
        "OK"   { $script:OK_COUNT++ }
        "WARN" { $script:WARN_COUNT++ }
        "VULN" { $script:VULN_COUNT++ }
        "N/A"  { $script:NA_COUNT++ }
    }
}

function Limit-Text {
    param([string]$Text, [int]$MaxLength = 1200)

    if ([string]::IsNullOrWhiteSpace($Text)) { return "(empty)" }
    $t = $Text.Trim()
    if ($t.Length -le $MaxLength) { return $t }
    return $t.Substring(0, $MaxLength) + "... [TRUNCATED - see RAW DATA]"
}

function Get-BasisText {
    param($Result, [switch]$ForReport)

    if (-not $Result) { return "(empty)" }

    $text = ""
    if (-not [string]::IsNullOrWhiteSpace($Result.Stdout)) {
        $text = $Result.Stdout.Trim()
    } elseif (-not [string]::IsNullOrWhiteSpace($Result.Stderr)) {
        $text = $Result.Stderr.Trim()
    } else {
        $text = "(empty)"
    }

    if ($ForReport) { return (Limit-Text $text) }
    return $text
}

function Write-ItemReport {
    param(
        [string]$Code,
        [string]$Importance,
        [string]$Title,
        [string]$Result,
        [string]$Verdict,
        [string]$Current,
        [string]$Basis,
        [string]$Action
    )

    Add-Count $Result
    $lines = @(
        "------------------------------------------------------------",
        ("ITEM CODE      : {0}" -f $Code),
        ("IMPORTANCE     : {0}" -f $Importance),
        ("CHECK ITEM     : {0}" -f $Title),
        ("RESULT CODE    : {0}" -f $Result),
        ("VERDICT        : {0}" -f $Verdict),
        ("CURRENT        : {0}" -f $Current),
        ("BASIS          : {0}" -f $Basis),
        ("ACTION         : {0}" -f $Action),
        ""
    )

    foreach ($line in $lines) {
        Add-Line $line
    }
}

function Resolve-SqlCmdPath {
    param([string]$Candidate)

    if ([string]::IsNullOrWhiteSpace($Candidate)) { return "" }

    try {
        if (Test-Path $Candidate -PathType Leaf) {
            return (Resolve-Path $Candidate).Path
        }

        if (Test-Path $Candidate -PathType Container) {
            $exe = Join-Path $Candidate "sqlcmd.exe"
            if (Test-Path $exe -PathType Leaf) {
                return (Resolve-Path $exe).Path
            }
        }
    } catch {}

    return ""
}

function Find-SqlCmd {
    $cmd = Get-Command sqlcmd.exe -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) { return $cmd.Source }

    $paths = @(
        "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\180\Tools\Binn\SQLCMD.EXE",
        "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE",
        "C:\Program Files\Microsoft SQL Server\160\Tools\Binn\SQLCMD.EXE",
        "C:\Program Files\Microsoft SQL Server\150\Tools\Binn\SQLCMD.EXE",
        "C:\Program Files\Microsoft SQL Server\140\Tools\Binn\SQLCMD.EXE",
        "C:\Program Files\Microsoft SQL Server\130\Tools\Binn\SQLCMD.EXE",
        "C:\Program Files\Microsoft SQL Server\120\Tools\Binn\SQLCMD.EXE"
    )

    foreach ($p in $paths) {
        if (Test-Path $p -PathType Leaf) { return $p }
    }

    return ""
}

function Get-ServerTarget {
    if (-not [string]::IsNullOrWhiteSpace($script:DBPORT)) {
        return "$($script:DBHOST),$($script:DBPORT)"
    }

    if (-not [string]::IsNullOrWhiteSpace($script:DBINSTANCE)) {
        if ($script:DBINSTANCE -eq "MSSQLSERVER") { return $script:DBHOST }
        return "$($script:DBHOST)\$($script:DBINSTANCE)"
    }

    return $script:DBHOST
}

function Get-MaskedCommandString {
    param([string]$Query)

    $serverTarget = Get-ServerTarget
    $safeQuery = $Query -replace "`r", " " -replace "`n", " "

    if ($script:AuthMode -eq "windows") {
        return ('& "{0}" -S "{1}" -d "{2}" -E -l 5 -W -h -1 -s "," -b -m-1 -C -Q "{3}"' -f $script:Client, $serverTarget, $script:DBNAME, $safeQuery)
    }

    return ('& "{0}" -S "{1}" -d "{2}" -U "{3}" -P "******" -l 5 -W -h -1 -s "," -b -m-1 -C -Q "{4}"' -f $script:Client, $serverTarget, $script:DBNAME, $script:DBUserForTrace, $safeQuery)
}

function Invoke-MssqlQuery {
    param([string]$Title, [string]$Query)

    $serverTarget = Get-ServerTarget
    $args = @("-S", $serverTarget, "-d", $script:DBNAME)

    if ($script:AuthMode -eq "windows") {
        $args += "-E"
    } else {
        $args += @("-U", $script:DBUSER, "-P", $script:DBPASS)
    }

    $args += @("-l", "5", "-W", "-h", "-1", "-s", ",", "-b", "-m-1", "-C", "-Q", $Query)

    Add-Line "[TITLE]"
    Add-Line $Title
    Add-Line "[COMMAND]"
    Add-Line (Get-MaskedCommandString -Query $Query)

    if (-not $script:Client -or -not (Test-Path $script:Client -PathType Leaf)) {
        Add-Line "[EXITCODE]"; Add-Line "999"
        Add-Line "[STDOUT]"; Add-Line ""
        Add-Line "[STDERR]"; Add-Line "[ERROR] sqlcmd.exe not found"
        Add-Line ""
        return [pscustomobject]@{ ExitCode = 999; Stdout = ""; Stderr = "[ERROR] sqlcmd.exe not found" }
    }

    try {
        $all = & $script:Client @args 2>&1 | Out-String
        $exit = $LASTEXITCODE
        $stdout = ""
        $stderr = ""

        if ($exit -eq 0) {
            $stdout = $all
        } else {
            $stderr = $all
        }

        Add-Line "[EXITCODE]"; Add-Line ([string]$exit)
        Add-Line "[STDOUT]"; Add-Line $stdout
        Add-Line "[STDERR]"; Add-Line $stderr
        Add-Line ""

        return [pscustomobject]@{ ExitCode = $exit; Stdout = $stdout; Stderr = $stderr }
    } catch {
        Add-Line "[EXITCODE]"; Add-Line "998"
        Add-Line "[STDOUT]"; Add-Line ""
        Add-Line "[STDERR]"; Add-Line ("[ERROR] " + $_.Exception.Message)
        Add-Line ""
        return [pscustomobject]@{ ExitCode = 998; Stdout = ""; Stderr = $_.Exception.Message }
    }
}

function Test-ClientPrecheck {
    if ([string]::IsNullOrWhiteSpace($script:Client)) { return "[ERROR] Client path empty" }

    try {
        $item = Get-Item -LiteralPath $script:Client -ErrorAction Stop
        return @(
            ("FullName   : {0}" -f $item.FullName),
            "Exists     : True",
            ("Mode       : {0}" -f $item.Mode),
            ("Length     : {0}" -f $item.Length),
            ("LastWrite  : {0}" -f $item.LastWriteTime)
        ) -join "`r`n"
    } catch {
        return "[ERROR] " + $_.Exception.Message
    }
}

function Get-SqlRelatedFirewallRules {
    if (-not (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
        return "Get-NetFirewallRule command not available"
    }

    try {
        return Get-NetFirewallRule -DisplayName "*SQL*" -ErrorAction SilentlyContinue |
            Where-Object { $_.Action -eq "Allow" } |
            ForEach-Object {
                $rule = $_
                Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue |
                    Select-Object `
                        @{Name = "Name"; Expression = { $rule.Name }},
                        @{Name = "DisplayName"; Expression = { $rule.DisplayName }},
                        @{Name = "Direction"; Expression = { $rule.Direction }},
                        @{Name = "Enabled"; Expression = { $rule.Enabled }},
                        LocalAddress,
                        RemoteAddress
            } |
            Format-Table -AutoSize |
            Out-String
    } catch {
        return "[ERROR] " + $_.Exception.Message
    }
}

function Get-SystemDsnReport {
    if (-not (Get-Command Get-OdbcDsn -ErrorAction SilentlyContinue)) {
        return "Get-OdbcDsn command not available"
    }

    try {
        return Get-OdbcDsn -DsnType System -ErrorAction SilentlyContinue |
            Format-Table -AutoSize |
            Out-String
    } catch {
        return "[ERROR] " + $_.Exception.Message
    }
}

$script:OK_COUNT = 0
$script:WARN_COUNT = 0
$script:VULN_COUNT = 0
$script:NA_COUNT = 0
$script:Raw = New-Object System.Collections.Generic.List[string]

Write-Host "KISA MSSQL Windows Audit"

$script:DBHOST = Prompt-Value "DBHOST" "localhost"
$script:DBINSTANCE = Prompt-Value "DBINSTANCE (optional, blank if using host/port)" ""
$script:DBPORT = Prompt-Value "DBPORT (optional, port has priority)" "1433"
$script:AuthMode = Prompt-Value "AUTH_MODE (windows/sql)" "windows"
if ($script:AuthMode -notin @("sql", "windows")) { $script:AuthMode = "windows" }

if ($script:AuthMode -eq "windows") {
    $script:DBUSER = ""
    $script:DBPASS = ""
    $script:DBUserForTrace = "(WindowsAuth)"
} else {
    $script:DBUSER = Prompt-Value "DBUSER" "sa"
    if ($script:DBUSER -match '^\(?WindowsAuth\)?$') {
        Write-Host "[INFO] DBUSER value looks like WindowsAuth, switching AUTH_MODE to windows."
        $script:AuthMode = "windows"
        $script:DBUSER = ""
        $script:DBPASS = ""
        $script:DBUserForTrace = "(WindowsAuth)"
    } else {
        $script:DBPASS = Read-Host "DBPASS"
        $script:DBUserForTrace = $script:DBUSER
    }
}

$script:DBNAME = Prompt-Value "DBNAME" "master"
$ClientHint = Prompt-Value "SQLCMD_PATH (optional, exe or folder)" ""
$script:Client = Resolve-SqlCmdPath $ClientHint
if (-not $script:Client) { $script:Client = Find-SqlCmd }

$script:OutFile = Join-Path $PSScriptRoot ("kisa_mssql_windows_{0}_{1}.txt" -f $env:COMPUTERNAME, (Get-Date -Format "yyyyMMddHHmmss"))
Write-Utf8Bom -Path $script:OutFile -Content ""

$services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match "MSSQL|SQLSERVERAGENT|SQLAgent|SQLBrowser|SQLWriter|SQLTELEMETRY|MSOLAP" } |
    Select-Object Name, State, StartName, PathName, DisplayName |
    Format-Table -AutoSize |
    Out-String

$processes = Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.ProcessName -match "sqlservr|sqlwriter|sqlbrowser" } |
    Select-Object ProcessName, Id, Path |
    Format-Table -AutoSize |
    Out-String

$netFirewallRule = Get-SqlRelatedFirewallRules
$serverTarget = Get-ServerTarget
$systemDsn = Get-SystemDsnReport

Add-Line "============================================================"
Add-Line "KISA DBMS Windows Audit Framework"
Add-Line "============================================================"
Add-Line "[SERVER PROFILE]"
Add-Line ("Hostname : " + $env:COMPUTERNAME)
Add-Line ("OS       : " + [Environment]::OSVersion.VersionString)
Add-Line ("ExecUser : " + [System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
Add-Line "DBMS     : mssql"
Add-Line ("DBHOST   : " + $script:DBHOST)
Add-Line ("DBINSTANCE: " + $script:DBINSTANCE)
Add-Line ("DBPORT   : " + $script:DBPORT)
Add-Line ("AUTHMODE : " + $script:AuthMode)
Add-Line ("DBUSER   : " + $script:DBUserForTrace)
Add-Line ("DBNAME   : " + $script:DBNAME)
Add-Line ("Client   : " + $script:Client)
Add-Line ("ServerTarget : " + $serverTarget)
Add-Line ("Time     : " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
Add-Line ""

$versionRes = Invoke-MssqlQuery -Title "version" -Query "SET NOCOUNT ON; SELECT @@VERSION;"
$versionBasis = Get-BasisText $versionRes
$connectionStatus = if ($versionRes.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($versionRes.Stdout)) { "SUCCESS" } else { "FAILED" }

$q = [ordered]@{}
$q["D-01"] = Invoke-MssqlQuery -Title "D-01" -Query "SET NOCOUNT ON; SELECT name,is_disabled,is_policy_checked,is_expiration_checked FROM sys.sql_logins WHERE name='sa';"
$q["D-02"] = Invoke-MssqlQuery -Title "D-02" -Query "SET NOCOUNT ON; SELECT name,type_desc,is_disabled,create_date,modify_date FROM sys.server_principals WHERE type IN ('S','U','G') ORDER BY name;"
$q["D-03"] = Invoke-MssqlQuery -Title "D-03" -Query "SET NOCOUNT ON; SELECT name,is_policy_checked,is_expiration_checked FROM sys.sql_logins;"
$q["D-04"] = Invoke-MssqlQuery -Title "D-04" -Query "SET NOCOUNT ON; SELECT p.name FROM sys.server_role_members rm JOIN sys.server_principals r ON rm.role_principal_id=r.principal_id JOIN sys.server_principals p ON rm.member_principal_id=p.principal_id WHERE r.name='sysadmin';"
$q["D-05"] = Invoke-MssqlQuery -Title "D-05" -Query "SET NOCOUNT ON; SELECT name,is_policy_checked,is_expiration_checked FROM sys.sql_logins WHERE name='sa';"
$q["D-08"] = Invoke-MssqlQuery -Title "D-08" -Query "SET NOCOUNT ON; SELECT session_id,encrypt_option,auth_scheme,client_net_address,local_net_address,local_tcp_port FROM sys.dm_exec_connections WHERE session_id=@@SPID; SELECT name,password_hash FROM sys.sql_logins;"
$q["D-09"] = Invoke-MssqlQuery -Title "D-09" -Query "SET NOCOUNT ON; SELECT name,is_policy_checked,is_expiration_checked FROM sys.sql_logins;"
$q["D-10"] = Invoke-MssqlQuery -Title "D-10" -Query "SET NOCOUNT ON; SELECT local_net_address,local_tcp_port,encrypt_option,protocol_type,auth_scheme FROM sys.dm_exec_connections WHERE session_id=@@SPID;"
$q["D-11"] = Invoke-MssqlQuery -Title "D-11" -Query "SET NOCOUNT ON; SELECT pr.name AS GranteeName, pr.type_desc, pe.permission_name, pe.state_desc, obj.name AS ObjectName, obj.type_desc FROM sys.database_permissions pe JOIN sys.database_principals pr ON pe.grantee_principal_id=pr.principal_id JOIN sys.objects obj ON pe.major_id=obj.object_id WHERE obj.schema_id=SCHEMA_ID('sys') AND pr.name IN ('public','guest') ORDER BY pr.name,obj.name;"
$q["D-13"] = Invoke-MssqlQuery -Title "D-13" -Query "SET NOCOUNT ON; EXEC master..xp_enum_oledb_providers;"
$q["D-14"] = Invoke-MssqlQuery -Title "D-14" -Query "SET NOCOUNT ON; SELECT SERVERPROPERTY('ErrorLogFileName') AS ErrorLogFileName;"
$q["D-16"] = Invoke-MssqlQuery -Title "D-16" -Query "SET NOCOUNT ON; DECLARE @LoginMode INT; EXEC master..xp_instance_regread N'HKEY_LOCAL_MACHINE',N'Software\Microsoft\MSSQLServer\MSSQLServer',N'LoginMode',@LoginMode OUTPUT; SELECT @LoginMode AS LoginMode;"
$q["D-17"] = Invoke-MssqlQuery -Title "D-17" -Query "SET NOCOUNT ON; SELECT name,is_state_enabled FROM sys.server_audits;"
# $q["D-18"] = Invoke-MssqlQuery -Title "D-18" -Query "SET NOCOUNT ON; SELECT class_desc,major_id,permission_name,state_desc FROM sys.database_permissions WHERE grantee_principal_id=database_principal_id('public');"
$q["D-20"] = Invoke-MssqlQuery -Title "D-20" -Query "SET NOCOUNT ON; SELECT s.name AS schema_name,o.name AS object_name,o.type_desc FROM sys.objects o JOIN sys.schemas s ON o.schema_id=s.schema_id WHERE s.name NOT IN ('sys','INFORMATION_SCHEMA') ORDER BY s.name,o.name;"
$q["D-21"] = Invoke-MssqlQuery -Title "D-21" -Query "SET NOCOUNT ON; SELECT pr.name,pe.permission_name,pe.state_desc FROM sys.database_permissions pe JOIN sys.database_principals pr ON pe.grantee_principal_id=pr.principal_id WHERE pe.state_desc LIKE 'GRANT_WITH_GRANT_OPTION';"
$q["D-23"] = Invoke-MssqlQuery -Title "D-23" -Query "SET NOCOUNT ON; EXEC sp_configure 'xp_cmdshell';"
$q["D-24"] = Invoke-MssqlQuery -Title "D-24" -Query "SET NOCOUNT ON; SELECT name,principal_id,type_desc FROM sys.system_objects WHERE name LIKE 'xp_reg%'; SELECT USER_NAME(grantee_principal_id) AS grantee_principal_name,OBJECT_NAME(major_id) AS object_name,permission_name,state_desc FROM sys.database_permissions WHERE OBJECT_NAME(major_id) LIKE 'xp_reg%' AND permission_name='EXECUTE' AND state_desc='GRANT';"
$q["D-25"] = $versionRes
$q["D-26"] = Invoke-MssqlQuery -Title "D-26" -Query "SET NOCOUNT ON; SELECT SERVERPROPERTY('ErrorLogFileName') AS ErrorLogFileName; EXEC master..xp_instance_regread @rootkey='HKEY_LOCAL_MACHINE', @key='SOFTWARE\Microsoft\MSSQLServer\MSSQLServer', @value_name='AuditLevel';"

Write-ItemReport "D-01" "상" "기본 계정 비밀번호/정책 변경" "WARN" "ManualCheck" "기본 계정 상태 점검 필요" (Get-BasisText $q["D-01"] -ForReport) "기본 계정 잠금/패스워드 변경 확인"
Write-ItemReport "D-02" "상" "불필요 계정 제거/잠금" "WARN" "ManualCheck" "계정 목록 점검 필요" (Get-BasisText $q["D-02"] -ForReport) "불필요/퇴직/미사용 계정 제거"
Write-ItemReport "D-03" "상" "비밀번호 기간 및 복잡도 설정" "WARN" "ManualCheck" "패스워드 정책 확인" (Get-BasisText $q["D-03"] -ForReport) "기관 정책에 맞게 정책 설정"
Write-ItemReport "D-04" "상" "DBA 권한 최소화" "WARN" "ManualCheck" "관리자 권한 계정 점검 필요" (Get-BasisText $q["D-04"] -ForReport) "불필요 sysadmin 회수"
Write-ItemReport "D-05" "중" "비밀번호 재사용 제약" "WARN" "ManualCheck" "재사용 정책 확인 필요" (Get-BasisText $q["D-05"] -ForReport) "패스워드 이력/재사용 설정 확인"
Write-ItemReport "D-06" "중" "DB 사용자 계정 개별 부여" "WARN" "ManualCheck" "공용 계정 사용 여부 인터뷰 필요" "manual" "개인별/응용프로그램별 계정 분리"
Write-ItemReport "D-07" "중" "root 권한으로 서비스 구동 제한" "N/A" "NotApplicable" "UNIX root 항목" "Windows 환경" "해당사항 없음"
Write-ItemReport "D-08" "상" "안전한 암호화 알고리즘 사용" "WARN" "ManualCheck" "연결 암호화 상태 점검" (Get-BasisText $q["D-08"] -ForReport) "TLS/암호화 사용 여부 확인 및 비밀번호 암호화"
Write-ItemReport "D-09" "중" "로그인 실패 잠금 정책" "WARN" "ManualCheck" "잠금 정책 확인" (Get-BasisText $q["D-09"] -ForReport) "실패 횟수/잠금 시간 정책 설정"
Write-ItemReport "D-10" "상" "원격 접속 제한" "WARN" "ManualCheck" "원격 접속 제한 정책 확인" (Get-BasisText $q["D-10"] -ForReport) "허용 IP/포트/방화벽 정책 점검"
Write-ItemReport "D-11" "상" "비인가 사용자 시스템 테이블 접근 제한" "WARN" "ManualCheck" "시스템 테이블 권한 점검" (Get-BasisText $q["D-11"] -ForReport) "비인가 권한 회수"
Write-ItemReport "D-12" "상" "안전한 리스너 비밀번호 설정 및 사용" "N/A" "NotApplicable" "가이드상 주 대상 아님" "mssql" "해당사항 없음"
Write-ItemReport "D-13" "중" "불필요한 ODBC/OLE-DB 데이터 소스 제거" "WARN" "ManualCheck" "Windows DSN/드라이버 점검 필요" (Get-BasisText $q["D-13"] -ForReport) "ODBC/OLEDB 정리"
Write-ItemReport "D-14" "중" "주요 파일 접근권한 적절성" "WARN" "ManualCheck" "주요 설정/로그 파일 ACL 점검 필요" (Get-BasisText $q["D-14"] -ForReport) "ACL 최소권한 설정"
Write-ItemReport "D-15" "하" "오라클 리스너 로그/trace 변경 제한" "N/A" "NotApplicable" "Oracle 전용 항목" "mssql" "해당사항 없음"
Write-ItemReport "D-16" "하" "Windows 인증 모드 사용" "WARN" "ManualCheck" "혼합 모드 또는 비확인" (Get-BasisText $q["D-16"] -ForReport) "Windows 인증 모드 및 sa 정책 검토"
Write-ItemReport "D-17" "하" "Audit Table 접근 제한" "WARN" "ManualCheck" "감사 기능 및 접근 통제 점검" (Get-BasisText $q["D-17"] -ForReport) "감사 로그 접근 통제 확인"
Write-ItemReport "D-18" "상" "응용프로그램 또는 DBA Role의 Public 설정 조정" "N/A" "NotApplicable" "가이드상 주 대상 아님" "mssql" "해당사항 없음"
Write-ItemReport "D-19" "상" "OS_ROLES/REMOTE_OS_* FALSE 설정" "N/A" "NotApplicable" "Oracle 전용" "mssql" "해당사항 없음"
Write-ItemReport "D-20" "하" "인가되지 않은 Object owner 제한" "WARN" "ManualCheck" "비표준 객체 owner 점검" (Get-BasisText $q["D-20"] -ForReport) "비인가 schema/object owner 검토"
Write-ItemReport "D-21" "중" "인가되지 않은 GRANT OPTION 제한" "WARN" "ManualCheck" "GRANT OPTION 점검" (Get-BasisText $q["D-21"] -ForReport) "불필요 GRANT OPTION 회수"
Write-ItemReport "D-22" "하" "자원 제한 기능 TRUE 설정" "N/A" "NotApplicable" "Oracle 중심 항목" "mssql" "수동 확인"
Write-ItemReport "D-23" "상" "xp_cmdshell 사용 제한" "WARN" "ManualCheck" "xp_cmdshell 설정 확인 필요" (Get-BasisText $q["D-23"] -ForReport) "xp_cmdshell 비활성 검토"
Write-ItemReport "D-24" "상" "Registry Procedure 권한 제한" "WARN" "ManualCheck" "xp_reg* 계열 점검" (Get-BasisText $q["D-24"] -ForReport) "권한/사용 제한"
Write-ItemReport "D-25" "상" "보안 패치 및 벤더 권고 적용" "WARN" "ManualCheck" "버전 정보 수집" (Get-BasisText $q["D-25"] -ForReport) "벤더 최신 패치/권고 비교"
Write-ItemReport "D-26" "상" "감사 기록 정책 적합성" "WARN" "ManualCheck" "감사/로그 설정 점검" (Get-BasisText $q["D-26"] -ForReport) "기관 감사 정책에 맞게 설정"

Add-Raw "connection status" $connectionStatus
Add-Raw "services" $services
Add-Raw "processes" $processes
Add-Raw "NetFirewallRule" $netFirewallRule
Add-Raw "system DSN" $systemDsn
Add-Raw "client discovery" ("ResolvedClient : " + $script:Client)
Add-Raw "client precheck" (Test-ClientPrecheck)
Add-Raw "input parameters" ("DBHOST={0}`r`nDBINSTANCE={1}`r`nDBPORT={2}`r`nAUTHMODE={3}`r`nDBUSER={4}`r`nDBNAME={5}`r`nServerTarget={6}" -f $script:DBHOST, $script:DBINSTANCE, $script:DBPORT, $script:AuthMode, $script:DBUserForTrace, $script:DBNAME, $serverTarget)
Add-Raw "version" $versionBasis
Add-Raw "ErrorLog 및 AuditLevel 값 조회 (0:None, 1:Success, 2:Failed, 3:Both)" (Get-BasisText $q["D-26"])

foreach ($k in $q.Keys) {
    if ($null -eq $q[$k]) { continue }
    Add-Raw ($k + " queried result") (Get-BasisText $q[$k])
}

Add-Line "==================== SUMMARY ===================="
Add-Line ("OK   : " + $script:OK_COUNT)
Add-Line ("WARN : " + $script:WARN_COUNT)
Add-Line ("VULN : " + $script:VULN_COUNT)
Add-Line ("N/A  : " + $script:NA_COUNT)
Add-Line "================================================="
Add-Line ""
Add-Line "==================== RAW DATA ===================="
foreach ($line in $script:Raw) { Add-Line $line }

Write-Host ""
Write-Host ("Result file: " + $script:OutFile)

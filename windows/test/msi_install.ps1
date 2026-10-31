# ztgate.msi 를 SERVER, PORT, CODE 와 함께 실제로 설치해 보고 약속을 확인한다. 관리자 PowerShell 에서.
#
#   powershell -File windows\test\msi_install.ps1 [-Msi <ztgate.msi>] [-Server <host>] [-Port <n>] [-Uninstall]
#
# 코드는 형식만 맞고 어느 서버도 내준 적이 없는 값이다. 기본 서버(vpn.example.invalid)에는 닿지 않으므로
# 등록되지 않은 PC 에서는 서비스가 코드를 들고 다시 시도하는 상태가 된다. 이미 등록된 PC 에서는 서비스가
# 그 코드를 쓰지 않고 지워야 하며, 기기 ID 가 그대로여야 한다. 지금 깔린 것보다 높은 버전으로 만든 MSI 를
# 준다 (같은 버전이면 업그레이드가 아니라 나란히 설치된다).
#
# -Uninstall 은 마지막에 제거까지 해 본다 (CI 처럼 버려도 되는 PC 에서만). 주지 않으면 설치된 채로 두고,
# 처음에 없던 HKLM\SOFTWARE\ztgate\install 은 지운다.
param(
	[string]$Msi = (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) '..\build\Release\ztgate.msi'),
	[string]$Server = 'vpn.example.invalid',
	[int]$Port = 9443,
	[switch]$Uninstall
)
$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'run as administrator' }

$Msi = (Resolve-Path $Msi).Path
$code = '7K2QF-9XWM4-ABCDE-FGHJK-MNPQR'
$logs = Join-Path $env:TEMP "ztgate-msi-test-$PID"
New-Item -ItemType Directory -Force $logs | Out-Null
$svc = Join-Path $env:ProgramFiles 'ztgate\vpn_service.exe'

$failed = 0
function Check([string]$name, [bool]$ok, [string]$got = '') {
	if ($ok) { Write-Output ("{0,-48} ok" -f $name) }
	else { Write-Output ("{0,-48} FAIL {1}" -f $name, $got); $script:failed++ }
}
function Msiexec([string[]]$arguments) {
	$p = Start-Process msiexec.exe -ArgumentList $arguments -Wait -PassThru
	return $p.ExitCode
}
function DeviceId {
	$v = Get-ItemProperty 'HKLM:\SOFTWARE\ztgate\device' -Name id -ErrorAction SilentlyContinue
	if ($v) { return [BitConverter]::ToString($v.id) }
	return ''
}
function Status {
	return (& $svc ctl status 2 2>&1 | Out-String)
}

$idBefore = DeviceId
$enrolled = $idBefore -ne ''
$hadInstall = Test-Path 'HKLM:\SOFTWARE\ztgate\install'
Write-Output "this PC is $(if ($enrolled) { 'enrolled' } else { 'not enrolled' })"

# 형식이 틀린 코드는 설치를 되돌린다. 무엇이 틀렸는지가 기록에 남는다.
$bad = Join-Path $logs 'bad.log'
$rc = Msiexec @('/i', "`"$Msi`"", "SERVER=$Server", 'CODE=NOT-A-CODE', '/qn', '/l*v', "`"$bad`"")
Check 'a malformed CODE fails the install' ($rc -eq 1603) "exit $rc"
Check 'the log says CODE was the problem' ([bool](Select-String -Path $bad -SimpleMatch 'returned actual error code 4' -Quiet))
Check 'the log does not hold the bad code' (-not (Select-String -Path $bad -SimpleMatch 'NOT-A-CODE' -Quiet))

$ok = Join-Path $logs 'install.log'
$rc = Msiexec @('/i', "`"$Msi`"", "SERVER=$Server", "PORT=$Port", "CODE=$code", '/qn', '/l*v', "`"$ok`"")
Check 'install with SERVER, PORT, CODE' ($rc -eq 0 -or $rc -eq 3010) "exit $rc"
Check 'the log does not hold the code' (-not (Select-String -Path $ok -SimpleMatch $code -Quiet))
Check 'the log hides CODE' ([bool](Select-String -Path $ok -Pattern 'CODE = \*+' -Quiet))

$install = Get-ItemProperty 'HKLM:\SOFTWARE\ztgate\install' -ErrorAction SilentlyContinue
Check 'SERVER is the GUI default' ($install -and $install.servers -eq $Server) ($install | Out-String)
Check 'PORT is the GUI default' ($install -and $install.port -eq $Port)

if ($enrolled) {
	$deadline = (Get-Date).AddSeconds(30)
	while ((Test-Path 'HKLM:\SOFTWARE\ztgate\enroll') -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
	Check 'an enrolled PC drops the code' (-not (Test-Path 'HKLM:\SOFTWARE\ztgate\enroll'))
	Check 'the identity is unchanged' ((DeviceId) -eq $idBefore) "$idBefore -> $(DeviceId)"
	$s = Status
	Check 'nothing to report (quit the GUI first)' ($s -match 'device: [0-9a-f]+' -and -not ($s -match 'install enrollment')) $s
}
else {
	Check 'the code waits for the service' (Test-Path 'HKLM:\SOFTWARE\ztgate\enroll')
	$acl = Get-Acl 'HKLM:\SOFTWARE\ztgate\enroll'
	$who = @($acl.Access | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
	Check 'the code key does not inherit' ($acl.AreAccessRulesProtected)
	Check 'only SYSTEM and Administrators' ($who.Count -eq 2 -and ($who -contains 'NT AUTHORITY\SYSTEM') -and ($who -contains 'BUILTIN\Administrators')) ($who -join ', ')
	$s = ''
	$deadline = (Get-Date).AddSeconds(60)
	do { $s = Status } while (-not ($s -match 'install enrollment: waiting \(last result [1-9]') -and (Get-Date) -lt $deadline)
	Check 'the service retries an unreachable server' ($s -match 'install enrollment: waiting \(last result [1-9]') $s
	Check 'still not enrolled' ((DeviceId) -eq '')
}

# 복구는 SERVER 도 CODE 도 없이 돈다. 설정은 그대로, 지운 코드는 되살아나지 않는다.
$codeLeft = Test-Path 'HKLM:\SOFTWARE\ztgate\enroll'
$rc = Msiexec @('/fa', "`"$Msi`"", '/qn', '/l*v', "`"$(Join-Path $logs 'repair.log')`"")
Check 'repair' ($rc -eq 0 -or $rc -eq 3010) "exit $rc"
$install = Get-ItemProperty 'HKLM:\SOFTWARE\ztgate\install' -ErrorAction SilentlyContinue
Check 'repair keeps SERVER' ($install -and $install.servers -eq $Server)
Check 'repair does not bring a used code back' ((Test-Path 'HKLM:\SOFTWARE\ztgate\enroll') -eq $codeLeft)

if ($Uninstall) {
	$rc = Msiexec @('/x', "`"$Msi`"", '/qn', '/l*v', "`"$(Join-Path $logs 'uninstall.log')`"")
	Check 'uninstall' ($rc -eq 0 -or $rc -eq 3010) "exit $rc"
	Check 'uninstall drops an unused code' (-not (Test-Path 'HKLM:\SOFTWARE\ztgate\enroll'))
	Check 'uninstall keeps the server default' (Test-Path 'HKLM:\SOFTWARE\ztgate\install')
}
if (-not $hadInstall) {
	Remove-Item 'HKLM:\SOFTWARE\ztgate\install' -ErrorAction SilentlyContinue
}

Write-Output "logs: $logs"
if ($failed) { throw "$failed checks failed" }

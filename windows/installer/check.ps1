# 만든 ztgate.msi 의 표를 읽어 설치 속성(SERVER, PORT, CODE)이 약속대로 들어 있는지 본다. 설치하지 않는다.
#
#   powershell -File windows\installer\check.ps1 [windows\build\Release\ztgate.msi]
param(
	[string]$Msi = (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) '..\build\Release\ztgate.msi')
)
$ErrorActionPreference = 'Stop'

$installer = New-Object -ComObject WindowsInstaller.Installer
$db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @((Resolve-Path $Msi).Path, 0))

function Query([string]$sql) {
	$view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @($sql))
	$view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
	$rows = @()
	while ($true) {
		$rec = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
		if ($null -eq $rec) { break }
		$n = $rec.GetType().InvokeMember('FieldCount', 'GetProperty', $null, $rec, $null)
		$rows += , @(1..[int]$n | ForEach-Object { $rec.GetType().InvokeMember('StringData', 'GetProperty', $null, $rec, @([int]$_)) })
	}
	$view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null) | Out-Null
	return , $rows
}

$failed = 0
function Check([string]$name, [bool]$ok, [string]$got = '') {
	if ($ok) { Write-Output ("{0,-40} ok" -f $name) }
	else { Write-Output ("{0,-40} FAIL {1}" -f $name, $got); $script:failed++ }
}

$props = @{}
foreach ($r in (Query 'SELECT `Property`, `Value` FROM `Property`')) { $props[$r[0]] = $r[1] }
$secure = $props['SecureCustomProperties'] -split ';'
$hidden = $props['MsiHiddenProperties'] -split ';'

Check 'PORT defaults to 9000' ($props['PORT'] -eq '9000') $props['PORT']
Check 'SERVER and CODE have no value' (-not $props.ContainsKey('SERVER') -and -not $props.ContainsKey('CODE'))
Check 'SERVER, PORT, CODE are secure' (($secure -contains 'SERVER') -and ($secure -contains 'PORT') -and ($secure -contains 'CODE')) $props['SecureCustomProperties']
Check 'CODE is hidden' ($hidden -contains 'CODE') $props['MsiHiddenProperties']

$ca = Query 'SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction` WHERE `Action` = ''Preset'''
Check 'Preset runs vpn_service.exe' ($ca.Count -eq 1 -and $ca[0][2] -eq 'vpn_service.exe') ($ca | Out-String)
if ($ca.Count -eq 1) {
	$type = [int]$ca[0][1]
	# 18 = 설치한 파일의 exe, 0x800 deferred, 0x400 시스템 계정 (no impersonate), 0x2000 기록에 대상을 숨긴다
	Check 'Preset is deferred, system, hidden target' (($type -band 0x3F) -eq 18 -and ($type -band 0x800) -and ($type -band 0x400) -and ($type -band 0x2000)) "type $type"
	Check 'Preset passes all three' ($ca[0][3] -eq 'preset "[SERVER]" "[PORT]" "[CODE]"') $ca[0][3]
}

$seq = @{}
foreach ($r in (Query 'SELECT `Action`, `Condition`, `Sequence` FROM `InstallExecuteSequence`')) { $seq[$r[0]] = $r }
Check 'Preset before StartServices' ($seq.ContainsKey('Preset') -and [int]$seq['Preset'][2] -lt [int]$seq['StartServices'][2] -and [int]$seq['Preset'][2] -gt [int]$seq['InstallFiles'][2])
Check 'Preset only when given, not on removal' ($seq.ContainsKey('Preset') -and $seq['Preset'][1] -eq '(SERVER OR CODE) AND NOT REMOVE~="ALL"') $seq['Preset'][1]

# 이름이 "-" 이고 값이 없는 줄은 제거할 때 키를 통째로 지운다.
$reg = Query 'SELECT `Key`, `Root`, `Name`, `Value` FROM `Registry`'
$ours = @($reg | Where-Object { $_[0] -like 'Software\ztgate\*' })
Check 'uninstall drops an unused code' (@($ours | Where-Object { $_[0] -eq 'Software\ztgate\enroll' -and $_[1] -eq '2' -and $_[2] -eq '-' -and $_[3] -eq '' }).Count -eq 1) ($ours | Out-String)
Check 'no registry row writes settings' ($ours.Count -eq 1) ($ours | Out-String)

$ctl = @{}
foreach ($r in (Query 'SELECT `Control`, `Type`, `Property`, `Text` FROM `Control` WHERE `Dialog_` = ''ConnectDlg''')) { $ctl[$r[0]] = $r }
Check 'dialog edits SERVER, PORT, CODE' ($ctl['Server'][2] -eq 'SERVER' -and $ctl['Port'][2] -eq 'PORT' -and $ctl['Code'][2] -eq 'CODE' -and
	$ctl['Server'][1] -eq 'Edit' -and $ctl['Code'][1] -eq 'Edit')
# 코드 페이지가 맞지 않으면 한글이 ? 로 바뀌어 들어간다.
Check 'dialog labels are Korean' ($ctl['ServerLabel'][3] -eq '서버 주소' -and $ctl['PortLabel'][3] -eq '포트' -and $ctl['CodeLabel'][3] -eq '등록 코드') ($ctl['ServerLabel'][3])
$ev = Query 'SELECT `Dialog_`, `Control_`, `Event`, `Argument`, `Condition` FROM `ControlEvent` WHERE `Event` = ''NewDialog'''
Check 'welcome leads to the dialog' (@($ev | Where-Object { $_[0] -eq 'WelcomeDlg' -and $_[3] -eq 'ConnectDlg' -and $_[4] -eq 'NOT Installed' }).Count -eq 1)
Check 'the dialog leads to install' (@($ev | Where-Object { $_[0] -eq 'ConnectDlg' -and $_[1] -eq 'Next' -and $_[3] -eq 'VerifyReadyDlg' }).Count -eq 1)
$ui = @((Query 'SELECT `Action` FROM `InstallUISequence`') | ForEach-Object { $_[0] })
Check 'install UI starts at the welcome page' (($ui -contains 'WelcomeDlg') -and ($ui -contains 'MaintenanceWelcomeDlg'))

if ($failed) { throw "$failed checks failed" }

# ztgate.msi 를 만든다. 먼저 솔루션을 Release x64 로 빌드하고, Wintun 을 windows\third_party 에 풀어 둔다.
#
#   powershell -File windows\installer\build.ps1 [-Version 0.7.0] [-Wix <WiX 3 의 bin 폴더>]
#
# WiX 3 은 GitHub 의 windows-2022 러너에 깔려 있고 그 자리를 WIX 환경 변수가 가리킨다. 다른
# 곳에서는 wix314-binaries.zip 을 풀어 그 폴더를 -Wix 로 준다 (설치하지 않아도 된다).
param(
	[string]$Version = '0.9.1',
	[string]$Wix = ''
)
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$bin = Join-Path $here '..\build\Release' | Resolve-Path
$obj = Join-Path $here '..\build\installer'
New-Item -ItemType Directory -Force $obj | Out-Null

if (-not $Wix) {
	if (-not $env:WIX) { throw 'WiX 3 not found: pass -Wix <folder with candle.exe>' }
	$Wix = Join-Path $env:WIX 'bin'
}
$candle = Join-Path $Wix 'candle.exe'
$light = Join-Path $Wix 'light.exe'

# wintun.dll 은 WireGuard LLC 의 바이너리라 함께 내보낼 때 그 라이선스도 옆에 둔다.
$license = Join-Path $bin 'wintun-LICENSE.txt'
if (-not (Test-Path $license)) {
	Copy-Item (Join-Path $here '..\third_party\wintun\LICENSE.txt') $license
}

foreach ($f in 'vpn_service.exe', 'vpn_gui.exe', 'vpn_client.exe', 'wintun.dll') {
	if (-not (Test-Path (Join-Path $bin $f))) { throw "missing $f in $bin (build the solution first)" }
}

& $candle -nologo -arch x64 -ext WixUtilExtension "-dVersion=$Version" "-dBinDir=$bin" `
	-out (Join-Path $obj 'ztgate.wixobj') (Join-Path $here 'ztgate.wxs')
if ($LASTEXITCODE -ne 0) { throw "candle failed ($LASTEXITCODE)" }

# ICE 검사 중 서비스와 바로가기에 관한 것은 per-machine 설치에서 그대로 맞는 경고다.
& $light -nologo -ext WixUtilExtension -spdb -out (Join-Path $bin 'ztgate.msi') (Join-Path $obj 'ztgate.wixobj')
if ($LASTEXITCODE -ne 0) { throw "light failed ($LASTEXITCODE)" }

Write-Output "built $(Join-Path $bin 'ztgate.msi')"

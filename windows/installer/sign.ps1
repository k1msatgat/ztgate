# Authenticode 로 서명한다. 인증서가 없으면 아무것도 하지 않고 그렇다고 알린다 (빌드는 그대로 간다).
#
#   windows\installer\sign.ps1 <파일> [<파일> ...]
#
# 인증서는 환경 변수로 받는다 (CI 에서는 저장소 Secrets):
#   ZTGATE_SIGN_PFX_BASE64   코드 서명 인증서 (.pfx) 를 base64 로
#   ZTGATE_SIGN_PFX_PASSWORD 그 암호
#   ZTGATE_SIGN_TIMESTAMP    타임스탬프 서버 (기본 http://timestamp.digicert.com)
#
# EV 인증서처럼 키가 HSM / 클라우드 KMS 에 있으면 이 스크립트 대신 그 공급자의 signtool 플러그인을 쓴다.
param([Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)][string[]]$Files)
$ErrorActionPreference = 'Stop'

if (-not $env:ZTGATE_SIGN_PFX_BASE64) {
	Write-Output "::warning title=code signing::no certificate (ZTGATE_SIGN_PFX_BASE64); $($Files.Count) file(s) left unsigned"
	exit 0
}

$sdk = Get-ChildItem "${env:ProgramFiles(x86)}/Windows Kits/10/bin/*/x64/signtool.exe" | Sort-Object FullName | Select-Object -Last 1
if (-not $sdk) { throw 'signtool.exe not found (Windows SDK)' }

$pfx = Join-Path ([IO.Path]::GetTempPath()) ("ztgate-sign-{0}.pfx" -f [guid]::NewGuid())
try {
	[IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:ZTGATE_SIGN_PFX_BASE64))
	$ts = if ($env:ZTGATE_SIGN_TIMESTAMP) { $env:ZTGATE_SIGN_TIMESTAMP } else { 'http://timestamp.digicert.com' }
	& $sdk.FullName sign /fd sha256 /td sha256 /tr $ts /f $pfx /p $env:ZTGATE_SIGN_PFX_PASSWORD /d ztgate $Files
	if ($LASTEXITCODE -ne 0) { throw "signtool failed ($LASTEXITCODE)" }
	& $sdk.FullName verify /pa $Files
	if ($LASTEXITCODE -ne 0) { throw "signature does not verify ($LASTEXITCODE)" }
}
finally {
	Remove-Item -Force -ErrorAction SilentlyContinue $pfx
}

# Copyright (c) 2021 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.
# SPDX-License-Identifier: BSD-2-Clause

param(
	[string]$GPGPath = "C:\Program Files (x86)\GnuPG\bin\gpg.exe",
	[string]$Config = "Release"
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Cygwin coordinates.
$URL = 'https://www.cygwin.com'
$Setup = 'setup-x86_64.exe'
$Mirrors = @(
	'https://mirrors.kernel.org/sourceware/cygwin/',
	'https://mirrorservice.org/sites/sourceware.org/pub/cygwin/',
	'https://cygwin.mirror.constant.com/'
)
$Packages = 'gcc-core,pkg-config,cmake,make,libcbor-devel,libssl-devel,zlib-devel'

# Work directories.
$Cygwin = "$PSScriptRoot\..\cygwin"
$Root = "${Cygwin}\root"

# Find GPG.
$GPG = $(Get-Command gpg -ErrorAction Ignore | `
    Select-Object -ExpandProperty Source)
if ([string]::IsNullOrEmpty($GPG)) {
	$GPG = $GPGPath
}
if (-Not (Test-Path $GPG)) {
	throw "Unable to find GPG at $GPG"
}

Write-Host "Config: $Config"
Write-Host "GPG: $GPG"

# Create work directories.
New-Item -Type Directory "${Cygwin}" -Force
New-Item -Type Directory "${Root}" -Force

# Create GNUPGHOME with an empty common.conf to disable use-keyboxd.
# Recent default is to enable keyboxd which in turn ignores --keyring
# arguments.
$GpgHome = "${Cygwin}\.gnupg"
New-Item -Type Directory "${GpgHome}" -Force
New-Item -Type File "${GpgHome}\common.conf" -Force

# Fetch and verify Cygwin.
Push-Location ${Cygwin}
try {
	if (-Not (Test-Path .\${Setup} -PathType leaf)) {
		Invoke-WebRequest ${URL}/${Setup} `
		    -OutFile .\${Setup}
	}
	if (-Not (Test-Path .\${Setup}.sig -PathType leaf)) {
		Invoke-WebRequest ${URL}/${Setup}.sig `
		    -OutFile .\${Setup}.sig
	}
	Copy-Item "$PSScriptRoot\cygwin.gpg" -Destination "${Cygwin}"
	& $GPG --homedir ./.gnupg --list-keys
	& $GPG --homedir ./.gnupg --quiet --no-default-keyring `
	    --keyring ./cygwin.gpg `
	    --verify ./${Setup}.sig ./${Setup}
	if ($LastExitCode -ne 0) {
		throw "GPG signature verification failed"
	}
} catch {
	throw "Failed to fetch and verify Cygwin"
} finally {
	Pop-Location
}

# Bootstrap Cygwin.
$Installed = $false
foreach ($Mirror in $Mirrors) {
	Write-Host "Trying Cygwin mirror: ${Mirror}"
	$SetupProcess = Start-Process "${Cygwin}\${Setup}" -Wait -NoNewWindow `
	    -PassThru `
	    -ArgumentList "-dnNOqW -s ${Mirror} -R ${Root} -P ${Packages}"
	if ($SetupProcess.ExitCode -ne 0) {
		Write-Warning "Cygwin setup exited with code $($SetupProcess.ExitCode)"
		continue
	}
	& "${Root}\bin\bash.exe" -lc "command -v gcc cmake make pkg-config >/dev/null"
	if ($LastExitCode -eq 0) {
		$Installed = $true
		break
	}
	Write-Warning "Cygwin installation incomplete from mirror ${Mirror}"
}

if (-Not $Installed) {
	$SetupLog = "${Root}\var\log\setup.log.full"
	if (Test-Path $SetupLog) {
		Write-Host "Last lines from ${SetupLog}:"
		Get-Content $SetupLog -Tail 200
	}
	throw "Failed to install required Cygwin packages from configured mirrors"
}

# Build libfido2.
$Env:PATH = "${Root}\bin;" + $Env:PATH
$Env:CC = "gcc"
& "${Root}\bin\cmake.exe" "-G" "Unix Makefiles" `
    "-DCMAKE_BUILD_TYPE=${Config}" `
    "-DCMAKE_C_COMPILER=gcc" `
    -B "build-${Config}"
if ($LastExitCode -ne 0) {
	throw "CMake configuration failed"
}
& "${Root}\bin\make.exe" -C "build-${Config}"
if ($LastExitCode -ne 0) {
	throw "Build failed"
}
& "${Root}\bin\make.exe" -C "build-${Config}" regress
if ($LastExitCode -ne 0) {
	throw "Regress target failed"
}

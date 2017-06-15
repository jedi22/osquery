#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

# Update-able metadata
$version = '1.2.0'
$chocoVersion = '1.2.0-r2'
$packageName = 'zstd'
$projectSource = 'https://github.com/facebook/zstd'
$packageSourceUrl = 'https://github.com/facebook/zstd'
$authors = 'Facebook'
$owners = 'Facebook'
$copyright = 'https://github.com/facebook/zstd/blob/master/LICENSE'
$license = 'https://github.com/facebook/zstd/blob/master/LICENSE'
$url = "https://github.com/facebook/zstd/archive/v$version.zip"

# Invoke our utilities file
. "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\osquery_utils.ps1"

# Invoke the MSVC developer tools/env
Invoke-BatchFile "$env:VS140COMNTOOLS\..\..\vc\vcvarsall.bat" amd64

# Time our execution
$sw = [System.Diagnostics.StopWatch]::startnew()

# Keep the location of build script, to bring with in the chocolatey package
$buildScript = $MyInvocation.MyCommand.Definition

# Create the choco build dir if needed
$buildPath = Get-OsqueryBuildPath
if ($buildPath -eq '') {
  Write-Host '[-] Failed to find source root' -foregroundcolor red
  exit
}
$chocoBuildPath = "$buildPath\chocolatey\$packageName"
if (-not (Test-Path "$chocoBuildPath")) {
  New-Item -Force -ItemType Directory -Path "$chocoBuildPath"
}
Set-Location $chocoBuildPath

# Retreive the source
$zipFile = "$packageName-$version.zip"
if(-not (Test-Path $zipFile)) {
  Invoke-WebRequest $url -OutFile $zipFile
}

# Extract the source
$sourceDir = Join-Path $(Get-Location) "$packageName-$version"
if (-not (Test-Path $sourceDir)) {
  $7z = (Get-Command '7z').Source
  $arg = "x $zipFile"
  Start-Process -FilePath $7z -ArgumentList $arg -NoNewWindow -Wait
}
Set-Location $sourceDir

$args = @(
  'VS2015',
  'x64',
  'Release',
  'v140'
)
$cmd = Join-Path $(Get-Location) 'build\VS_scripts\build.generic.cmd'
Start-Process -FilePath $cmd -ArgumentList $args -NoNewWindow -Wait

# Construct the Chocolatey Package
$chocoDir = New-Item -ItemType Directory -Path 'osquery-choco'
Set-Location $chocoDir
$includeDir = New-Item -ItemType Directory -Path 'local\include'
$libDir = New-Item -ItemType Directory -Path 'local\lib'
$srcDir = New-Item -ItemType Directory -Path 'local\src'

Write-NuSpec `
  $packageName `
  $chocoVersion `
  $authors `
  $owners `
  $projectSource `
  $packageSourceUrl `
  $copyright `
  $license

Set-Location $sourceDir
Copy-Item "build\VS_scripts\bin\Release\x64\libzstd_static.lib" $libDir
Copy-Item -Recurse "lib\zstd.h" $includeDir
Copy-Item $buildScript $srcDir
Set-Location 'osquery-choco'
choco pack

Write-Host "[*] Build took $($sw.ElapsedMilliseconds) ms" `
  -ForegroundColor DarkGreen
if (Test-Path "$packageName.$chocoVersion.nupkg") {
  Write-Host `
    "[+] Finished building $packageName v$chocoVersion." `
    -ForegroundColor Green
}
else {
  Write-Host `
    "[-] Failed to build $packageName v$chocoVersion." `
    -ForegroundColor Red
}
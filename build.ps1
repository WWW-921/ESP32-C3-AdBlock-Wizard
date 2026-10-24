param(
  [Parameter(Mandatory=$true)][string]$FpcRoot,
  [string]$Python = 'python',
  [string]$Output = "$PSScriptRoot\build\ESP32-AdBlock-Wizard.exe"
)
$ErrorActionPreference='Stop'
$buildDir=Join-Path $PSScriptRoot 'build'
New-Item -ItemType Directory -Force $buildDir | Out-Null
Push-Location $PSScriptRoot
try {
  & $Python -m unittest discover -s tests -v
  if ($LASTEXITCODE) { throw 'Tests failed' }
  & $Python -m PyInstaller --noconfirm --clean --onefile --name engine --distpath $buildDir --workpath "$buildDir\pyinstaller" --specpath $buildDir --collect-all esptool --collect-all esp_pylib --collect-all serial engine.py
  if ($LASTEXITCODE) { throw 'Engine build failed' }
  # ASCII relative resource paths also work when the project folder contains Chinese.
  $resources=@{ENGINE='build/engine.exe';BOOT='firmware/bootloader.bin';PARTITIONS='firmware/partitions.bin';OTA='firmware/boot_app0.bin';APP='firmware/firmware.bin';FILESYSTEM='firmware/littlefs.bin';FWMANIFEST='firmware/manifest.json'}
  $lines=foreach ($key in $resources.Keys) { '{0} RCDATA "{1}"' -f $key,$resources[$key].Replace('\','/') }
  [IO.File]::WriteAllLines("$buildDir\payload.rc",[string[]]$lines,[Text.Encoding]::ASCII)
  $bin=Join-Path $FpcRoot 'bin\x86_64-win64'
  $oldPath=$env:PATH
  $env:PATH=$bin+';'+$env:PATH
  & "$bin\windres.exe" -i 'build/payload.rc' -o 'payload.res' -O res
  if ($LASTEXITCODE) { throw 'Resource compilation failed' }
  & "$bin\fpc.exe" -Mdelphiunicode -dEMBEDDED "-Fu$FpcRoot\units\x86_64-win64\*" '-FUbuild' '-FEbuild' Wizard.dpr
  if ($LASTEXITCODE) { throw 'Pascal compilation failed' }
  $target=[IO.Path]::GetFullPath($Output)
  New-Item -ItemType Directory -Force ([IO.Path]::GetDirectoryName($target)) | Out-Null
  Copy-Item -LiteralPath "$buildDir\Wizard.exe" -Destination $target -Force
  Get-FileHash -LiteralPath $target -Algorithm SHA256
} finally { if ($oldPath) { $env:PATH=$oldPath }; Pop-Location }

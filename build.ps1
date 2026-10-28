param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [switch]$Test,
    [switch]$Run,
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
$preset = $Configuration.ToLowerInvariant()

if (-not (Get-Command cmake.exe -ErrorAction SilentlyContinue)) {
    $cmake = Get-ChildItem 'C:\Program Files\Microsoft Visual Studio' -Recurse -Filter cmake.exe -ErrorAction SilentlyContinue |
        Where-Object FullName -Like '*CommonExtensions*Microsoft*CMake*bin*' |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $cmake) { throw 'CMake was not found. Install the C++ CMake tools component in Visual Studio Installer.' }
    $env:Path = "$(Split-Path $cmake);$env:Path"
}

$hasVs2026 = Test-Path 'C:\Program Files\Microsoft Visual Studio\18'
if ($hasVs2026) { $preset += '-2026' }

if ($Clean -and (Test-Path "$PSScriptRoot\build")) {
    Remove-Item -LiteralPath "$PSScriptRoot\build" -Recurse -Force
}

cmake --preset $(if ($hasVs2026) { 'vs2026' } else { 'vs2022' })
cmake --build --preset $preset
if ($Test) { ctest --preset $preset }
if ($Run) { & "$PSScriptRoot\build\bin\$Configuration\RustyDolphin.exe" }

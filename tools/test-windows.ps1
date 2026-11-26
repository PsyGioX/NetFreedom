# Windows TEST build (unsigned): tests, release build, package, SHA256SUMS.txt, zip + archive hash.
# Run in PowerShell from the repository root, in a VS developer shell (MSVC + Windows SDK), Rust >= 1.83.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$Version = (Select-String -Path Cargo.toml -Pattern '^version = "(.*)"' | Select-Object -First 1).Matches[0].Groups[1].Value

cargo test --locked
cargo build --release --locked

Remove-Item -Recurse -Force package -ErrorAction SilentlyContinue
Copy-Item -Recurse dist/windows package
Copy-Item target/release/netfreedom.exe package/netfreedom.exe
Copy-Item LICENSE, THIRD-PARTY-NOTICES.md, PHILOSOPHY.md, README.md package/
Remove-Item package/SHA256SUMS.txt -ErrorAction SilentlyContinue

Push-Location package
Get-ChildItem -Recurse -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' } | ForEach-Object {
  $rel = (Resolve-Path -Relative $_.FullName).Substring(2) -replace '\\','/'
  "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $rel
} | Sort-Object { $_.Substring(66) } | Set-Content -Encoding ascii SHA256SUMS.txt
Pop-Location

$Zip = "NetFreedom-$Version-windows-x64-test.zip"
Compress-Archive -Path package/* -DestinationPath $Zip -Force
Get-FileHash $Zip -Algorithm SHA256
.\package\netfreedom.exe verify

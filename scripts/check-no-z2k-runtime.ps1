$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$forbidden = @(
  'github.com/necronicle/z2k',
  'raw.githubusercontent.com/necronicle/z2k',
  'codeload.github.com/necronicle/z2k'
)
$productionRoots = @(
  (Join-Path $root 'cmd'),
  (Join-Path $root 'configs'),
  (Join-Path $root 'internal'),
  (Join-Path $root 'scripts'),
  (Join-Path $root '.github')
)
$files = Get-ChildItem -LiteralPath $productionRoots -File -Recurse |
  Where-Object { $_.FullName -notmatch '[\\/]testdata[\\/]' -and $_.Name -ne 'check-no-z2k-runtime.ps1' }

$hits = foreach ($file in $files) {
  foreach ($needle in $forbidden) {
    if (Select-String -LiteralPath $file.FullName -SimpleMatch $needle -Quiet) {
      "$($file.FullName): forbidden runtime dependency $needle"
    }
  }
}
if ($hits) {
  $hits | Write-Error
  exit 1
}
Write-Output 'NO_Z2K_RUNTIME_DEPENDENCY: PASS'

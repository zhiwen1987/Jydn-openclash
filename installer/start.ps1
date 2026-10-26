param([Parameter(ValueFromRemainingArguments=$true)][string[]]$InstallerArguments)
$ErrorActionPreference = 'Stop'
$stackDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$stackPython = Join-Path $stackDirectory 'runtime/win64/python.exe'
if (-not (Test-Path -LiteralPath $stackPython)) { throw 'Missing bundled Python. Extract the complete release package first.' }
$env:PYTHONUTF8 = '1'
$env:PYTHONDONTWRITEBYTECODE = '1'
& $stackPython (Join-Path $stackDirectory 'clash_stack.py') @InstallerArguments
exit $LASTEXITCODE

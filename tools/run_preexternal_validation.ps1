[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$gnuToolchain = '+stable-x86_64-pc-windows-gnu'
$validationFailures = 0
$logRoot = $null

if ($OutputDirectory) {
    $requestedOutputDirectory = if ([System.IO.Path]::IsPathRooted($OutputDirectory)) {
        $OutputDirectory
    }
    else {
        Join-Path $repositoryRoot $OutputDirectory
    }
    $runId = Get-Date -Format 'yyyyMMddTHHmmssfff'
    $logRoot = Join-Path ([System.IO.Path]::GetFullPath($requestedOutputDirectory)) ("run_$runId")
    New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
    Write-Host "Validation logs: $logRoot"
}

function Resolve-Executable {
    param(
        [Parameter(Mandatory = $true)][string]$CommandName,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$PreferredPaths
    )

    foreach ($candidate in $PreferredPaths) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    $command = Get-Command $CommandName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $command) {
        return $command.Source
    }

    return $null
}

$pythonExecutable = Resolve-Executable -CommandName 'python.exe' -PreferredPaths @(
    (Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe')
)
$cargoExecutable = Resolve-Executable -CommandName 'cargo.exe' -PreferredPaths @(
    (Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe')
)

function Write-ValidationStatus {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [Parameter(Mandatory = $true)][bool]$Passed
    )

    $result = if ($Passed) { 'PASS' } else { 'FAIL' }
    Write-Host "[$result] $Name (exit $ExitCode)"
}

function Invoke-ValidationCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $safeName = $Name -replace '[^A-Za-z0-9._-]', '_'
    $exitCode = 9009

    if (-not $Executable -or -not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
        $message = "Required executable is unavailable for $Name."
        if ($logRoot) {
            [System.IO.File]::WriteAllText((Join-Path $logRoot "$safeName.stdout.log"), '')
            [System.IO.File]::WriteAllText((Join-Path $logRoot "$safeName.stderr.log"), "$message`r`n")
        }
        else {
            [Console]::Error.WriteLine($message)
        }
    }
    elseif ($logRoot) {
        $stdoutPath = Join-Path $logRoot "$safeName.stdout.log"
        $stderrPath = Join-Path $logRoot "$safeName.stderr.log"
        try {
            # Start-Process captures the native streams directly.  PowerShell
            # otherwise converts ordinary Cargo/unittest stderr progress into
            # error records, which would pollute a handover log.
            $process = Start-Process -FilePath $Executable -ArgumentList $Arguments -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
            $exitCode = $process.ExitCode
        }
        catch {
            $exitCode = 1
            [System.IO.File]::AppendAllText($stderrPath, ($_.Exception.ToString() + [Environment]::NewLine))
        }
    }
    else {
        $previousErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            & $Executable @Arguments
            $exitCode = $LASTEXITCODE
        }
        catch {
            $exitCode = 1
            [Console]::Error.WriteLine($_.Exception.ToString())
        }
        finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
    }

    $passed = $exitCode -eq 0
    if ($logRoot) {
        $status = [ordered]@{
            name = $Name
            executable = $Executable
            arguments = $Arguments
            exit_code = $exitCode
            passed = $passed
        } | ConvertTo-Json -Depth 3
        [System.IO.File]::WriteAllText((Join-Path $logRoot "$safeName.status.json"), ($status + [Environment]::NewLine))
    }
    Write-ValidationStatus -Name $Name -ExitCode $exitCode -Passed $passed
    if (-not $passed) {
        $script:validationFailures++
    }
}

Push-Location $repositoryRoot
try {
    $gitExecutable = Resolve-Executable -CommandName 'git.exe' -PreferredPaths @()
    if ($gitExecutable) {
        $gitStatus = & $gitExecutable -C $repositoryRoot status --porcelain=v1
        $gitExitCode = $LASTEXITCODE
        if ($gitExitCode -eq 0) {
            if ($gitStatus) {
                Write-Host 'Git worktree: DIRTY'
            }
            else {
                Write-Host 'Git worktree: CLEAN'
            }
        }
        else {
            Write-Host "Git worktree: STATUS UNAVAILABLE (exit $gitExitCode)"
            $validationFailures++
        }
        if ($logRoot) {
            [System.IO.File]::WriteAllText((Join-Path $logRoot 'git_status.stdout.log'), (($gitStatus -join [Environment]::NewLine) + [Environment]::NewLine))
            [System.IO.File]::WriteAllText((Join-Path $logRoot 'git_status.status.json'), (([ordered]@{ exit_code = $gitExitCode; dirty = [bool]$gitStatus } | ConvertTo-Json) + [Environment]::NewLine))
        }
    }
    else {
        Write-Host 'Git worktree: STATUS UNAVAILABLE (git executable unavailable)'
        $validationFailures++
    }

    Invoke-ValidationCommand -Name 'active_v2_python_pytest' -Executable $pythonExecutable -Arguments @('-m', 'pytest', 'tests')
    Invoke-ValidationCommand -Name 'v2_wire_python' -Executable $pythonExecutable -Arguments @('-I', '-B', 'wire_protocol/v2/run_python_tests.py')
    Invoke-ValidationCommand -Name 'cross_language_unittest' -Executable $pythonExecutable -Arguments @('-B', '-m', 'unittest', 'cross_language_reconciliation.test_reconciliation', 'cross_language_reconciliation.test_detached_semantic_verifier')

    Invoke-ValidationCommand -Name 'security_core_rust_test_gnu' -Executable $cargoExecutable -Arguments @($gnuToolchain, 'test', '--manifest-path', 'security_core/Cargo.toml', '--locked')
    Invoke-ValidationCommand -Name 'security_core_rust_check_gnu' -Executable $cargoExecutable -Arguments @($gnuToolchain, 'check', '--manifest-path', 'security_core/Cargo.toml', '--all-targets', '--locked')
    Invoke-ValidationCommand -Name 'security_core_rust_fmt_check_gnu' -Executable $cargoExecutable -Arguments @($gnuToolchain, 'fmt', '--manifest-path', 'security_core/Cargo.toml', '--', '--check')
    Invoke-ValidationCommand -Name 'security_core_rust_clippy_gnu' -Executable $cargoExecutable -Arguments @($gnuToolchain, 'clippy', '--manifest-path', 'security_core/Cargo.toml', '--all-targets', '--locked', '--', '-D', 'warnings')

    Invoke-ValidationCommand -Name 'v2_wire_rust_test_gnu' -Executable $cargoExecutable -Arguments @($gnuToolchain, 'test', '--manifest-path', 'wire_protocol/v2/rust/Cargo.toml', '--locked')
    Invoke-ValidationCommand -Name 'polyglot_v2_kernel_rust_test_gnu' -Executable $cargoExecutable -Arguments @($gnuToolchain, 'test', '--manifest-path', 'polyglot/rust/v2_assurance_kernel/Cargo.toml', '--locked')
    Invoke-ValidationCommand -Name 'polyglot_v2_kernel_rust_clippy_gnu' -Executable $cargoExecutable -Arguments @($gnuToolchain, 'clippy', '--manifest-path', 'polyglot/rust/v2_assurance_kernel/Cargo.toml', '--all-targets', '--locked', '--', '-D', 'warnings')
    Invoke-ValidationCommand -Name 'rust_authority_service_test_gnu' -Executable $cargoExecutable -Arguments @($gnuToolchain, 'test', '--manifest-path', 'rust_authority_service/Cargo.toml', '--all-targets', '--features', 'evidence-only-fixtures', '--locked')
    Invoke-ValidationCommand -Name 'rust_authority_service_clippy_gnu' -Executable $cargoExecutable -Arguments @($gnuToolchain, 'clippy', '--manifest-path', 'rust_authority_service/Cargo.toml', '--all-targets', '--features', 'evidence-only-fixtures', '--locked', '--', '-D', 'warnings')
}
finally {
    Pop-Location
}

Write-Host 'Not validated by this local runner: TPM hardware/custody, external providers, or deployed effect-path non-bypass.'
if ($validationFailures -gt 0) {
    Write-Host "Validation completed with $validationFailures failure(s)."
    exit 1
}

Write-Host 'Validation completed with no local command failures.'
exit 0

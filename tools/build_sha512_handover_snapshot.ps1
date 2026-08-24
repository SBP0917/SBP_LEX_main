[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path.TrimEnd([char[]]@('\', '/'))
$OutputRoot = Join-Path $RepositoryRoot "runtime_artifacts\sha512_handover"
$SnapshotFileNames = @(
    "repository_state.txt",
    "tracked_worktree.patch",
    "exclusions.txt",
    "source_evidence_sha512_manifest.tsv",
    "excluded_files.tsv",
    "untracked_sha512_manifest.tsv",
    "untracked_excluded_files.tsv",
    "tool_versions.txt",
    "README.md",
    "snapshot_artifacts_sha512_manifest.tsv"
)

foreach ($snapshotFileName in $SnapshotFileNames) {
    $snapshotFilePath = Join-Path $OutputRoot $snapshotFileName
    if (Test-Path -LiteralPath $snapshotFilePath) {
        throw "Refusing to overwrite an existing handover snapshot record: $snapshotFilePath"
    }
}

function Write-Utf8Text {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )

    [System.IO.File]::WriteAllText($Path, $Text, $Utf8NoBom)
}

function Write-Utf8Lines {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string[]]$Lines
    )

    [System.IO.File]::WriteAllLines($Path, $Lines, $Utf8NoBom)
}

function Get-RelativeRepositoryPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $relative = $Path.Substring($RepositoryRoot.Length).TrimStart([char[]]@('\', '/'))
    return $relative.Replace("\", "/")
}

$ExcludedDirectoryNames = @(
    ".git",
    ".codex",
    ".codex-cli",
    "target",
    "__pycache__",
    ".pytest_cache",
    "pytest_tmp",
    "test_tmp",
    "tmp",
    "temp"
)

function Get-ExclusionReason {
    param([Parameter(Mandatory = $true)][string]$RelativePath)

    if ($RelativePath -eq "runtime_artifacts/sha512_handover" -or
        $RelativePath.StartsWith("runtime_artifacts/sha512_handover/", [System.StringComparison]::OrdinalIgnoreCase)) {
        return "handover-output-folder"
    }

    foreach ($segment in ($RelativePath -split "/")) {
        if ($ExcludedDirectoryNames -contains $segment) {
            return "excluded-directory-segment:$segment"
        }
    }

    if ($RelativePath.StartsWith("runtime_artifacts/", [System.StringComparison]::OrdinalIgnoreCase)) {
        foreach ($segment in ($RelativePath -split "/")) {
            if ($segment -match "(?i)(^|[-_])(test|tmp|temp|pytest)([-_]|$)") {
                return "temporary-runtime-test-directory:$segment"
            }
        }
    }

    return $null
}

function Get-Sha512Entry {
    param([Parameter(Mandatory = $true)][System.IO.FileInfo]$File)

    $relative = Get-RelativeRepositoryPath -Path $File.FullName
    $hash = (Get-FileHash -Algorithm SHA512 -LiteralPath $File.FullName).Hash.ToLowerInvariant()
    return "{0}`t{1}`t{2}" -f $hash, $File.Length, $relative
}

function Get-ToolVersionBlock {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $commandInfo = Get-Command -Name $Command -ErrorAction SilentlyContinue
    if ($null -eq $commandInfo) {
        return @("[$Name]", "status=UNAVAILABLE", "")
    }

    $versionOutput = (& $Command @Arguments 2>&1 | Out-String).TrimEnd()
    $exitCode = $LASTEXITCODE
    return @(
        "[$Name]",
        "status=AVAILABLE",
        "path=$($commandInfo.Source)",
        "exit_code=$exitCode",
        "version_output=$versionOutput",
        ""
    )
}

New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

$generatedAt = [DateTime]::UtcNow.ToString("o")
$head = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Could not resolve repository HEAD."
}

$branch = (& git -C $RepositoryRoot symbolic-ref --short -q HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($branch)) {
    $branch = "DETACHED"
}

$status = (& git -C $RepositoryRoot status --short --branch --untracked-files=all 2>&1 | Out-String).TrimEnd()
if ($LASTEXITCODE -ne 0) {
    throw "Could not capture repository status."
}

$repositoryStatePath = Join-Path $OutputRoot "repository_state.txt"
Write-Utf8Text -Path $repositoryStatePath -Text @"
snapshot_generated_utc=$generatedAt
repository_root=$RepositoryRoot
head=$head
branch=$branch

git_status_porcelain_v1:
$status
"@

$patchPath = Join-Path $OutputRoot "tracked_worktree.patch"
$patch = (& git -C $RepositoryRoot diff --binary --full-index --no-ext-diff HEAD -- . 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) {
    throw "Could not capture the binary tracked-worktree patch."
}
Write-Utf8Text -Path $patchPath -Text $patch

$exclusionsPath = Join-Path $OutputRoot "exclusions.txt"
Write-Utf8Text -Path $exclusionsPath -Text @"
SHA-512 source/evidence and untracked manifests include ordinary files under the repository root.

The following directory segments are excluded wherever they occur:
- .git (Git internals)
- .codex (Codex local state)
- .codex-cli (Codex CLI local state)
- target (compiled Rust/build outputs)
- __pycache__ (compiled Python cache)
- .pytest_cache (pytest cache)
- pytest_tmp, test_tmp, tmp, temp (temporary test/work folders)
- runtime_artifacts subfolders with a name segment such as *-test-*, *-tmp-*,
  *-temp-*, or pytest-* (temporary test-run output)
- runtime_artifacts/sha512_handover (this generated snapshot, excluded to avoid self-reference)

Reparse-point files are excluded because their target content is outside this repository snapshot.
"@

$sourceManifestPath = Join-Path $OutputRoot "source_evidence_sha512_manifest.tsv"
$excludedFilesPath = Join-Path $OutputRoot "excluded_files.tsv"
$sourceManifest = [System.Collections.Generic.List[string]]::new()
$excludedFiles = [System.Collections.Generic.List[string]]::new()
$sourceManifest.Add("sha512`tbytes`trepository_relative_path")
$excludedFiles.Add("reason`trepository_relative_path")

$allFiles = Get-ChildItem -LiteralPath $RepositoryRoot -Force -File -Recurse
foreach ($file in $allFiles) {
    try {
        $relative = Get-RelativeRepositoryPath -Path $file.FullName
        $reason = Get-ExclusionReason -RelativePath $relative
        if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            $reason = "reparse-point-file"
        }

        if ($null -ne $reason) {
            $excludedFiles.Add(("{0}`t{1}" -f $reason, $relative))
            continue
        }

        $sourceManifest.Add((Get-Sha512Entry -File $file))
    }
    catch {
        throw "Source/evidence manifest failed for '$($file.FullName)': $($_.Exception.Message)"
    }
}
Write-Utf8Lines -Path $sourceManifestPath -Lines $sourceManifest.ToArray()
Write-Utf8Lines -Path $excludedFilesPath -Lines $excludedFiles.ToArray()

$untrackedManifestPath = Join-Path $OutputRoot "untracked_sha512_manifest.tsv"
$untrackedExcludedPath = Join-Path $OutputRoot "untracked_excluded_files.tsv"
$untrackedManifest = [System.Collections.Generic.List[string]]::new()
$untrackedExcluded = [System.Collections.Generic.List[string]]::new()
$untrackedManifest.Add("sha512`tbytes`trepository_relative_path")
$untrackedExcluded.Add("reason`trepository_relative_path")

$untrackedPaths = & git -c core.quotePath=false -C $RepositoryRoot ls-files --others --exclude-standard
if ($LASTEXITCODE -ne 0) {
    throw "Could not enumerate untracked files."
}
foreach ($untrackedPath in $untrackedPaths) {
    if ([string]::IsNullOrWhiteSpace($untrackedPath)) {
        continue
    }

    $normalisedRelativePath = $untrackedPath.Replace("\", "/")
    $reason = Get-ExclusionReason -RelativePath $normalisedRelativePath
    if ($null -ne $reason) {
        $untrackedExcluded.Add(("{0}`t{1}" -f $reason, $normalisedRelativePath))
        continue
    }

    try {
        $fullPath = Join-Path $RepositoryRoot $untrackedPath
        $file = Get-Item -LiteralPath $fullPath -Force
        if (-not ($file -is [System.IO.FileInfo])) {
            $untrackedExcluded.Add(("not-regular-file`t{0}" -f $normalisedRelativePath))
            continue
        }
        if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            $untrackedExcluded.Add(("reparse-point-file`t{0}" -f $normalisedRelativePath))
            continue
        }

        $untrackedManifest.Add((Get-Sha512Entry -File $file))
    }
    catch {
        throw "Untracked manifest failed for '$normalisedRelativePath': $($_.Exception.Message)"
    }
}
Write-Utf8Lines -Path $untrackedManifestPath -Lines $untrackedManifest.ToArray()
Write-Utf8Lines -Path $untrackedExcludedPath -Lines $untrackedExcluded.ToArray()

$toolVersionsPath = Join-Path $OutputRoot "tool_versions.txt"
$toolLines = [System.Collections.Generic.List[string]]::new()
$toolLines.Add("snapshot_generated_utc=$generatedAt")
$toolLines.Add("[PowerShell]")
$toolLines.Add("edition=$($PSVersionTable.PSEdition)")
$toolLines.Add("version=$($PSVersionTable.PSVersion)")
$toolLines.Add("platform=$($PSVersionTable.Platform)")
$toolLines.Add("runtime=$([System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription)")
$toolLines.Add("")
foreach ($tool in @(
    @{ Name = "Git"; Command = "git"; Arguments = @("--version") },
    @{ Name = "Python"; Command = "python"; Arguments = @("--version") },
    @{ Name = "Cargo"; Command = "cargo"; Arguments = @("--version") },
    @{ Name = "Rustc"; Command = "rustc"; Arguments = @("--version") },
    @{ Name = "Java"; Command = "java"; Arguments = @("-version") }
)) {
    foreach ($line in (Get-ToolVersionBlock -Name $tool.Name -Command $tool.Command -Arguments $tool.Arguments)) {
        $toolLines.Add($line)
    }
}
Write-Utf8Lines -Path $toolVersionsPath -Lines $toolLines.ToArray()

$readmePath = Join-Path $OutputRoot "README.md"
$readmeTemplate = @'
# SHA-512 Handover Snapshot

Generated at UTC: __GENERATED_UTC__

This folder is a reproducible handover record, not an archive and not a release attestation.
It contains the Git identity and status, a binary patch for every tracked worktree change
against HEAD, source/evidence SHA-512 hashes, a SHA-512 manifest of untracked files within
the stated scope, exclusions, and exact locally observed tool-version output.

## Verify

1. Open `repository_state.txt` and confirm the expected repository root, HEAD, branch, and status.
2. Review `exclusions.txt` and `excluded_files.tsv`; excluded material is not represented by a content hash.
3. On a matching worktree, recompute a file hash with PowerShell:
   `Get-FileHash -Algorithm SHA512 -LiteralPath <file>`
   and compare its lowercase hexadecimal value and byte count with
   `source_evidence_sha512_manifest.tsv` or `untracked_sha512_manifest.tsv`.
4. To inspect tracked changes represented at snapshot time, run:
   `git apply --check tracked_worktree.patch`
   from a worktree whose HEAD matches `repository_state.txt`.
   Do not apply the patch to an evidence worktree unless intentionally creating a review copy.
5. Verify the generated snapshot records themselves against
   `snapshot_artifacts_sha512_manifest.tsv`. That manifest deliberately does not contain
   a hash of itself, avoiding self-reference.

The output folder itself is excluded from the source and untracked manifests so the snapshot
does not alter its own input set while it is built.
'@
Write-Utf8Text -Path $readmePath -Text $readmeTemplate.Replace("__GENERATED_UTC__", $generatedAt)

$artifactManifestPath = Join-Path $OutputRoot "snapshot_artifacts_sha512_manifest.tsv"
$artifactManifest = [System.Collections.Generic.List[string]]::new()
$artifactManifest.Add("sha512`tbytes`tsnapshot_relative_path")
foreach ($artifact in (Get-ChildItem -LiteralPath $OutputRoot -File -Recurse | Sort-Object FullName)) {
    if ($artifact.Name -eq "snapshot_artifacts_sha512_manifest.tsv") {
        continue
    }
    $hash = (Get-FileHash -Algorithm SHA512 -LiteralPath $artifact.FullName).Hash.ToLowerInvariant()
    $artifactRelativePath = $artifact.FullName.Substring($OutputRoot.Length).TrimStart([char[]]@('\', '/')).Replace("\", "/")
    $artifactManifest.Add(("{0}`t{1}`t{2}" -f $hash, $artifact.Length, $artifactRelativePath))
}
Write-Utf8Lines -Path $artifactManifestPath -Lines $artifactManifest.ToArray()

$sourceFileCount = $sourceManifest.Count - 1
$untrackedFileCount = $untrackedManifest.Count - 1
$excludedFileCount = $excludedFiles.Count - 1
$untrackedExcludedCount = $untrackedExcluded.Count - 1
$patchHash = (Get-FileHash -Algorithm SHA512 -LiteralPath $patchPath).Hash.ToLowerInvariant()
$artifactManifestHash = (Get-FileHash -Algorithm SHA512 -LiteralPath $artifactManifestPath).Hash.ToLowerInvariant()

Write-Output "Handover snapshot created: $OutputRoot"
Write-Output "HEAD: $head"
Write-Output "Source/evidence files hashed: $sourceFileCount"
Write-Output "Untracked files hashed: $untrackedFileCount"
Write-Output "Excluded files listed: $excludedFileCount"
Write-Output "Excluded untracked files listed: $untrackedExcludedCount"
Write-Output "tracked_worktree.patch SHA-512: $patchHash"
Write-Output "snapshot_artifacts_sha512_manifest.tsv SHA-512: $artifactManifestHash"

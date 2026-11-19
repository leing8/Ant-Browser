# build-mac.ps1 在 Windows 宿主机上一键交叉编译纯 Go 无 CGO 的 macOS（arm64 / amd64）
# 与 Windows（amd64）版 ant-session-migrator，校验 Mach-O 64-bit 二进制头并打包保留 POSIX 0755 权限的 ZIP。
param(
    [string]$OutputDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$toolDir = $PSScriptRoot
$repoRoot = (Resolve-Path (Join-Path $toolDir "..\..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $repoRoot "publish\output"
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# 读取工具版本号
$exportGo = Get-Content -LiteralPath (Join-Path $toolDir "export.go") -Raw
$version = "1.2.0"
if ($exportGo -match 'toolVersion\s*=\s*"([^"]+)"') {
    $version = $Matches[1]
}

Add-Type -AssemblyName System.IO.Compression

function New-PosixExecutableZip {
    param(
        [string]$ZipPath,
        [string]$RootFolder,
        [string]$BinaryPath,
        [string]$BinaryName,
        [string]$ReadmePath
    )
    if (Test-Path -LiteralPath $ZipPath) {
        Remove-Item -LiteralPath $ZipPath -Force
    }

    $commandScript = @'
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
xattr -dr com.apple.quarantine ./ant-session-migrator >/dev/null 2>&1 || true
chmod +x ./ant-session-migrator
./ant-session-migrator "$@"
'@ -replace "`r`n", "`n"

    $fs = [System.IO.File]::Open($ZipPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            # 1. 可执行二进制（设置 Unix 0755 权限位: 0100755 << 16）
            $binEntry = $zip.CreateEntry("$RootFolder/$BinaryName", [System.IO.Compression.CompressionLevel]::Optimal)
            $binEntry.ExternalAttributes = ([int]0x81ED) -shl 16
            $inStream = [System.IO.File]::OpenRead($BinaryPath)
            $outStream = $binEntry.Open()
            try { $inStream.CopyTo($outStream) } finally { $outStream.Dispose(); $inStream.Dispose() }

            # 2. 双击启动脚本 run-migrator.command（0755）
            $cmdEntry = $zip.CreateEntry("$RootFolder/run-migrator.command", [System.IO.Compression.CompressionLevel]::Optimal)
            $cmdEntry.ExternalAttributes = ([int]0x81ED) -shl 16
            $cmdBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($commandScript)
            $cmdStream = $cmdEntry.Open()
            try { $cmdStream.Write($cmdBytes, 0, $cmdBytes.Length) } finally { $cmdStream.Dispose() }

            # 3. README.md（0644）
            if (Test-Path -LiteralPath $ReadmePath -PathType Leaf) {
                $docEntry = $zip.CreateEntry("$RootFolder/README.md", [System.IO.Compression.CompressionLevel]::Optimal)
                $docEntry.ExternalAttributes = ([int]0x81A4) -shl 16
                $docIn = [System.IO.File]::OpenRead($ReadmePath)
                $docOut = $docEntry.Open()
                try { $docIn.CopyTo($docOut) } finally { $docOut.Dispose(); $docIn.Dispose() }
            }
        }
        finally { $zip.Dispose() }
    }
    finally { $fs.Dispose() }
}

Push-Location $toolDir
try {
    Write-Host "[1/4] Checking Go module & cross-compile vet..."
    go mod tidy
    if ($LASTEXITCODE -ne 0) { throw "go mod tidy failed" }

    foreach ($arch in @("arm64", "amd64")) {
        $env:GOOS = "darwin"
        $env:GOARCH = $arch
        $env:CGO_ENABLED = "0"
        go vet ./...
        if ($LASTEXITCODE -ne 0) { throw "go vet darwin/$arch failed" }
    }

    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ant-migrator-mac-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    try {
        foreach ($arch in @("arm64", "amd64")) {
            Write-Host "[build] Cross-compiling ant-session-migrator for darwin/$arch (CGO_ENABLED=0)..."
            $binOut = Join-Path $tmpDir "ant-session-migrator-$arch"
            $env:GOOS = "darwin"
            $env:GOARCH = $arch
            $env:CGO_ENABLED = "0"
            go build -trimpath -ldflags="-s -w" -o $binOut .
            if ($LASTEXITCODE -ne 0) { throw "go build darwin/$arch failed" }

            # 校验 Mach-O 64-bit 魔数 (0xCFFAEDFE little-endian)
            $hdr = New-Object byte[] 4
            $s = [System.IO.File]::OpenRead($binOut)
            try { [void]$s.Read($hdr, 0, 4) } finally { $s.Dispose() }
            if (-not ($hdr[0] -eq 0xCF -and $hdr[1] -eq 0xFA -and $hdr[2] -eq 0xED -and $hdr[3] -eq 0xFE)) {
                throw "Invalid Mach-O 64-bit header for darwin/$arch"
            }

            $rootFolder = "ant-session-migrator-$version-macos-$arch"
            $zipPath = Join-Path $OutputDir "$rootFolder.zip"
            New-PosixExecutableZip `
                -ZipPath $zipPath `
                -RootFolder $rootFolder `
                -BinaryPath $binOut `
                -BinaryName "ant-session-migrator" `
                -ReadmePath (Join-Path $toolDir "README.md")

            $szMB = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
            Write-Host "  [OK] $zipPath ($szMB MB, Mach-O 64-bit verified)"
        }
    }
    finally {
        Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item Env:GOOS -ErrorAction SilentlyContinue
        Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
        Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
    }

    Write-Host "[build] Rebuilding Windows ant-session-migrator.exe..."
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"
    go build -trimpath -ldflags="-s -w" -o (Join-Path $toolDir "ant-session-migrator.exe") .
    if ($LASTEXITCODE -ne 0) { throw "go build windows/amd64 failed" }
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
    Write-Host "  [OK] $(Join-Path $toolDir 'ant-session-migrator.exe')"
}
finally {
    Pop-Location
}

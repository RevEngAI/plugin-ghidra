# Installs the RevEng.AI Ghidra plugin and enables it in the CodeBrowser tool.
#
#   irm https://raw.githubusercontent.com/RevEngAI/plugin-ghidra/main/install.ps1 | iex
#
# $env:GHIDRA_INSTALL_DIR     target this Ghidra install instead of detecting one
# $env:REVENG_PLUGIN_VERSION  release tag to install (default: latest)

& {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem

$Repo = 'RevEngAI/plugin-ghidra'
$ExtName = 'plugin-ghidra'
$PluginPackage = 'RevEng.AI'
$SettingsRoot = Join-Path $env:APPDATA 'ghidra'

function Get-Prop($Ghidra, $Name) {
    $line = Get-Content (Join-Path $Ghidra 'Ghidra\application.properties') |
        Where-Object { $_ -like "$Name=*" } | Select-Object -First 1
    $line.Substring($Name.Length + 1).Trim()
}

function Test-Ghidra($Dir) {
    $Dir -and (Test-Path -LiteralPath (Join-Path $Dir 'Ghidra\application.properties'))
}

function Find-Installs {
    $candidates = @()
    $lastrun = Join-Path $SettingsRoot 'lastrun'
    if (Test-Path $lastrun) { $candidates += (Get-Content $lastrun -Raw).Trim() }
    $roots = @('C:\', $env:ProgramFiles, ${env:ProgramFiles(x86)}, 'C:\tools', $HOME,
        "$HOME\Downloads", "$HOME\Desktop", "$HOME\scoop\apps\ghidra",
        "$env:ProgramData\chocolatey\lib\ghidra\tools")
    foreach ($root in $roots | Where-Object { $_ -and (Test-Path $_) }) {
        foreach ($d in Get-ChildItem $root -Directory -ErrorAction SilentlyContinue) {
            if ($d.Name -like 'ghidra*' -or $root -like '*ghidra*') {
                $candidates += $d.FullName
                $candidates += Get-ChildItem $d.FullName -Directory -Filter 'ghidra*' -ErrorAction SilentlyContinue |
                    ForEach-Object { $_.FullName }
            }
        }
    }
    $candidates | Where-Object { Test-Ghidra $_ } |
        ForEach-Object { (Get-Item -LiteralPath $_).FullName.TrimEnd('\') } | Sort-Object -Unique
}

if ($env:GHIDRA_INSTALL_DIR) {
    if (-not (Test-Ghidra $env:GHIDRA_INSTALL_DIR)) { throw "No Ghidra install at $env:GHIDRA_INSTALL_DIR" }
    $ghidra = $env:GHIDRA_INSTALL_DIR
} else {
    $installs = @(Find-Installs)
    if ($installs.Count -eq 0) { throw 'No Ghidra install found; set $env:GHIDRA_INSTALL_DIR to its path' }
    if ($installs.Count -eq 1) {
        $ghidra = $installs[0]
    } else {
        Write-Host 'Ghidra installs found:'
        for ($i = 0; $i -lt $installs.Count; $i++) {
            Write-Host ("  {0}) {1}  {2}" -f ($i + 1), (Get-Prop $installs[$i] 'application.version'), $installs[$i])
        }
        $choice = Read-Host "Install into [1-$($installs.Count)]"
        if ($choice -notmatch '^\d+$' -or [int]$choice -lt 1 -or [int]$choice -gt $installs.Count) { throw 'Invalid choice' }
        $ghidra = $installs[[int]$choice - 1]
    }
}

$version = Get-Prop $ghidra 'application.version'
$settings = Join-Path $SettingsRoot "ghidra_${version}_$(Get-Prop $ghidra 'application.release.name')"
Write-Host "Ghidra $version at $ghidra"

$running = Get-CimInstance Win32_Process -Filter "Name LIKE 'java%'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match 'ghidra\.GhidraRun' }
if ($running) { throw 'Ghidra is running; close it and rerun' }

$tmp = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid())
New-Item -ItemType Directory $tmp | Out-Null
try {
    $asset = "ghidra_${version}_$ExtName.zip"
    if ($env:REVENG_PLUGIN_VERSION) {
        $url = "https://github.com/$Repo/releases/download/$env:REVENG_PLUGIN_VERSION/$asset"
    } else {
        $url = "https://github.com/$Repo/releases/latest/download/$asset"
    }
    $zip = Join-Path $tmp $asset
    $unpacked = Join-Path $tmp 'x'
    Write-Host "Downloading $url"
    try {
        Invoke-WebRequest $url -OutFile $zip -UseBasicParsing
    } catch {
        throw "No release build for Ghidra $version; see https://github.com/$Repo#building-your-own-plugin-for-custom-ghidra-forks-and-versions"
    }

    [IO.Compression.ZipFile]::ExtractToDirectory($zip, $unpacked)
    if (-not (Test-Path (Join-Path (Join-Path $unpacked $ExtName) 'extension.properties'))) { throw 'Unexpected archive layout' }
    $extensions = Join-Path $settings 'Extensions'
    New-Item -ItemType Directory -Force $extensions | Out-Null
    $target = Join-Path $extensions $ExtName
    if (Test-Path $target) { Remove-Item -Recurse -Force $target }
    Move-Item (Join-Path $unpacked $ExtName) $extensions
    Write-Host "Installed to $target"

    $tool = Join-Path (Join-Path $settings 'tools') '_code_browser.tcd'
    if (-not (Test-Path $tool)) {
        Write-Host 'CodeBrowser not configured yet; Ghidra will offer to enable the plugins when it opens.'
        return
    }

    $jar = [IO.Compression.ZipFile]::OpenRead((Join-Path (Join-Path $target 'lib') "$ExtName.jar"))
    try {
        $plugins = $jar.Entries | ForEach-Object { $_.FullName } |
            Where-Object { $_ -match '^ai/reveng/toolkit/ghidra/plugins/[^/$]*Plugin\.class$' } |
            ForEach-Object { ($_ -replace '\.class$', '') -replace '/', '.' }
    } finally { $jar.Dispose() }
    if (-not $plugins) { throw "No plugins found in $ExtName.jar" }

    Copy-Item $tool "$tool.bak" -Force
    [xml]$xml = Get-Content $tool -Raw
    $toolNode = $xml.TOOL_CONFIG.SelectSingleNode('TOOL')
    foreach ($old in @($toolNode.SelectNodes("PACKAGE[@NAME='$PluginPackage']"))) { [void]$toolNode.RemoveChild($old) }
    $package = $xml.CreateElement('PACKAGE')
    $package.SetAttribute('NAME', $PluginPackage)
    foreach ($plugin in $plugins) {
        $include = $xml.CreateElement('INCLUDE')
        $include.SetAttribute('CLASS', $plugin)
        [void]$package.AppendChild($include)
    }
    [void]$toolNode.AppendChild($package)
    $xml.Save($tool)
    Write-Host "Enabled in CodeBrowser (backup: $tool.bak)"
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
}

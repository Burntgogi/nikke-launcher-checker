#requires -Version 5.1
# 제작자 Serio_ai
[CmdletBinding()]
param(
    [string]$InstallPath,
    [string]$LogDirectory,
    [switch]$OfferRemediation,
    [string]$RestoreBackup
)

$ErrorActionPreference = 'Stop'
if (!$LogDirectory) { $LogDirectory = Join-Path $PSScriptRoot 'logs' }
$lines = [System.Collections.Generic.List[string]]::new()
$hits = [ordered]@{ Exposure = 0; Request = 0; Download = 0; Execution = 0; Persistence = 0; Review = 0 }
$scan = @{ Issues = 0; DebugLogs = 0; CacheFiles = 0; PayloadFiles = 0 }
$affectedCaches = [System.Collections.Generic.List[string]]::new()
$payloadCandidates = [ordered]@{}
$registeredDlls = [System.Collections.Generic.List[object]]::new()
$chromeClsidPath = 'Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}'
$chromeValuePath = "$chromeClsidPath\InprocServer32"
$loaderUrl = '(?i)https?://(?:analytics\.)?insightjs\.(?:com|org)(?=[:/\s"''\x00]|$)'
$payloadUrl = '(?i)(?:https?://)?analytics\.insightjs\.com/comm/assets/insight\.bundle\b'
$loaderCacheNames = 'dd65fa4d61079e7e_0', 'ce2fd3f1007a9fe9_0', '1416c638b3830103_0', 'fd520c7c0f65c2d7_0'
$loaderHashes = @{
    5808 = '2f2aac505f486067af6831d6c75ea74df63acb1ed4e4002709c5962c68bd9203'
    135273 = '3aaafbd612f04501a6fdb0bb8b2f8a87796223e5584ac18ea5eb180feeafb193'
    4358 = '21d2fa4b6cdd15da3d5246687a01ef84fb848668144258b110606db5eb5ea7ce'
}
$payloadHashes = @{
    205135 = 'cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec'
    165108 = '60fd53ab7356384ba2161b9bc84420cd170905011a2f3ca09f3e38fe3122f3a1'
}

function Write-Report([string]$Message, [switch]$Show) {
    if ($env:USERPROFILE) { $Message = $Message.Replace($env:USERPROFILE, '%USERPROFILE%') }
    $lines.Add($Message)
    if ($Show) { Write-Host $Message }
}

function Add-Finding([string]$Stage, [string]$Evidence, [string]$Location) {
    $hits[$Stage]++
    Write-Report ('[{0}] {1} | {2}' -f $Stage, $Evidence, $Location)
}

function Add-Gap([string]$Path, [string]$Reason) {
    $scan.Issues++
    Write-Report ('[확인하지 못한 항목] {0} | {1}' -f $Path, $Reason)
}

function Get-ScanItem([string]$Path) {
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            Add-Gap $Path '링크 또는 접합점 건너뜀'
            return
        }
        $item
    } catch [System.Management.Automation.ItemNotFoundException] {
        return
    } catch [System.Management.Automation.DriveNotFoundException] {
        return
    } catch {
        Add-Gap $Path $_.CategoryInfo.Category.ToString()
    }
}

function Get-ScanFiles([string]$Path, [int]$Depth) {
    $folder = Get-ScanItem $Path
    if (!$folder -or !$folder.PSIsContainer) { return }
    try {
        $children = Get-ChildItem -LiteralPath $folder.FullName -Force -ErrorAction Stop
    } catch {
        Add-Gap $Path $_.CategoryInfo.Category.ToString()
        return
    }
    foreach ($child in $children) {
        if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            Add-Gap $child.FullName '링크 또는 접합점 건너뜀'
        } elseif (!$child.PSIsContainer) {
            $child
        } elseif ($Depth -gt 0) {
            Get-ScanFiles $child.FullName ($Depth - 1)
        } else {
            Add-Gap $child.FullName '탐색 깊이 제한'
        }
    }
}

function Read-Artifact([IO.FileInfo]$File) {
    try {
        $sharing = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
        $stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, $sharing)
        try {
            if ($stream.Length -gt 32MB) {
                Add-Gap $File.FullName '32 MiB를 초과해 내용 검사 생략'
                return
            }
            $reader = [IO.BinaryReader]::new($stream)
            try { return ,($reader.ReadBytes([int]$stream.Length)) } finally { $reader.Dispose() }
        } finally { $stream.Dispose() }
    } catch {
        Add-Gap $File.FullName $_.Exception.GetType().Name
    }
}

function Get-ArtifactText([byte[]]$Bytes) {
    if ($Bytes.Length -ge 2) {
        if ($Bytes[0] -eq 255 -and $Bytes[1] -eq 254) { return [Text.Encoding]::Unicode.GetString($Bytes) }
        if ($Bytes[0] -eq 254 -and $Bytes[1] -eq 255) { return [Text.Encoding]::BigEndianUnicode.GetString($Bytes) }
    }
    [Text.Encoding]::ASCII.GetString($Bytes)
}

function Get-BytesHash([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
}

function Test-CacheFile([IO.FileInfo]$File, [string]$Kind) {
    $bytes = Read-Artifact $File
    if ($null -eq $bytes) { return }
    $scan.CacheFiles++
    $path = $File.FullName
    $content = Get-ArtifactText $bytes
    if ($Kind -eq 'LevelDB') {
        if ($content -match 'k2f\.agent\.state') { Add-Finding Execution '런처 캐시에 실행 기록(k2f.agent.state)이 있습니다.' $path }
        return
    }
    if ($content -match $loaderUrl -or $content -match '(?i)(?<![\w.-])(?:analytics\.)?insightjs\.(?:com|org)(?![\w.-])') {
        Add-Finding Exposure '런처 캐시에 사건과 관련된 인터넷 주소가 있습니다.' $path
    } elseif ($Kind -eq 'Code' -and $File.Name -in $loaderCacheNames) {
        Add-Finding Review '캐시 파일 이름이 일치합니다. 관련 주소는 찾지 못했습니다.' $path
    }
    if ($content -match $payloadUrl) { Add-Finding Request '캐시에 다운로드 주소가 있습니다.' $path }
    if ($loaderHashes.ContainsKey($bytes.Length) -and (Get-BytesHash $bytes) -eq $loaderHashes[$bytes.Length]) {
        Add-Finding Exposure '변조된 스크립트와 파일 지문(SHA-256)이 일치합니다.' $path
    }
    if ($payloadHashes.ContainsKey($bytes.Length) -and (Get-BytesHash $bytes) -eq $payloadHashes[$bytes.Length]) {
        Add-Finding Download '알려진 악성코드와 파일 지문(SHA-256)이 일치합니다.' $path
    }
}

function Test-LauncherFile([IO.FileInfo]$File, [string]$Kind) {
    $bytes = Read-Artifact $File
    if ($null -eq $bytes) { return }
    $path = $File.FullName
    if ($Kind -eq 'Debug') { $scan.DebugLogs++ } else { $scan.PayloadFiles++ }

    if ($payloadHashes.ContainsKey($bytes.Length) -and (Get-BytesHash $bytes) -eq $payloadHashes[$bytes.Length]) {
        Add-Finding Download '알려진 악성코드와 파일 지문(SHA-256)이 일치합니다.' $path
        if ($OfferRemediation -and $Kind -eq 'Tinyget') { $payloadCandidates[$path] = $payloadHashes[$bytes.Length] }
        return
    }
    if ($Kind -eq 'Tinyget' -and $bytes.Length -ge 3 -and $bytes[0] -eq 27 -and $bytes[1] -eq 76 -and $bytes[2] -eq 74) {
        Add-Finding Download '다운로드 폴더(tinyget)에 악성코드와 같은 형식의 파일이 있습니다.' $path
        return
    }
    $content = Get-ArtifactText $bytes
    if ($Kind -eq 'Debug') {
        $count = [regex]::Matches($content, '(?i)\bk2f_chan\s+registered\b|\bagent started as\s+\S+').Count
        if ($count) { Add-Finding Execution "런처 로그(debug.log)에 실행 흔적이 $($count)건 있습니다." $path }
        if ($content -match '(?i)\bk2f_chan\s+registered\b') { $scan.ConfirmedExecution = $true }
    }
    if ($content -match $payloadUrl) { Add-Finding Request '런처 로그에 다운로드 주소가 있습니다.' $path }
    if ($content -match '(?i)\blua downloaded to\s+log[\\/]tinyget[\\/]') {
        Add-Finding Download '런처 로그에 Lua 파일을 저장한 기록이 있습니다.' $path
    }
}

function Get-LauncherDirectories {
    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($InstallPath -match '^[\\/]{2}') {
        Add-Gap $InstallPath '로컬 드라이브의 설치 폴더를 지정하세요.'
    } elseif ($InstallPath) {
        $requested = Get-ScanItem $InstallPath
        if ($requested -and $requested.PSIsContainer) { $candidates.Add($requested.FullName) }
        else { Add-Gap $InstallPath '지정한 설치 폴더를 열 수 없음' }
    }
    foreach ($process in Get-Process -Name '*nikke*' -ErrorAction SilentlyContinue) {
        if ($process.Path -and $process.Name -match '^(?:nikke_launcher.*|nikke)$') {
            $candidates.Add((Split-Path -LiteralPath $process.Path))
        }
    }
    $uninstall = 'Software\Microsoft\Windows\CurrentVersion\Uninstall'
    foreach ($hive in [Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryHive]::LocalMachine) {
        foreach ($view in $registryViews) {
            $baseKey = $uninstallKey = $null
            $label = "$hive\$uninstall [$view]"
            $denied = 0
            try {
                $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
                $uninstallKey = $baseKey.OpenSubKey($uninstall, $false)
                if (!$uninstallKey) { continue }
                foreach ($name in $uninstallKey.GetSubKeyNames()) {
                    $entry = $null
                    try {
                        $entry = $uninstallKey.OpenSubKey($name, $false)
                        if ($entry -and $entry.GetValue('DisplayName') -match 'NIKKE|니케') {
                            $location = [string]$entry.GetValue('InstallLocation')
                            if ($location) { $candidates.Add($location.Trim('"')) }
                        }
                    } catch { $denied++ }
                    finally { if ($entry) { $entry.Dispose() } }
                }
                if ($denied) { Add-Gap $label "설치 정보 $denied 건 조회 실패" }
            } catch { Add-Gap $label $_.Exception.GetType().Name }
            finally {
                if ($uninstallKey) { $uninstallKey.Dispose() }
                if ($baseKey) { $baseKey.Dispose() }
            }
        }
    }
    $commonRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, (Join-Path $env:USERPROFILE 'Games'))
    $commonRoots += $localPaths | ForEach-Object { Join-Path $_ 'Programs' }
    $commonRoots += [IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady -and $_.DriveType -eq 'Fixed' } | ForEach-Object {
        $_.RootDirectory.FullName
        Join-Path $_.RootDirectory.FullName 'Games'
    }
    foreach ($root in $commonRoots | Where-Object { $_ } | Select-Object -Unique) {
        if (!(Get-ScanItem $root)) { continue }
        try {
            foreach ($folder in Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop) {
                if ($folder.Name -match 'nikke|니케|level.?infinite|hotcool|proximabeta') { $candidates.Add($folder.FullName) }
            }
        } catch {
            Add-Gap $root $_.CategoryInfo.Category.ToString()
        }
    }
    foreach ($candidate in $candidates | Select-Object -Unique) {
        if ($candidate -notmatch '^[A-Za-z]:[\\/]') { Add-Gap $candidate '로컬 드라이브 경로만 조회'; continue }
        $folder = Get-ScanItem $candidate
        if (!$folder -or !$folder.PSIsContainer) { continue }
        $folder.FullName
        if ($folder.Parent) { $folder.Parent.FullName }
        try {
            Get-ChildItem -LiteralPath $folder.FullName -Directory -Force -ErrorAction Stop |
                Where-Object Name -Match 'nikke|니케|launcher' | Select-Object -ExpandProperty FullName
        } catch { Add-Gap $candidate $_.CategoryInfo.Category.ToString() }
    }
}

function Test-ChromePersistence {
    foreach ($view in $registryViews) {
        $label = "HKCU\$chromeClsidPath [$view]"
        $baseKey = $key = $server = $null
        try {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, $view)
            $key = $baseKey.OpenSubKey($chromeClsidPath, $false)
            if (!$key) { Write-Report "[미발견] $label"; continue }
            $server = $key.OpenSubKey('InprocServer32', $false)
            $target = if ($server) { [string]$server.GetValue('', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
            if ($target -match '(?i)[\\/]platform_experience_helper\.dll"?\s*$') {
                Add-Finding Persistence 'Chrome에서 의심 파일을 불러오도록 등록돼 있습니다.' $label
                if ($OfferRemediation) {
                    $kind = $server.GetValueKind('')
                    $dllPath = [Environment]::ExpandEnvironmentVariables($target.Trim('"'))
                    if ($kind -in 'String','ExpandString' -and (Test-ActionChromePath $dllPath)) {
                        $registeredDlls.Add(@{ Kind = 'Registry'; Path = "HKCU\$chromeValuePath"; Dll = $dllPath; Value = $target; ValueKind = [string]$kind; View = [string]$view })
                    }
                }
            } else {
                Add-Finding Review '관련 레지스트리 항목이 있습니다. 의심 파일과의 연결은 확인되지 않았습니다.' $label
            }
        } catch { Add-Gap $label $_.Exception.GetType().Name }
        finally {
            foreach ($handle in $server, $key, $baseKey) { if ($handle) { $handle.Dispose() } }
        }
    }
    foreach ($local in $localPaths) {
        $userHelper = Join-Path $local 'Google\Chrome\User Data\PlatformExperienceHelper'
        Write-Report "[범위] $userHelper"
        foreach ($file in Get-ScanFiles $userHelper 2) {
            if ($file.Name -eq 'platform_experience_helper.dll' -and $file.Directory.Name -match '^[0-9a-f]{64}$') {
                Add-Finding Persistence 'Chrome 사용자 폴더에 의심 파일이 있습니다. Chrome이 이 파일을 불러왔는지는 확인되지 않았습니다.' $file.FullName
            } elseif ($file.Name -in 'platform_experience_helper.dll', 'service_util.dll') {
                Add-Finding Review 'Chrome 사용자 폴더에 확인이 필요한 DLL 파일이 있습니다.' $file.FullName
            }
        }
    }
    $appRoots = @($localPaths; $env:ProgramFiles; ${env:ProgramFiles(x86)}) | Where-Object { $_ } | ForEach-Object { Join-Path $_ 'Google\Chrome\Application' }
    foreach ($root in $appRoots | Select-Object -Unique) {
        $locations = @((Join-Path $root 'PlatformExperienceHelper'))
        if (Get-ScanItem $root) {
            try {
                $locations += Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop | Where-Object Name -Match '^\d+(\.\d+){2,3}$' |
                    ForEach-Object { Join-Path $_.FullName 'PlatformExperienceHelper' }
            } catch { Add-Gap $root $_.CategoryInfo.Category.ToString() }
        }
        foreach ($location in $locations) {
            Write-Report "[범위] $location"
            foreach ($file in Get-ScanFiles $location 2) {
                if ($file.Name -in 'platform_experience_helper.dll', 'service_util.dll') {
                    Add-Finding Review 'Chrome 설치 폴더에 확인이 필요한 DLL 파일이 있습니다.' $file.FullName
                }
            }
        }
    }
}


function Test-ActionChromePath([string]$Path) {
    $prefix = (Join-Path $responseLocal 'Google\Chrome\User Data\PlatformExperienceHelper') + '\'
    $Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -and
        $Path.Substring($prefix.Length) -match '^[0-9a-f]{64}\\platform_experience_helper\.dll$'
}

function Assert-LocalActionPath([string]$Path) {
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path.Substring(2) -match '[<>:"|?*/\x00-\x1f]|[. ](?:\\|$)' -or
        [IO.Path]::GetFullPath($Path) -cne $Path -or [IO.DriveInfo]::new($Path.Substring(0, 3)).DriveType -ne 'Fixed') {
        throw '로컬 고정 드라이브의 정확한 경로를 확인할 수 없습니다.'
    }
    for ($part = $Path; $part; $part = [IO.Path]::GetDirectoryName($part)) {
        try { $entry = Get-Item -LiteralPath $part -Force -ErrorAction Stop }
        catch [System.Management.Automation.ItemNotFoundException] { continue }
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw '경로에 링크 또는 접합점이 있습니다.'
        }
    }
}

function Initialize-ResponseTools {
    if ($PSVersionTable.PSEdition -eq 'Desktop') { Add-Type -AssemblyName System.Security }
    if ('NikkeCheckedFile' -as [type]) { return }

    # Verify and remove through one handle so a replaced path cannot select a different file.
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class NikkeCheckedFile {
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint OpenExisting = 3;
    private const uint CreateNew = 1;

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInfo {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint size, uint flags);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo info);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int kind, ref byte info, uint size);

    private static void CheckHandle(SafeFileHandle handle, string path) {
        FileInfo info;
        if (!GetFileInformationByHandle(handle, out info)) throw new Win32Exception();
        if ((info.Attributes & 0x410) != 0 || info.Links != 1)
            throw new IOException("The target is a directory, reparse point, or hard-linked file.");
        var final = new StringBuilder(32768);
        uint length = GetFinalPathNameByHandleW(handle, final, (uint)final.Capacity, 0);
        if (length == 0) throw new Win32Exception();
        if (length >= final.Capacity || !String.Equals(final.ToString(), @"\\?\" + path, StringComparison.OrdinalIgnoreCase))
            throw new IOException("The opened file does not have the approved path.");
    }

    public static FileStream OpenForQuarantine(string path) {
        var handle = CreateFileW(path, GenericRead | DeleteAccess, 0, IntPtr.Zero, OpenExisting, OpenReparsePoint, IntPtr.Zero);
        try {
            if (handle.IsInvalid) throw new Win32Exception();
            CheckHandle(handle, path);
            return new FileStream(handle, FileAccess.Read);
        } catch { handle.Dispose(); throw; }
    }

    private static void MarkForRemoval(SafeFileHandle handle) {
        byte remove = 1;
        if (!SetFileInformationByHandle(handle, 4, ref remove, 1)) throw new Win32Exception();
    }

    public static void Quarantine(FileStream file) { MarkForRemoval(file.SafeFileHandle); }

    public static void Restore(string path, byte[] bytes) {
        using (var handle = CreateFileW(path, GenericRead | GenericWrite | DeleteAccess, 0, IntPtr.Zero, CreateNew, OpenReparsePoint, IntPtr.Zero)) {
            if (handle.IsInvalid) throw new Win32Exception();
            try { CheckHandle(handle, path); }
            catch { MarkForRemoval(handle); throw; }
            using (var stream = new FileStream(handle, FileAccess.Write)) {
                try {
                    stream.Write(bytes, 0, bytes.Length);
                    stream.Flush(true);
                } catch { MarkForRemoval(handle); throw; }
            }
        }
    }
}
'@
}

function Save-ActionBackup([System.Collections.IDictionary]$Record, [string]$Path) {
    Assert-LocalActionPath $Path
    $null = [IO.Directory]::CreateDirectory($backupRoot)
    Assert-LocalActionPath $Path
    $Record['Version'] = 1
    $bytes = [Text.Encoding]::UTF8.GetBytes(($Record | ConvertTo-Json -Compress))
    $encrypted = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, 'CurrentUser')
    $stream = [IO.File]::Open($Path, 'CreateNew', 'Write', 'None')
    try {
        $stream.Write($encrypted, 0, $encrypted.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    if ((Get-FileHash -LiteralPath $Path).Hash -ne (Get-BytesHash $encrypted)) {
        throw '암호화 백업을 확인할 수 없습니다.'
    }
}

function Get-RemediationItems {
    $verifiedDlls = [ordered]@{}
    foreach ($entry in $registeredDlls) {
        if ($verifiedDlls.Contains($entry.Dll)) { continue }
        $file = Get-ScanItem $entry.Dll
        if (!$file -or $file.PSIsContainer) { continue }
        $bytes = Read-Artifact $file
        if ($bytes.Length -ge 2 -and $bytes.Length -le 1MB -and $bytes[0] -eq 77 -and $bytes[1] -eq 90) {
            $hash = Get-BytesHash $bytes
            if ($hash -eq $file.Directory.Name) { $verifiedDlls[$entry.Dll] = $hash }
        }
    }

    foreach ($entry in $registeredDlls) {
        if ($scan.ConfirmedExecution -or $verifiedDlls.Contains($entry.Dll)) { $entry }
    }
    foreach ($path in $verifiedDlls.Keys) {
        @{ Kind = 'File'; Path = $path; Hash = $verifiedDlls[$path]; Evidence = 'Chrome에 등록된 DLL입니다. 파일 지문이 상위 폴더 이름과 일치합니다.' }
    }
    if ($scan.ConfirmedExecution -or $verifiedDlls.Count) {
        foreach ($path in $payloadCandidates.Keys) {
            @{ Kind = 'File'; Path = $path; Hash = $payloadCandidates[$path]; Evidence = '공개된 악성코드와 파일 지문이 일치합니다.' }
        }
    }
}

function Invoke-RegistryAction([System.Collections.IDictionary]$Record, [string]$Backup, [switch]$Restore) {
    if ($Record.Path -cne "HKCU\$chromeValuePath" -or $Record.View -notin $registryViews -or
        $Record.ValueKind -notin 'String','ExpandString' -or
        [Environment]::ExpandEnvironmentVariables(([string]$Record.Value).Trim('"')) -cne $Record.Dll -or
        !(Test-ActionChromePath $Record.Dll)) {
        throw '확인된 레지스트리 대상과 일치하지 않습니다.'
    }
    Assert-LocalActionPath $Record.Dll
    $view = [Microsoft.Win32.RegistryView]$Record.View
    $kind = [Microsoft.Win32.RegistryValueKind]$Record.ValueKind
    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey('CurrentUser', $view)
    $key = $null
    try {
        $key = $baseKey.OpenSubKey($chromeValuePath, $true)
        if (!$key) { throw '레지스트리 키가 없거나 열 수 없습니다.' }
        $options = [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        if ($Restore) {
            if ('' -in $key.GetValueNames()) { throw '기본값이 이미 있어 복구를 건너뜁니다.' }
            $key.SetValue('', $Record.Value, $kind)
            if ($key.GetValue('', $null, $options) -cne $Record.Value -or $key.GetValueKind('') -ne $kind) {
                throw '기본값이 복구됐는지 확인할 수 없습니다.'
            }
        } else {
            if ($key.GetValue('', $null, $options) -cne $Record.Value -or $key.GetValueKind('') -ne $kind) {
                throw '점검한 뒤 레지스트리 값이 바뀌었습니다.'
            }
            Save-ActionBackup $Record $Backup
            if ($key.GetValue('', $null, $options) -cne $Record.Value -or $key.GetValueKind('') -ne $kind) {
                throw '백업하는 동안 레지스트리 값이 바뀌었습니다.'
            }
            $key.DeleteValue('', $true)
            if ('' -in $key.GetValueNames()) { throw '기본값이 제거됐는지 확인할 수 없습니다.' }
        }
    } finally {
        if ($key) { $key.Dispose() }
        $baseKey.Dispose()
    }
}

function Show-RecoveryCommand([string]$Path) {
    Write-Host '오탐으로 확인되면 이 PC의 같은 Windows 계정에서 점검 도구 폴더를 열고 아래 명령을 실행하세요.'
    Write-Host ('.\Run-Nikke-Check.bat -Restore "{0}"' -f $Path)
}

function Invoke-ConfirmedActions {
    $items = @(Get-RemediationItems)
    if (!$items.Count) {
        Write-Report '격리하거나 제거할 수 있을 만큼 근거가 확인된 항목이 없습니다.' -Show
        return
    }
    Write-Report '선택 조치. 각 항목에서 Enter를 누르면 건너뜁니다.' -Show
    Write-Report '인터넷 연결을 끊고 니케 런처와 Chrome을 닫은 뒤 진행하세요. 회사 PC라면 보안 담당자에게 먼저 연락하세요.' -Show
    foreach ($item in $items) {
        $backup = Join-Path $backupRoot ([Guid]::NewGuid().ToString('N') + '.nikke-backup')
        Write-Host ''
        if ($item.Kind -eq 'File') {
            Write-Host "파일 격리  $($item.Path)"
            Write-Host $item.Evidence
            Write-Host "SHA-256  $($item.Hash)"
            Write-Host '암호화 백업을 확인한 뒤 원래 위치의 파일을 제거합니다.'
        } else {
            Write-Host "기본값 제거  $($item.Path) [$($item.View)]"
            Write-Host "이 값이 가리키는 DLL  $($item.Dll)"
            Write-Host '현재 사용자의 (기본값) 한 개를 백업한 뒤 제거합니다.'
        }
        Write-Host "백업 파일  $backup"
        Show-RecoveryCommand $backup
        if ((Read-Host '이 항목을 처리하려면 Y를 입력하세요') -ine 'Y') {
            Write-Report "건너뜀  $($item.Path)" -Show
            continue
        }
        try {
            Initialize-ResponseTools
            if ($item.Kind -eq 'File') {
                Assert-LocalActionPath $item.Path
                $stream = [NikkeCheckedFile]::OpenForQuarantine($item.Path)
                try {
                    if ($stream.Length -gt 1MB) { throw '파일 크기가 확인 범위를 벗어났습니다.' }
                    $bytes = [byte[]]::new([int]$stream.Length)
                    for ($offset = 0; $offset -lt $bytes.Length; $offset += $read) {
                        $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
                        if (!$read) { throw '파일을 끝까지 읽을 수 없습니다.' }
                    }
                    if ((Get-BytesHash $bytes) -ne $item.Hash) { throw '점검한 뒤 파일 내용이 바뀌었습니다.' }
                    Save-ActionBackup @{ Kind = 'File'; Path = $item.Path; Hash = $item.Hash; Data = [Convert]::ToBase64String($bytes) } $backup
                    [NikkeCheckedFile]::Quarantine($stream)
                } finally { $stream.Dispose() }
                if (Test-Path -LiteralPath $item.Path) { throw '원래 위치에 파일이 남았거나 다시 생겼습니다.' }
            } else {
                Invoke-RegistryAction $item $backup
            }
            Write-Report "처리 완료  $($item.Path)" -Show
        } catch {
            Write-Report "미완료  $($item.Path) | $($_.Exception.GetBaseException().Message)" -Show
            $scan.Issues++
        } finally {
            if ([IO.File]::Exists($backup)) { Write-Report "백업  $backup" -Show }
        }
    }
}

function Restore-ActionBackup([string]$Path) {
    if ([IO.Path]::GetDirectoryName($Path) -ine $backupRoot -or [IO.Path]::GetFileName($Path) -notmatch '^[0-9a-f]{32}\.nikke-backup$') {
        throw '점검 도구가 안내한 백업 파일 경로를 입력하세요.'
    }
    Assert-LocalActionPath $Path
    $file = Get-Item -LiteralPath $Path -Force
    if ($file.PSIsContainer -or $file.Length -gt 2MB) { throw '읽을 수 있는 점검 도구 백업이 아닙니다.' }
    Initialize-ResponseTools
    $encrypted = [IO.File]::ReadAllBytes($Path)
    $plain = [Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, 'CurrentUser')
    $data = [Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json
    if ($data.Version -ne 1 -or $data.Kind -notin 'File','Registry') { throw '백업 형식을 확인할 수 없습니다.' }
    if ($data.Kind -eq 'File') {
        Assert-LocalActionPath $data.Path
        $bytes = [Convert]::FromBase64String($data.Data)
        $knownPayload = $payloadHashes.ContainsKey($bytes.Length) -and $payloadHashes[$bytes.Length] -eq $data.Hash -and
            $data.Path -match '\\log\\tinyget\\'
        $knownDll = (Test-ActionChromePath $data.Path) -and
            [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($data.Path)) -eq $data.Hash
        if ($bytes.Length -gt 1MB -or (Get-BytesHash $bytes) -ne $data.Hash -or !($knownPayload -or $knownDll)) {
            throw '백업의 파일 지문이나 원래 경로가 일치하지 않습니다.'
        }
        Write-Host "파일 복구  $($data.Path)"
    } else {
        Write-Host "기본값 복구  $($data.Path) [$($data.View)]"
        Write-Host "이 값이 가리키는 DLL  $($data.Dll)"
    }
    Write-Host '오탐으로 확인된 경우에만 복구하세요. 원래 위치에 파일이나 값이 있으면 덮어쓰지 않습니다.'
    if ((Read-Host '이 항목을 복구하려면 RESTORE를 입력하세요') -cne 'RESTORE') {
        Write-Host '복구를 취소했습니다.'
        return
    }
    if ($data.Kind -eq 'File') {
        Assert-LocalActionPath $data.Path
        [NikkeCheckedFile]::Restore($data.Path, $bytes)
    } else {
        $record = @{}
        foreach ($property in $data.PSObject.Properties) { $record[$property.Name] = $property.Value }
        Invoke-RegistryAction $record -Restore
    }
    Write-Host '복구했습니다.'
}

if ($env:OS -ne 'Windows_NT') { throw 'Windows에서 실행하세요.' }
$responseLocal = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
$localPaths = @($responseLocal,
    (Join-Path $env:USERPROFILE 'AppData\Local')) | Where-Object { $_ } | Select-Object -Unique
$roamingPath = [Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData)
$registryViews = @([Microsoft.Win32.RegistryView]::Registry32)
if ([Environment]::Is64BitOperatingSystem) { $registryViews += [Microsoft.Win32.RegistryView]::Registry64 }
$backupRoot = Join-Path $responseLocal 'NikkeLauncherChecker\Backups'
if ($RestoreBackup) {
    try { Restore-ActionBackup $RestoreBackup }
    catch {
        Write-Host "복구 미완료  $($_.Exception.GetBaseException().Message)"
        exit 2
    }
    exit 0
}
Write-Report '니케 PC 런처 감염 점검' -Show
Write-Report '제작자 Serio_ai' -Show
Write-Report ('점검 시각 {0:yyyy-MM-dd HH:mm:ss zzz}' -f [DateTimeOffset]::Now)
Write-Report '현재 Windows 계정의 기록을 확인하고 점검 로그만 저장합니다.' -Show
$headerLineCount = $lines.Count

try {
    Write-Report "`n=== 런처 로그 ==="
    $checked = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($root in Get-LauncherDirectories) {
        foreach ($launcher in $root, (Join-Path $root 'Launcher')) {
            if (!$checked.Add($launcher)) { continue }
            $debug = Get-ScanItem (Join-Path $launcher 'intl_service\debug.log')
            if ($debug -and !$debug.PSIsContainer) {
                Write-Report "[로그] $($debug.FullName) | 수정 $($debug.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))"
                Test-LauncherFile $debug 'Debug'
            }
            foreach ($file in Get-ScanFiles (Join-Path $launcher 'log\tinyget') 1) { Test-LauncherFile $file 'Tinyget' }
        }
    }
    if (!$scan.DebugLogs) { Write-Report '읽을 수 있는 런처 로그(debug.log)가 없습니다.' }

    Write-Report "`n=== 런처 캐시 ==="
    $profileRoots = @($roamingPath; $localPaths) | Where-Object { $_ } | Select-Object -Unique
    foreach ($root in $profileRoots) {
        Write-Report "[범위] $root\nikke_launcher*\tbs_cache"
        try {
            $profiles = @(Get-ChildItem -LiteralPath $root -Filter 'nikke_launcher*' -Directory -Force -ErrorAction Stop)
        } catch { Add-Gap $root $_.CategoryInfo.Category.ToString(); continue }
        foreach ($profile in $profiles) {
            if ($profile.Attributes -band [IO.FileAttributes]::ReparsePoint) { Add-Gap $profile.FullName '프로필 링크 건너뜀'; continue }
            $cache = Join-Path $profile.FullName 'tbs_cache'
            if (!(Get-ScanItem $cache)) { continue }
            $findingsBefore = $hits.Exposure + $hits.Request + $hits.Download + $hits.Execution
            foreach ($file in Get-ScanFiles (Join-Path $cache 'Code Cache\js') 2) { Test-CacheFile $file 'Code' }
            foreach ($file in Get-ScanFiles (Join-Path $cache 'Cache') 3) { Test-CacheFile $file 'HTTP' }
            foreach ($file in Get-ScanFiles (Join-Path $cache 'Local Storage\leveldb') 1) {
                if ($file.Extension -in '.log', '.ldb', '.sst') { Test-CacheFile $file 'LevelDB' }
            }
            $network = Get-ScanItem (Join-Path $cache 'Network Persistent State')
            if ($network -and !$network.PSIsContainer) { Test-CacheFile $network 'HTTP' }
            $findingsAfter = $hits.Exposure + $hits.Request + $hits.Download + $hits.Execution
            if ($findingsAfter -gt $findingsBefore) { $affectedCaches.Add($cache) }
        }
    }
    if (!$scan.CacheFiles) { Write-Report '읽을 수 있는 런처 캐시가 없습니다.' }

    Write-Report "`n=== Chrome DLL 및 사용자 레지스트리 ==="
    Test-ChromePersistence
} catch {
    Add-Gap '점검 중 예외로 이후 단계가 생략될 수 있음' ("{0} | 스크립트 줄 {1}" -f $_.Exception.GetType().Name, $_.InvocationInfo.ScriptLineNumber)
}
$detailLineCount = $lines.Count - $headerLineCount
$details = $lines.GetRange($headerLineCount, $detailLineCount)
$lines.RemoveRange($headerLineCount, $detailLineCount)

$stopLauncher = '니케 PC 런처를 닫으세요. 작업 표시줄 알림 영역에도 남아 있으면 종료하고, 정리를 마칠 때까지 열지 마세요.'
$preserve = '파일을 지우기 전에 점검 로그를 보관하세요. 백신에서 같은 파일을 탐지했다면 보호 기록도 남겨 두세요. 회사 PC라면 정리 전에 보안 담당자에게 연락하세요.'
$removeLauncher = @('개인 PC에서 니케가 아직 설치돼 있다면 Windows 설정 → 앱 → 설치된 앱(Windows 10은 앱 및 기능)에서 제거하세요.')
if ($affectedCaches.Count) {
    $removeLauncher += '개인 PC에서 런처를 제거한 뒤에도 아래에 표시된 tbs_cache 폴더가 남아 있으면 그 폴더만 삭제하세요.'
}
$reinstallLauncher = 'PC 정리를 마치고 니케 공식 공지에서 수정판과 재설치 방법을 확인한 뒤 공식 배포처에서 새 설치 파일을 받으세요. 악성 파일이나 자동 실행 흔적이 남아 있다면 재설치를 미루세요.'
$isolate = @(
    'Wi-Fi를 끄세요. 인터넷 케이블이 꽂혀 있으면 뽑으세요.'
    $stopLauncher
    $preserve
)
$accounts = '다른 안전한 기기에서 이메일, 니케/Level Infinite, 브라우저에 저장했거나 이 PC에서 사용한 주요 계정의 비밀번호를 바꾸세요. 각 서비스의 보안 설정에서 모든 기기를 로그아웃하고 2단계 인증을 켜세요.'
$keys = 'API 키나 SSH 키가 노출됐다면 폐기하고 다시 발급하세요. 가상자산 지갑의 복구 문구가 노출됐을 수 있다면 안전한 기기에서 새 지갑을 만드세요.'
$scanForThreats = '개인 PC는 Windows 보안 → 바이러스 및 위협 방지 → 검사 옵션에서 전체 검사를 실행하세요. 다른 백신을 사용한다면 해당 백신으로 검사하세요.'
$reviewQuarantine = '개인 PC는 Windows 보안의 보호 기록에서 점검 로그에 나온 경로와 일치하는 항목을 확인하세요. 조치가 필요하면 격리를 선택하세요. 같은 위협이 이미 격리돼 있고 기록을 보관했다면 해당 항목의 제거를 선택하세요.'
$reinstall = @(
    '실행이나 자동 실행 흔적이 확인됐다면 Windows 클린 설치를 권장합니다. 필요한 문서와 사진, 점검 자료를 다른 저장장치에 보관하세요. BitLocker를 켰다면 복구 키도 확보하세요.'
    '안전한 PC에서 Microsoft 공식 Windows 설치 USB를 만드세요. USB를 꽂고 USB로 PC를 시작하세요. 설치 화면에서 Windows가 있던 디스크를 확인한 뒤 새로 설치하세요. 선택한 디스크의 데이터가 지워집니다.'
    '설치가 끝나면 보관한 문서와 사진을 옮기세요. 이전 실행 파일, 브라우저 프로필, Windows 전체 백업은 그대로 복원하지 마세요.'
)

Write-Report "`n점검 결과" -Show
if ($hits.Execution -or $hits.Persistence) {
    if ($hits.Execution) { Write-Report '악성코드가 실행된 흔적을 찾았습니다.' -Show }
    if ($hits.Persistence) { Write-Report 'Chrome에서 악성코드가 다시 실행될 수 있는 파일이나 설정을 찾았습니다.' -Show }
    Write-Report '정보가 유출됐는지는 이 점검으로 알 수 없습니다.' -Show
    $steps = $isolate + $accounts + $keys + $scanForThreats + $reviewQuarantine + $removeLauncher + $reinstall + $reinstallLauncher
} elseif ($hits.Download) {
    Write-Report '악성코드로 의심되는 파일이나 다운로드 기록을 찾았습니다. 실행 여부는 확인되지 않았습니다.' -Show
    $steps = $isolate + ('실행을 배제하기 어렵다면 계정부터 보호하세요. ' + $accounts) +
        $scanForThreats + $reviewQuarantine + $removeLauncher +
        '정리 후 다시 점검하세요. 악성 파일이 남거나 실행·Chrome 자동 실행 흔적이 나오면 PC를 분리한 상태에서 Windows 클린 설치를 검토하세요. 설치 방법은 점검 로그에 있습니다.' + $reinstallLauncher
} elseif ($hits.Request) {
    Write-Report '악성코드의 다운로드 주소가 남아 있습니다. 파일을 받았거나 실행했는지는 확인되지 않았습니다.' -Show
    $steps = @($stopLauncher, $preserve) + $removeLauncher + $reinstallLauncher
} elseif ($hits.Exposure) {
    Write-Report '악성 스크립트에 노출된 흔적을 찾았습니다. 악성코드 실행 여부는 확인되지 않았습니다.' -Show
    $steps = @($stopLauncher, $preserve) + $removeLauncher + $reinstallLauncher
} elseif ($hits.Review -or $scan.Issues -or (!$scan.DebugLogs -and !$scan.CacheFiles -and !$scan.PayloadFiles)) {
    Write-Report '판정 보류. 읽을 수 있는 자료가 부족하거나 추가로 확인할 항목이 있습니다.' -Show
    $steps = @('니케를 사용했던 Windows 계정인지 확인하세요. 설치 위치를 안다면 니케 설치 폴더를 Run-Nikke-Check.bat 위로 끌어 놓아 다시 확인하세요.')
} else {
    Write-Report '확인한 자료에서 알려진 감염 흔적을 찾지 못했습니다.' -Show
    Write-Report '기록이 지워졌다면 과거 감염을 확인하기 어렵습니다.' -Show
    $steps = @()
}
if ($scan.Issues) { Write-Report "확인하지 못한 항목이 $($scan.Issues)개 있습니다. 점검 로그에서 확인하세요." -Show }

if ($steps.Count) {
    Write-Report "`n지금 할 일" -Show
    for ($index = 0; $index -lt $steps.Count; $index++) {
        Write-Report ('{0}. {1}' -f ($index + 1), $steps[$index]) -Show
    }
}
if ($affectedCaches.Count) {
    Write-Report "`n흔적이 나온 런처 캐시" -Show
    foreach ($cache in $affectedCaches) { Write-Report $cache -Show }
}

$lines.AddRange($details)
Write-Report "`n검사 범위와 참고 자료"
Write-Report (($hits.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value }) -join '  ')
Write-Report ('검사한 파일 수. 런처 로그 {0}개, 캐시 {1}개, 다운로드 폴더(tinyget) {2}개.' -f $scan.DebugLogs, $scan.CacheFiles, $scan.PayloadFiles)
Write-Report '현재 계정의 기본 폴더와 찾을 수 있는 니케 설치 폴더를 확인했습니다. 압축된 자료나 별도 Chrome 프로필, 다른 Windows 계정과 Proton 환경은 점검에서 빠질 수 있습니다.'
Write-Report '남아 있는 기록을 확인하는 점검입니다. 흔적이 없어도 과거 감염이나 정보 유출 여부는 알 수 없습니다.'
Write-Report '공유하기 전에 설치 경로에 이름 등 개인정보가 있는지 확인하세요.'
Write-Report '판정 기준 https://github.com/MotherSphere/NIKKE-Launcher-Check/blob/main/docs/incident.md#indicators-of-compromise'
Write-Report '사건 분석 https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5'
Write-Report '니케 공식 공지 https://x.com/NIKKE_kr/status/2117817404399210900'
Write-Report 'Windows 앱 제거 https://support.microsoft.com/en-gb/windows/apps/uninstall-or-remove-apps-and-programs-in-windows'
Write-Report 'Windows 보안 보호 기록 https://support.microsoft.com/en-us/windows/security/windows-security/protection-history-in-the-windows-security-app'
Write-Report 'Microsoft Windows 설치 안내 https://support.microsoft.com/en-us/windows/deployment/install-upgrade/reinstall-windows-with-the-installation-media'

try {
    $LogDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogDirectory)
    $null = [IO.Directory]::CreateDirectory($LogDirectory)
    $logPath = Join-Path $LogDirectory ('Nikke-Check-{0:yyyyMMdd-HHmmss-fff}-{1}.txt' -f [DateTime]::Now, $PID)
    [IO.File]::WriteAllLines($logPath, $lines.ToArray(), [Text.UTF8Encoding]::new($true))
    Write-Host "`n점검 로그 저장 위치`n$logPath"
} catch {
    Write-Host '점검 로그를 저장하지 못했습니다. 두 파일을 바탕 화면처럼 파일을 저장할 수 있는 폴더에 두고 다시 실행하세요.'
    exit 2
}
if ($OfferRemediation -and ($scan.ConfirmedExecution -or $registeredDlls.Count)) {
    $firstActionLine = $lines.Count
    try { Invoke-ConfirmedActions }
    catch {
        Write-Report "선택 조치 중단  $($_.Exception.GetBaseException().Message)" -Show
        $scan.Issues++
    }
    try { [IO.File]::AppendAllLines($logPath, $lines.GetRange($firstActionLine, $lines.Count - $firstActionLine)) }
    catch {
        Write-Host '조치 결과를 점검 로그에 덧붙이지 못했습니다. 화면의 백업 경로를 보관하세요.'
        exit 2
    }
}
if ($scan.Issues) { exit 1 }
exit 0

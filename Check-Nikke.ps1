#requires -Version 5.1
# 제작자 Serio_ai
[CmdletBinding()]
param(
    [string]$InstallPath,
    [string]$LogDirectory
)

$ErrorActionPreference = 'Stop'
if (!$LogDirectory) { $LogDirectory = Join-Path $PSScriptRoot 'logs' }
$lines = [System.Collections.Generic.List[string]]::new()
$hits = [ordered]@{ Exposure = 0; Request = 0; Download = 0; Execution = 0; Persistence = 0; Review = 0 }
$scan = @{ Issues = 0; DebugLogs = 0; CacheFiles = 0; PayloadFiles = 0 }
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
    $clsidPath = 'Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}'
    foreach ($view in $registryViews) {
        $label = "HKCU\$clsidPath [$view]"
        $baseKey = $key = $server = $null
        try {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, $view)
            $key = $baseKey.OpenSubKey($clsidPath, $false)
            if (!$key) { Write-Report "[미발견] $label"; continue }
            $server = $key.OpenSubKey('InprocServer32', $false)
            $target = if ($server) { [string]$server.GetValue('', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
            if ($target -match '(?i)[\\/]platform_experience_helper\.dll"?\s*$') {
                Add-Finding Persistence 'Chrome에서 의심 파일을 불러오도록 등록돼 있습니다.' $label
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

if ($env:OS -ne 'Windows_NT') { throw 'Windows에서 실행하세요.' }
$localPaths = @([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData),
    (Join-Path $env:USERPROFILE 'AppData\Local')) | Where-Object { $_ } | Select-Object -Unique
$roamingPath = [Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData)
$registryViews = @([Microsoft.Win32.RegistryView]::Registry32)
if ([Environment]::Is64BitOperatingSystem) { $registryViews += [Microsoft.Win32.RegistryView]::Registry64 }
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
            foreach ($file in Get-ScanFiles (Join-Path $cache 'Code Cache\js') 2) { Test-CacheFile $file 'Code' }
            foreach ($file in Get-ScanFiles (Join-Path $cache 'Cache') 3) { Test-CacheFile $file 'HTTP' }
            foreach ($file in Get-ScanFiles (Join-Path $cache 'Local Storage\leveldb') 1) {
                if ($file.Extension -in '.log', '.ldb', '.sst') { Test-CacheFile $file 'LevelDB' }
            }
            $network = Get-ScanItem (Join-Path $cache 'Network Persistent State')
            if ($network -and !$network.PSIsContainer) { Test-CacheFile $network 'HTTP' }
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

$pauseLauncher = '니케 PC 런처를 다시 열지 마세요. 점검 로그를 보관하고, 니케 공식 공지에서 업데이트와 캐시 정리 방법을 확인하세요.'
$isolate = @(
    'Wi-Fi를 끄세요. 인터넷 케이블이 꽂혀 있으면 뽑으세요.'
    'PC를 재부팅하거나 파일을 지우기 전에 점검 로그와 발견된 파일을 보관하세요. 회사 PC라면 보안팀에 먼저 연락하세요.'
)
$accounts = '다른 안전한 기기에서 이메일, 니케/Level Infinite, 업무 계정의 비밀번호를 바꾸세요. 각 서비스의 보안 설정에서 기존 로그인 기기를 모두 로그아웃하세요.'
$keys = 'API 키나 SSH 키가 노출됐다면 폐기하고 다시 발급하세요. 가상자산 지갑의 복구 문구가 노출됐을 수 있다면 안전한 기기에서 새 지갑을 만드세요.'
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
    $steps = $isolate + $accounts + $keys + $reinstall
} elseif ($hits.Download) {
    Write-Report '악성코드로 의심되는 파일이나 다운로드 기록을 찾았습니다. 실행 여부는 확인되지 않았습니다.' -Show
    $steps = $isolate + @(
        ('실행이 의심되거나 당시 기록이 남아 있지 않다면 계정도 보호하세요. ' + $accounts)
        $keys
        '감염 여부를 확인하기 어렵고 PC를 안전하게 쓰기 힘들다면 Windows 클린 설치를 고려하세요. 설치 방법은 점검 로그의 Microsoft 안내를 참고하세요.'
    )
} elseif ($hits.Request) {
    Write-Report '악성코드의 다운로드 주소가 남아 있습니다. 파일을 받았거나 실행했는지는 확인되지 않았습니다.' -Show
    $steps = @($pauseLauncher)
} elseif ($hits.Exposure) {
    Write-Report '악성 스크립트에 노출된 흔적을 찾았습니다. 악성코드 실행 여부는 확인되지 않았습니다.' -Show
    $steps = @($pauseLauncher)
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

$lines.AddRange($details)
Write-Report "`n검사 범위와 참고 자료"
Write-Report (($hits.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value }) -join '  ')
Write-Report ('검사한 파일 수. 런처 로그 {0}개, 캐시 {1}개, 다운로드 폴더(tinyget) {2}개.' -f $scan.DebugLogs, $scan.CacheFiles, $scan.PayloadFiles)
Write-Report '현재 계정의 기본 폴더와 찾을 수 있는 니케 설치 폴더를 확인했습니다. 압축된 자료나 별도 Chrome 프로필, 다른 Windows 계정과 Proton 환경은 점검에서 빠질 수 있습니다.'
Write-Report '남아 있는 기록을 확인하는 점검입니다. 흔적이 없어도 과거 감염이나 정보 유출 여부는 알 수 없습니다.'
Write-Report '공유하기 전에 설치 경로에 이름 등 개인정보가 있는지 확인하세요.'
Write-Report '판정 기준 https://github.com/MotherSphere/NIKKE-Launcher-Check/blob/main/docs/incident.md#indicators-of-compromise'
Write-Report '사건 분석 https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5'
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
if ($scan.Issues) { exit 1 }
exit 0

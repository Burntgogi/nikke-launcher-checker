#requires -Version 5.1
# 제작자 Serio_ai
[CmdletBinding()]
param(
    [string]$InstallPath,
    [string]$LogDirectory,
    [switch]$OfferRemediation,
    [string]$RestoreBackup,
    [ValidateSet('Auto','ko','en','ja')]
    [string]$Language = 'Auto'
)

$ErrorActionPreference = 'Stop'

if ($Language -eq 'Auto') {
    $uiLanguage = (Get-UICulture).TwoLetterISOLanguageName
    $Language = 'en'
    if ($uiLanguage -in 'ko', 'ja') { $Language = $uiLanguage }
}

# Only user-facing text varies by language. Finding IDs and backup fields stay the same.
$messages = switch ($Language) {
    'ko' {
        @{
            Gap = '[확인하지 못한 항목] {0} | {1}'
            ReparseSkipped = '링크 또는 접합점 건너뜀'
            DepthLimit = '탐색 깊이 제한'
            SizeLimit = '32 MiB를 초과해 내용 검사 생략'
            CacheExecution = '런처 캐시에 실행 기록(k2f.agent.state)이 있습니다.'
            CacheExposure = '런처 캐시에 사건과 관련된 인터넷 주소가 있습니다.'
            CacheNameOnly = '캐시 파일 이름이 일치합니다. 관련 주소는 찾지 못했습니다.'
            CacheRequest = '캐시에 다운로드 주소가 있습니다.'
            LoaderHash = '변조된 스크립트와 파일 지문(SHA-256)이 일치합니다.'
            PayloadHash = '알려진 악성코드와 파일 지문(SHA-256)이 일치합니다.'
            PayloadPattern = '다운로드 폴더(tinyget)에 악성코드와 같은 형식의 파일이 있습니다.'
            LogExecution = '런처 로그(debug.log)에 실행 흔적이 {0}건 있습니다.'
            LogRequest = '런처 로그에 다운로드 주소가 있습니다.'
            LogDownload = '런처 로그에 Lua 파일을 저장한 기록이 있습니다.'
            LocalInstallPath = '로컬 드라이브의 설치 폴더를 지정하세요.'
            InstallPathUnreadable = '지정한 설치 폴더를 열 수 없음'
            InstallEntriesUnreadable = '설치 정보 {0} 건 조회 실패'
            LocalScanOnly = '로컬 드라이브 경로만 조회'
            NotFound = '[미발견] {0}'
            ChromeRegistered = 'Chrome에서 의심 파일을 불러오도록 등록돼 있습니다.'
            ChromeRegistryReview = '관련 레지스트리 항목이 있습니다. 의심 파일과의 연결은 확인되지 않았습니다.'
            Scope = '[범위] {0}'
            ChromeDll = 'Chrome 사용자 폴더에 의심 파일이 있습니다. Chrome이 이 파일을 불러왔는지는 확인되지 않았습니다.'
            ChromeUserReview = 'Chrome 사용자 폴더에 확인이 필요한 DLL 파일이 있습니다.'
            ChromeInstallReview = 'Chrome 설치 폴더에 확인이 필요한 DLL 파일이 있습니다.'
            UnsafePath = '로컬 고정 드라이브의 정확한 경로를 확인할 수 없습니다.'
            UnsafeFileHandle = '대상이 폴더, 링크, 접합점 또는 하드 링크가 있는 파일입니다.'
            OpenedPathMismatch = '열린 파일의 경로가 확인한 경로와 일치하지 않습니다.'
            ReparsePath = '경로에 링크 또는 접합점이 있습니다.'
            BackupVerificationFailed = '암호화 백업을 확인할 수 없습니다.'
            ChromeActionEvidence = 'Chrome에 등록된 DLL입니다. 파일 지문이 상위 폴더 이름과 일치합니다.'
            PayloadActionEvidence = '공개된 악성코드와 파일 지문이 일치합니다.'
            RegistryTargetMismatch = '확인된 레지스트리 대상과 일치하지 않습니다.'
            RegistryKeyUnreadable = '레지스트리 키가 없거나 열 수 없습니다.'
            RegistryValueExists = '기본값이 이미 있어 복구를 건너뜁니다.'
            RegistryRestoreUnverified = '기본값이 복구됐는지 확인할 수 없습니다.'
            RegistryValueChanged = '점검한 뒤 레지스트리 값이 바뀌었습니다.'
            RegistryValueChangedDuringBackup = '백업하는 동안 레지스트리 값이 바뀌었습니다.'
            RegistryRemovalUnverified = '기본값이 제거됐는지 확인할 수 없습니다.'
            RecoveryInstructions = '오탐으로 확인되면 이 PC의 같은 Windows 계정에서 점검 도구 폴더를 열고 아래 명령을 실행하세요.'
            NoActionTargets = '격리하거나 제거할 수 있을 만큼 근거가 확인된 항목이 없습니다.'
            OptionalActions = '선택 조치. 각 항목에서 Enter를 누르면 건너뜁니다.'
            BeforeActions = '인터넷 연결을 끊고 니케 런처와 Chrome을 닫은 뒤 진행하세요. 회사 PC라면 보안 담당자에게 먼저 연락하세요.'
            FileQuarantine = '파일 격리  {0}'
            FileQuarantineEffect = '암호화 백업을 확인한 뒤 원래 위치의 파일을 제거합니다.'
            RegistryRemove = '기본값 제거  {0} [{1}]'
            RegistryDll = '이 값이 가리키는 DLL  {0}'
            RegistryRemoveEffect = '현재 사용자의 (기본값) 한 개를 백업한 뒤 제거합니다.'
            BackupFile = '백업 파일  {0}'
            ConfirmAction = '이 항목을 처리하려면 Y를 입력하세요'
            ActionSkipped = '건너뜀  {0}'
            ActionSizeLimit = '파일 크기가 확인 범위를 벗어났습니다.'
            FileReadIncomplete = '파일을 끝까지 읽을 수 없습니다.'
            FileChanged = '점검한 뒤 파일 내용이 바뀌었습니다.'
            OriginalFilePresent = '원래 위치에 파일이 남았거나 다시 생겼습니다.'
            ActionDone = '처리 완료  {0}'
            ActionFailed = '미완료  {0} | {1}'
            BackupSaved = '백업  {0}'
            BackupPathRequired = '점검 도구가 안내한 백업 파일 경로를 입력하세요.'
            BackupUnreadable = '읽을 수 있는 점검 도구 백업이 아닙니다.'
            BackupFormatUnknown = '백업 형식을 확인할 수 없습니다.'
            BackupMismatch = '백업의 파일 지문이나 원래 경로가 일치하지 않습니다.'
            FileRestore = '파일 복구  {0}'
            RegistryRestore = '기본값 복구  {0} [{1}]'
            BeforeRestore = '오탐으로 확인된 경우에만 복구하세요. 원래 위치에 파일이나 값이 있으면 덮어쓰지 않습니다.'
            ConfirmRestore = '이 항목을 복구하려면 RESTORE를 입력하세요'
            RestoreCancelled = '복구를 취소했습니다.'
            RestoreDone = '복구했습니다.'
            WindowsOnly = 'Windows에서 실행하세요.'
            RestoreFailed = '복구 미완료  {0}'
            Title = '니케 PC 런처 감염 점검'
            Author = '제작자 Serio_ai'
            ScanTime = '점검 시각 {0:yyyy-MM-dd HH:mm:ss zzz}'
            ScanIntro = '현재 Windows 계정의 기록을 확인하고 점검 로그만 저장합니다.'
            LogSection = '=== 런처 로그 ==='
            DebugLogFile = '[로그] {0} | 수정 {1}'
            NoDebugLogs = '읽을 수 있는 런처 로그(debug.log)가 없습니다.'
            CacheSection = '=== 런처 캐시 ==='
            ProfileLinkSkipped = '프로필 링크 건너뜀'
            NoCache = '읽을 수 있는 런처 캐시가 없습니다.'
            ChromeSection = '=== Chrome DLL 및 사용자 레지스트리 ==='
            ScanInterrupted = '점검 중 예외로 이후 단계가 생략될 수 있음'
            ScriptLine = '{0} | 스크립트 줄 {1}'
            StopLauncher = '니케 PC 런처를 닫으세요. 작업 표시줄 알림 영역에도 남아 있으면 종료하고, 정리를 마칠 때까지 열지 마세요.'
            PreserveEvidence = '파일을 지우기 전에 점검 로그를 보관하세요. 백신에서 같은 파일을 탐지했다면 보호 기록도 남겨 두세요. 회사 PC라면 정리 전에 보안 담당자에게 연락하세요.'
            RemoveLauncher = '개인 PC에서 니케가 아직 설치돼 있다면 Windows 설정 → 앱 → 설치된 앱(Windows 10은 앱 및 기능)에서 제거하세요.'
            RemoveCache = '개인 PC에서 런처를 제거한 뒤에도 아래에 표시된 tbs_cache 폴더가 남아 있으면 그 폴더만 삭제하세요.'
            ReinstallLauncher = 'PC 정리를 마치고 니케 공식 공지에서 수정판과 재설치 방법을 확인한 뒤 공식 배포처에서 새 설치 파일을 받으세요. 악성 파일이나 자동 실행 흔적이 남아 있다면 재설치를 미루세요.'
            Disconnect = 'Wi-Fi를 끄세요. 인터넷 케이블이 꽂혀 있으면 뽑으세요.'
            ProtectAccounts = '다른 안전한 기기에서 이메일, 니케/Level Infinite, 브라우저에 저장했거나 이 PC에서 사용한 주요 계정의 비밀번호를 바꾸세요. 각 서비스의 보안 설정에서 모든 기기를 로그아웃하고 2단계 인증을 켜세요.'
            RotateKeys = 'API 키나 SSH 키가 노출됐다면 폐기하고 다시 발급하세요. 가상자산 지갑의 복구 문구가 노출됐을 수 있다면 안전한 기기에서 새 지갑을 만드세요.'
            RunAntivirus = '개인 PC는 Windows 보안 → 바이러스 및 위협 방지 → 검사 옵션에서 전체 검사를 실행하세요. 다른 백신을 사용한다면 해당 백신으로 검사하세요.'
            ReviewQuarantine = '개인 PC는 Windows 보안의 보호 기록에서 점검 로그에 나온 경로와 일치하는 항목을 확인하세요. 조치가 필요하면 격리를 선택하세요. 같은 위협이 이미 격리돼 있고 기록을 보관했다면 해당 항목의 제거를 선택하세요.'
            CleanInstallPrepare = '실행이나 자동 실행 흔적이 확인됐다면 Windows 클린 설치를 권장합니다. 필요한 문서와 사진, 점검 자료를 다른 저장장치에 보관하세요. BitLocker를 켰다면 복구 키도 확보하세요.'
            CleanInstallUsb = '안전한 PC에서 Microsoft 공식 Windows 설치 USB를 만드세요. USB를 꽂고 USB로 PC를 시작하세요. 설치 화면에서 Windows가 있던 디스크를 확인한 뒤 새로 설치하세요. 선택한 디스크의 데이터가 지워집니다.'
            CleanInstallRestore = '설치가 끝나면 보관한 문서와 사진을 옮기세요. 이전 실행 파일, 브라우저 프로필, Windows 전체 백업은 그대로 복원하지 마세요.'
            Results = '점검 결과'
            ResultExecution = '악성코드가 실행된 흔적을 찾았습니다.'
            ResultPersistence = 'Chrome에서 악성코드가 다시 실행될 수 있는 파일이나 설정을 찾았습니다.'
            UnknownDisclosure = '정보가 유출됐는지는 이 점검으로 알 수 없습니다.'
            ResultDownload = '악성코드로 의심되는 파일이나 다운로드 기록을 찾았습니다. 실행 여부는 확인되지 않았습니다.'
            ProtectIfExecutionPossible = '실행을 배제하기 어렵다면 계정부터 보호하세요.'
            CheckAgain = '정리 후 다시 점검하세요. 악성 파일이 남거나 실행·Chrome 자동 실행 흔적이 나오면 PC를 분리한 상태에서 Windows 클린 설치를 검토하세요. 설치 방법은 점검 로그에 있습니다.'
            ResultRequest = '악성코드의 다운로드 주소가 남아 있습니다. 파일을 받았거나 실행했는지는 확인되지 않았습니다.'
            ResultExposure = '악성 스크립트에 노출된 흔적을 찾았습니다. 악성코드 실행 여부는 확인되지 않았습니다.'
            ResultInconclusive = '판정 보류. 읽을 수 있는 자료가 부족하거나 추가로 확인할 항목이 있습니다.'
            CheckAccountAndPath = '니케를 사용했던 Windows 계정인지 확인하세요. 설치 위치를 안다면 니케 설치 폴더를 Run-Nikke-Check.bat 위로 끌어 놓아 다시 확인하세요.'
            ResultNoTraces = '확인한 자료에서 알려진 감염 흔적을 찾지 못했습니다.'
            MissingHistory = '기록이 지워졌다면 과거 감염을 확인하기 어렵습니다.'
            UncheckedCount = '확인하지 못한 항목이 {0}개 있습니다. 점검 로그에서 확인하세요.'
            NextSteps = '지금 할 일'
            AffectedCaches = '흔적이 나온 런처 캐시'
            ScopeAndSources = '검사 범위와 참고 자료'
            FileCounts = '검사한 파일 수. 런처 로그 {0}개, 캐시 {1}개, 다운로드 폴더(tinyget) {2}개.'
            ScopeLimits = '현재 계정의 기본 폴더와 찾을 수 있는 니케 설치 폴더를 확인했습니다. 압축된 자료나 별도 Chrome 프로필, 다른 Windows 계정과 Proton 환경은 점검에서 빠질 수 있습니다.'
            EvidenceLimits = '남아 있는 기록을 확인하는 점검입니다. 흔적이 없어도 과거 감염이나 정보 유출 여부는 알 수 없습니다.'
            LogPrivacy = '공유하기 전에 설치 경로에 이름 등 개인정보가 있는지 확인하세요.'
            IndicatorsSource = '판정 기준'
            AnalysisSource = '사건 분석'
            OfficialNotice = '니케 공식 공지'
            AppRemovalSource = 'Windows 앱 제거'
            ProtectionHistorySource = 'Windows 보안 보호 기록'
            InstallWindowsSource = 'Microsoft Windows 설치 안내'
            LogLocation = '점검 로그 저장 위치'
            LogSaveFailed = '점검 로그를 저장하지 못했습니다. 두 파일을 바탕 화면처럼 파일을 저장할 수 있는 폴더에 두고 다시 실행하세요.'
            ActionsStopped = '선택 조치 중단  {0}'
            ActionLogFailed = '조치 결과를 점검 로그에 덧붙이지 못했습니다. 화면의 백업 경로를 보관하세요.'
        }
    }
    'ja' {
        @{
            Gap = '[未確認] {0} | {1}'
            ReparseSkipped = 'リンクまたはジャンクションをスキップ'
            DepthLimit = '検索の深さが上限に達しました'
            SizeLimit = '32 MiB を超えるため内容の確認を省略'
            CacheExecution = 'ランチャーのキャッシュに実行記録 (k2f.agent.state) があります。'
            CacheExposure = 'ランチャーのキャッシュに事件に関連するアドレスがあります。'
            CacheNameOnly = 'キャッシュのファイル名が一致しました。関連アドレスは見つかりませんでした。'
            CacheRequest = 'キャッシュにダウンロード先のアドレスがあります。'
            LoaderHash = 'SHA-256 ハッシュが改ざんされたスクリプトと一致しました。'
            PayloadHash = 'SHA-256 ハッシュが既知のマルウェアと一致しました。'
            PayloadPattern = 'ダウンロードフォルダー (tinyget) にマルウェアと同じ形式のファイルがあります。'
            LogExecution = 'ランチャーログ (debug.log) に実行の痕跡が {0} 件あります。'
            LogRequest = 'ランチャーログにダウンロード先のアドレスがあります。'
            LogDownload = 'ランチャーログに Lua ファイルの保存記録があります。'
            LocalInstallPath = 'ローカルドライブ上のインストールフォルダーを指定してください。'
            InstallPathUnreadable = '指定されたインストールフォルダーを開けませんでした'
            InstallEntriesUnreadable = 'インストール情報を {0} 件読み取れませんでした'
            LocalScanOnly = 'ローカルドライブ上のパスのみ確認します'
            NotFound = '[見つかりませんでした] {0}'
            ChromeRegistered = 'Chrome が不審なファイルを読み込むように登録されています。'
            ChromeRegistryReview = '関連するレジストリ項目があります。不審なファイルとの関連は確認できませんでした。'
            Scope = '[確認範囲] {0}'
            ChromeDll = 'Chrome のユーザーフォルダーに不審なファイルがあります。Chrome が読み込んだかは確認できませんでした。'
            ChromeUserReview = 'Chrome のユーザーフォルダーに確認が必要な DLL があります。'
            ChromeInstallReview = 'Chrome のインストールフォルダーに確認が必要な DLL があります。'
            UnsafePath = 'ローカル固定ドライブ上の正確なパスを確認できませんでした。'
            UnsafeFileHandle = '対象はフォルダー、リンク、ジャンクション、またはハードリンクのあるファイルです。'
            OpenedPathMismatch = '開いたファイルのパスが確認済みのパスと一致しません。'
            ReparsePath = 'パスにリンクまたはジャンクションがあります。'
            BackupVerificationFailed = '暗号化バックアップを確認できませんでした。'
            ChromeActionEvidence = 'Chrome に登録された DLL です。SHA-256 ハッシュが親フォルダー名と一致します。'
            PayloadActionEvidence = 'ファイルの SHA-256 ハッシュが公開済みのマルウェアのハッシュと一致します。'
            RegistryTargetMismatch = '確認済みのレジストリ項目と一致しません。'
            RegistryKeyUnreadable = 'レジストリキーが存在しないか、開けません。'
            RegistryValueExists = '既定値がすでにあるため、復元をスキップします。'
            RegistryRestoreUnverified = '既定値が復元されたことを確認できませんでした。'
            RegistryValueChanged = '点検後にレジストリ値が変わりました。'
            RegistryValueChangedDuringBackup = 'バックアップ中にレジストリ値が変わりました。'
            RegistryRemovalUnverified = '既定値が削除されたことを確認できませんでした。'
            RecoveryInstructions = '誤検知だと確認できた場合は、この PC に同じ Windows アカウントでサインインし、点検ツールのフォルダーで下のコマンドを実行してください。'
            NoActionTargets = '隔離や削除の条件を満たす項目はありません。'
            OptionalActions = '対処は任意です。Enter キーで項目をスキップできます。'
            BeforeActions = 'インターネットを切断し、NIKKE ランチャーと Chrome を閉じてください。会社の PC では先にセキュリティ担当者へ連絡してください。'
            FileQuarantine = 'ファイルを隔離  {0}'
            FileQuarantineEffect = '暗号化バックアップを確認してから、元の場所のファイルを取り除きます。'
            RegistryRemove = '既定値を削除  {0} [{1}]'
            RegistryDll = 'この値が参照する DLL  {0}'
            RegistryRemoveEffect = '現在の Windows ユーザーの既定値を 1 件だけバックアップして削除します。'
            BackupFile = 'バックアップファイル  {0}'
            ConfirmAction = 'この項目を処理するには Y と入力してください'
            ActionSkipped = 'スキップ  {0}'
            ActionSizeLimit = '隔離できるファイルサイズの上限を超えています。'
            FileReadIncomplete = 'ファイルを最後まで読み取れませんでした。'
            FileChanged = '点検後にファイルの内容が変わりました。'
            OriginalFilePresent = '元の場所にファイルが残っているか、再作成されています。'
            ActionDone = '処理完了  {0}'
            ActionFailed = '処理未完了  {0} | {1}'
            BackupSaved = 'バックアップ  {0}'
            BackupPathRequired = '点検ツールが表示したバックアップファイルのパスを指定してください。'
            BackupUnreadable = 'このファイルは点検ツールのバックアップとして読み取れません。'
            BackupFormatUnknown = 'バックアップの形式を確認できませんでした。'
            BackupMismatch = 'ファイルのハッシュまたは元のパスがバックアップと一致しません。'
            FileRestore = 'ファイルを復元  {0}'
            RegistryRestore = '既定値を復元  {0} [{1}]'
            BeforeRestore = '誤検知だと確認できた場合にだけ復元してください。元の場所にファイルや値がある場合は上書きしません。'
            ConfirmRestore = 'この項目を復元するには RESTORE と入力してください'
            RestoreCancelled = '復元をキャンセルしました。'
            RestoreDone = '復元しました。'
            WindowsOnly = 'Windows で実行してください。'
            RestoreFailed = '復元未完了  {0}'
            Title = 'NIKKE PC ランチャー感染チェック'
            Author = '作成者 Serio_ai'
            ScanTime = '点検日時 {0:yyyy-MM-dd HH:mm:ss zzz}'
            ScanIntro = '現在の Windows アカウントの記録を読み取り、点検ログを保存します。'
            LogSection = '=== ランチャーログ ==='
            DebugLogFile = '[ログ] {0} | 更新 {1}'
            NoDebugLogs = '読み取れるランチャーログ (debug.log) がありません。'
            CacheSection = '=== ランチャーのキャッシュ ==='
            ProfileLinkSkipped = 'プロファイルへのリンクをスキップ'
            NoCache = '読み取れるランチャーのキャッシュがありません。'
            ChromeSection = '=== Chrome DLL とユーザーレジストリ ==='
            ScanInterrupted = 'エラーにより以降の点検が省略された可能性があります'
            ScriptLine = '{0} | スクリプトの {1} 行目'
            StopLauncher = 'NIKKE PC ランチャーを閉じてください。タスクバーの通知領域に残っていれば、そこからも終了し、対処が済むまで起動しないでください。'
            PreserveEvidence = 'ファイルを削除する前に点検ログを保存してください。ウイルス対策ソフトが同じファイルを検出した場合は、その履歴も残してください。会社の PC では対処の前にセキュリティ担当者へ連絡してください。'
            RemoveLauncher = '個人の PC に NIKKE が残っている場合は、Windows の「設定」→「アプリ」→「インストールされているアプリ」からアンインストールしてください。Windows 10 では「アプリと機能」です。'
            RemoveCache = '個人の PC でランチャーをアンインストールした後、下に表示された tbs_cache フォルダーが残っていれば、そのフォルダーだけを削除してください。'
            ReinstallLauncher = '対処が済んだら、NIKKE の公式告知で修正版と再インストール手順を確認し、公式配布元からインストーラーを入手してください。悪意のあるファイルや自動起動の痕跡が残っている間は再インストールを控えてください。'
            Disconnect = 'Wi-Fi をオフにしてください。有線接続の場合は LAN ケーブルを抜いてください。'
            ProtectAccounts = '安全な別の端末で、メール、NIKKE／Level Infinite、この PC で使った重要なアカウントやブラウザーに保存したアカウントのパスワードを変更してください。各サービスのセキュリティ設定で全端末からログアウトし、2 段階認証を有効にしてください。'
            RotateKeys = 'API キーや SSH キーが漏えいした場合は、無効化して再発行してください。暗号資産ウォレットの復元フレーズが漏えいした可能性がある場合は、安全な端末で新しいウォレットを作成してください。'
            RunAntivirus = '個人の PC では「Windows セキュリティ」→「ウイルスと脅威の防止」→「スキャンのオプション」でフルスキャンを実行してください。別のウイルス対策ソフトを使っている場合は、そのソフトでスキャンしてください。'
            ReviewQuarantine = '個人の PC では、「Windows セキュリティ」の「保護の履歴」と点検ログのパスを照合してください。対処が必要なら「隔離」を選びます。同じ脅威がすでに隔離され、履歴を保存済みなら「削除」を選んでください。'
            CleanInstallPrepare = '実行や自動起動の痕跡が確認できた場合は、Windows のクリーンインストールを推奨します。必要な文書、写真、点検資料を別のストレージに保存してください。BitLocker が有効なら回復キーも確保してください。'
            CleanInstallUsb = '安全な PC で、Microsoft 公式の Windows インストール USB を作成してください。対象の PC に挿し、USB から起動します。インストール画面で Windows が入っていたドライブを確認してから、新規インストールしてください。選択したドライブのデータは消去されます。'
            CleanInstallRestore = 'インストール後は、保存した文書と写真を戻してください。以前の実行ファイル、ブラウザープロファイル、Windows 全体のバックアップをそのまま戻すのは避けてください。'
            Results = '点検結果'
            ResultExecution = 'マルウェアが実行された痕跡が見つかりました。'
            ResultPersistence = 'Chrome でマルウェアが再び実行される可能性のあるファイルや設定が見つかりました。'
            UnknownDisclosure = 'この点検では、情報が流出したかは分かりません。'
            ResultDownload = 'マルウェアが疑われるファイルまたはダウンロード記録が見つかりました。実行されたかは確認できませんでした。'
            ProtectIfExecutionPossible = '実行された可能性がある場合は、先にアカウントを保護してください。'
            CheckAgain = '対処後にもう一度点検してください。悪意のあるファイルが残っているか、実行や Chrome の自動起動の痕跡が見つかった場合は、PC をネットワークから切り離したまま Windows のクリーンインストールを検討してください。手順へのリンクは点検ログにあります。'
            ResultRequest = 'マルウェアのダウンロード先が見つかりました。実際にダウンロードされたか、実行されたかは確認できませんでした。'
            ResultExposure = '悪意のあるスクリプトに触れた痕跡が見つかりました。マルウェアが実行されたかは確認できませんでした。'
            ResultInconclusive = '判定保留。読み取れる記録が不足しているか、追加の確認が必要な項目があります。'
            CheckAccountAndPath = 'NIKKE を使っていた Windows アカウントか確認してください。インストール先が分かる場合は、そのフォルダーを Run-Nikke-Check.bat にドラッグして再点検してください。'
            ResultNoTraces = '確認できた記録からは既知の感染の痕跡は見つかりませんでした。'
            MissingHistory = '記録が消えていると、過去の感染は確認しにくくなります。'
            UncheckedCount = '確認できなかった項目が {0} 件あります。詳しくは点検ログをご覧ください。'
            NextSteps = '次にすること'
            AffectedCaches = '痕跡が見つかったランチャーのキャッシュ'
            ScopeAndSources = '点検範囲と参考資料'
            FileCounts = '確認したファイル数。ランチャーログ {0} 件、キャッシュ {1} 件、ダウンロードフォルダー (tinyget) {2} 件。'
            ScopeLimits = '現在のアカウントの既定フォルダーと、見つかった NIKKE のインストールフォルダーを確認しました。圧縮ファイル、別の Chrome プロファイル、別の Windows アカウント、Proton 環境は点検範囲に含まれない場合があります。'
            EvidenceLimits = '残っている記録を確認する点検です。痕跡がなくても、過去の感染や情報流出の有無は分かりません。'
            LogPrivacy = 'ログを共有する前に、パスに名前などの個人情報が含まれていないか確認してください。'
            IndicatorsSource = '判定に使った侵害指標'
            AnalysisSource = '事件の分析'
            OfficialNotice = 'NIKKE 公式告知'
            AppRemovalSource = 'Windows でアプリをアンインストール'
            ProtectionHistorySource = 'Windows セキュリティの保護の履歴'
            InstallWindowsSource = 'Microsoft の Windows インストール手順'
            LogLocation = '点検ログの保存先'
            LogSaveFailed = 'ログを保存できませんでした。デスクトップなど、書き込みできるフォルダーに 2 つのファイルを置いてからやり直してください。'
            ActionsStopped = '対処を中止  {0}'
            ActionLogFailed = '対処の結果をログに追記できませんでした。画面に表示されたバックアップのパスを控えてください。'
        }
    }
    default {
        @{
            Gap = '[Unchecked] {0} | {1}'
            ReparseSkipped = 'Skipped a link or junction'
            DepthLimit = 'Search depth limit reached'
            SizeLimit = 'Content check skipped. File exceeds 32 MiB.'
            CacheExecution = 'The launcher cache contains an execution record (k2f.agent.state).'
            CacheExposure = 'The launcher cache contains an address linked to the incident.'
            CacheNameOnly = 'The cache filename matches. No related address was found.'
            CacheRequest = 'The cache contains a download address.'
            LoaderHash = 'The SHA-256 hash matches a tampered script.'
            PayloadHash = 'The SHA-256 hash matches known malware.'
            PayloadPattern = 'The download folder (tinyget) contains a file with the same format as the malware.'
            LogExecution = 'Execution traces in the launcher log (debug.log): {0}.'
            LogRequest = 'The launcher log contains a download address.'
            LogDownload = 'The launcher log records a Lua file being saved.'
            LocalInstallPath = 'Specify the installation folder on a local drive.'
            InstallPathUnreadable = 'Could not open the specified installation folder'
            InstallEntriesUnreadable = 'Could not read {0} installation entries'
            LocalScanOnly = 'Only local drive paths are checked'
            NotFound = '[Not found] {0}'
            ChromeRegistered = 'Chrome is configured to load a suspicious file.'
            ChromeRegistryReview = 'A related registry entry exists. Its link to the suspicious file could not be verified.'
            Scope = '[Scope] {0}'
            ChromeDll = 'The Chrome user folder contains a suspicious file. Whether Chrome loaded it is unknown.'
            ChromeUserReview = 'A DLL in the Chrome user folder needs review.'
            ChromeInstallReview = 'A DLL in the Chrome installation folder needs review.'
            UnsafePath = 'Could not verify the exact path on a fixed local drive.'
            UnsafeFileHandle = 'The target is a directory, reparse point, or hard-linked file.'
            OpenedPathMismatch = 'The opened file does not have the approved path.'
            ReparsePath = 'The path contains a link or junction.'
            BackupVerificationFailed = 'Could not verify the encrypted backup.'
            ChromeActionEvidence = 'The DLL is registered for Chrome. Its SHA-256 hash matches the parent folder name.'
            PayloadActionEvidence = 'The file''s SHA-256 hash matches a published malware hash.'
            RegistryTargetMismatch = 'The registry entry does not match the verified target.'
            RegistryKeyUnreadable = 'The registry key is missing or cannot be opened.'
            RegistryValueExists = 'The default value already exists. Skipping restore.'
            RegistryRestoreUnverified = 'Could not verify that the default value was restored.'
            RegistryValueChanged = 'The registry value changed after the scan.'
            RegistryValueChangedDuringBackup = 'The registry value changed during backup.'
            RegistryRemovalUnverified = 'Could not verify that the default value was removed.'
            RecoveryInstructions = 'If you confirm a false positive, open the checker folder on this PC with the same Windows account and run the command below.'
            NoActionTargets = 'No items met the criteria for quarantine or removal.'
            OptionalActions = 'Optional actions. Press Enter to skip an item.'
            BeforeActions = 'Disconnect from the internet and close the NIKKE launcher and Chrome. On a work PC, contact your security team first.'
            FileQuarantine = 'Quarantine file  {0}'
            FileQuarantineEffect = 'The file is removed from its original location after the encrypted backup is verified.'
            RegistryRemove = 'Remove default value  {0} [{1}]'
            RegistryDll = 'DLL referenced by this value  {0}'
            RegistryRemoveEffect = 'The tool backs up and removes one default value for the current Windows user.'
            BackupFile = 'Backup file  {0}'
            ConfirmAction = 'Type Y to proceed with this item'
            ActionSkipped = 'Skipped  {0}'
            ActionSizeLimit = 'The file exceeds the size limit for quarantine.'
            FileReadIncomplete = 'Could not read the entire file.'
            FileChanged = 'The file changed after the scan.'
            OriginalFilePresent = 'The file remains or has reappeared at its original location.'
            ActionDone = 'Completed  {0}'
            ActionFailed = 'Incomplete  {0} | {1}'
            BackupSaved = 'Backup  {0}'
            BackupPathRequired = 'Enter the backup path shown by the checker.'
            BackupUnreadable = 'This is not a readable checker backup.'
            BackupFormatUnknown = 'Could not verify the backup format.'
            BackupMismatch = 'The file hash or the original path does not match the backup.'
            FileRestore = 'Restore file  {0}'
            RegistryRestore = 'Restore default value  {0} [{1}]'
            BeforeRestore = 'Restore only after confirming a false positive. Existing files or values at the original location will be kept.'
            ConfirmRestore = 'Type RESTORE to restore this item'
            RestoreCancelled = 'Restore cancelled.'
            RestoreDone = 'Restored.'
            WindowsOnly = 'Run this tool on Windows.'
            RestoreFailed = 'Restore incomplete  {0}'
            Title = 'NIKKE PC Launcher Check'
            Author = 'Author Serio_ai'
            ScanTime = 'Scan time {0:yyyy-MM-dd HH:mm:ss zzz}'
            ScanIntro = 'The scan reads records for this Windows account and saves a log.'
            LogSection = '=== Launcher logs ==='
            DebugLogFile = '[Log] {0} | Modified {1}'
            NoDebugLogs = 'No readable launcher logs (debug.log) were found.'
            CacheSection = '=== Launcher cache ==='
            ProfileLinkSkipped = 'Skipped a profile link'
            NoCache = 'No readable launcher cache was found.'
            ChromeSection = '=== Chrome DLLs and user registry ==='
            ScanInterrupted = 'An error may have skipped later checks'
            ScriptLine = '{0} | Script line {1}'
            StopLauncher = 'Close the NIKKE PC launcher, including its icon in the notification area. Leave it closed until cleanup is complete.'
            PreserveEvidence = 'Save the scan log before deleting files. If your antivirus detected the same file, save the detection record too. On a work PC, contact your security team before cleanup.'
            RemoveLauncher = 'On a personal PC, if NIKKE is still installed, uninstall it in Settings → Apps → Installed apps (Apps & features on Windows 10).'
            RemoveCache = 'On a personal PC, if a tbs_cache folder listed below remains after uninstalling the launcher, delete only that folder.'
            ReinstallLauncher = 'After cleanup, check the official NIKKE notice for the fixed launcher and installation instructions. Download the installer from the official site. If malicious files or traces of automatic startup remain, wait before reinstalling.'
            Disconnect = 'Turn off Wi-Fi. Unplug the network cable if one is connected.'
            ProtectAccounts = 'From another trusted device, change passwords for email, NIKKE/Level Infinite, and important accounts you used on this PC or saved in its browser. Use each service''s security settings to sign out all devices and turn on two-step verification.'
            RotateKeys = 'Revoke and replace any exposed API or SSH keys. If a crypto wallet recovery phrase may have been exposed, create a new wallet on a trusted device.'
            RunAntivirus = 'On a personal PC, open Windows Security → Virus & threat protection → Scan options and run a full scan. If you use another antivirus, scan with that tool.'
            ReviewQuarantine = 'On a personal PC, compare Windows Security''s Protection history with the paths in the scan log. If action is needed, choose Quarantine. If the same threat is already quarantined and you have saved its record, choose Remove.'
            CleanInstallPrepare = 'A clean install of Windows is recommended if you find signs of execution or automatic startup. Save the documents, photos and scan records you need to another drive. If BitLocker is enabled, save its recovery key too.'
            CleanInstallUsb = 'On a trusted PC, create an official Microsoft Windows installation USB. Plug it into the affected PC and boot from it. In Windows Setup, identify the drive that held Windows before starting a clean install. The selected drive will be erased.'
            CleanInstallRestore = 'After installation, copy back your documents and photos. Avoid restoring old executables, browser profiles, or a full Windows backup as-is.'
            Results = 'Scan results'
            ResultExecution = 'Found signs that malware ran.'
            ResultPersistence = 'Found files or settings that could let malware run again in Chrome.'
            UnknownDisclosure = 'This scan cannot tell whether any data was stolen.'
            ResultDownload = 'Found a suspicious file or a download record. Execution could not be verified.'
            ProtectIfExecutionPossible = 'If the malware may have run, secure your accounts first.'
            CheckAgain = 'Scan again after cleanup. If malicious files remain, or you find signs of execution or automatic startup in Chrome, keep the PC offline and consider a clean Windows install. The scan log links to installation instructions.'
            ResultRequest = 'Found a malware download address. The scan could not verify whether the file was downloaded or run.'
            ResultExposure = 'Found signs of exposure to a malicious script. Execution of the malware could not be verified.'
            ResultInconclusive = 'Inconclusive. There are too few readable records or some items need further review.'
            CheckAccountAndPath = 'Make sure you are using the Windows account you used for NIKKE. If you know where NIKKE is installed, drag its installation folder onto Run-Nikke-Check.bat to scan again.'
            ResultNoTraces = 'No known signs of infection were found in the records checked.'
            MissingHistory = 'Deleted records can make past infections difficult to detect.'
            UncheckedCount = 'The scan could not check {0} item(s). See the log for details.'
            NextSteps = 'What to do next'
            AffectedCaches = 'Launcher cache folders with findings'
            ScopeAndSources = 'Scan scope and references'
            FileCounts = 'Files checked. Launcher logs: {0}, cache: {1}, download folder (tinyget): {2}.'
            ScopeLimits = 'The scan covers default folders for this account and NIKKE installation folders it can find. Archives, other Chrome profiles, other Windows accounts and Proton may fall outside its scope.'
            EvidenceLimits = 'The scan checks records that remain. An absence of traces cannot establish whether an infection or data theft occurred in the past.'
            LogPrivacy = 'Before sharing the log, check paths for personal information such as your name.'
            IndicatorsSource = 'Indicators used'
            AnalysisSource = 'Incident analysis'
            OfficialNotice = 'Official NIKKE notice'
            AppRemovalSource = 'Uninstall apps in Windows'
            ProtectionHistorySource = 'Windows Security Protection history'
            InstallWindowsSource = 'Microsoft Windows installation guide'
            LogLocation = 'Scan log saved to'
            LogSaveFailed = 'Could not save the log. Put both files in a folder you can write to, such as your desktop, then try again.'
            ActionsStopped = 'Optional actions stopped  {0}'
            ActionLogFailed = 'Could not add the action results to the log. Keep the backup path shown on screen.'
        }
    }
}

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
    Write-Report ($messages.Gap -f $Path, $Reason)
}

function Get-ScanItem([string]$Path) {
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            Add-Gap $Path $messages.ReparseSkipped
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
            Add-Gap $child.FullName $messages.ReparseSkipped
        } elseif (!$child.PSIsContainer) {
            $child
        } elseif ($Depth -gt 0) {
            Get-ScanFiles $child.FullName ($Depth - 1)
        } else {
            Add-Gap $child.FullName $messages.DepthLimit
        }
    }
}

function Read-Artifact([IO.FileInfo]$File) {
    try {
        $sharing = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
        $stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, $sharing)
        try {
            if ($stream.Length -gt 32MB) {
                Add-Gap $File.FullName $messages.SizeLimit
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
        if ($content -match 'k2f\.agent\.state') { Add-Finding Execution $messages.CacheExecution $path }
        return
    }
    if ($content -match $loaderUrl -or $content -match '(?i)(?<![\w.-])(?:analytics\.)?insightjs\.(?:com|org)(?![\w.-])') {
        Add-Finding Exposure $messages.CacheExposure $path
    } elseif ($Kind -eq 'Code' -and $File.Name -in $loaderCacheNames) {
        Add-Finding Review $messages.CacheNameOnly $path
    }
    if ($content -match $payloadUrl) { Add-Finding Request $messages.CacheRequest $path }
    if ($loaderHashes.ContainsKey($bytes.Length) -and (Get-BytesHash $bytes) -eq $loaderHashes[$bytes.Length]) {
        Add-Finding Exposure $messages.LoaderHash $path
    }
    if ($payloadHashes.ContainsKey($bytes.Length) -and (Get-BytesHash $bytes) -eq $payloadHashes[$bytes.Length]) {
        Add-Finding Download $messages.PayloadHash $path
    }
}

function Test-LauncherFile([IO.FileInfo]$File, [string]$Kind) {
    $bytes = Read-Artifact $File
    if ($null -eq $bytes) { return }
    $path = $File.FullName
    if ($Kind -eq 'Debug') { $scan.DebugLogs++ } else { $scan.PayloadFiles++ }

    if ($payloadHashes.ContainsKey($bytes.Length) -and (Get-BytesHash $bytes) -eq $payloadHashes[$bytes.Length]) {
        Add-Finding Download $messages.PayloadHash $path
        if ($OfferRemediation -and $Kind -eq 'Tinyget') { $payloadCandidates[$path] = $payloadHashes[$bytes.Length] }
        return
    }
    if ($Kind -eq 'Tinyget' -and $bytes.Length -ge 3 -and $bytes[0] -eq 27 -and $bytes[1] -eq 76 -and $bytes[2] -eq 74) {
        Add-Finding Download $messages.PayloadPattern $path
        return
    }
    $content = Get-ArtifactText $bytes
    if ($Kind -eq 'Debug') {
        $count = [regex]::Matches($content, '(?i)\bk2f_chan\s+registered\b|\bagent started as\s+\S+').Count
        if ($count) { Add-Finding Execution ($messages.LogExecution -f $count) $path }
        if ($content -match '(?i)\bk2f_chan\s+registered\b') { $scan.ConfirmedExecution = $true }
    }
    if ($content -match $payloadUrl) { Add-Finding Request $messages.LogRequest $path }
    if ($content -match '(?i)\blua downloaded to\s+log[\\/]tinyget[\\/]') {
        Add-Finding Download $messages.LogDownload $path
    }
}

function Get-LauncherDirectories {
    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($InstallPath -match '^[\\/]{2}') {
        Add-Gap $InstallPath $messages.LocalInstallPath
    } elseif ($InstallPath) {
        $requested = Get-ScanItem $InstallPath
        if ($requested -and $requested.PSIsContainer) { $candidates.Add($requested.FullName) }
        else { Add-Gap $InstallPath $messages.InstallPathUnreadable }
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
                if ($denied) { Add-Gap $label ($messages.InstallEntriesUnreadable -f $denied) }
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
        if ($candidate -notmatch '^[A-Za-z]:[\\/]') { Add-Gap $candidate $messages.LocalScanOnly; continue }
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
            if (!$key) { Write-Report ($messages.NotFound -f $label); continue }
            $server = $key.OpenSubKey('InprocServer32', $false)
            $target = if ($server) { [string]$server.GetValue('', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
            if ($target -match '(?i)[\\/]platform_experience_helper\.dll"?\s*$') {
                Add-Finding Persistence $messages.ChromeRegistered $label
                if ($OfferRemediation) {
                    $kind = $server.GetValueKind('')
                    $dllPath = [Environment]::ExpandEnvironmentVariables($target.Trim('"'))
                    if ($kind -in 'String','ExpandString' -and (Test-ActionChromePath $dllPath)) {
                        $registeredDlls.Add(@{ Kind = 'Registry'; Path = "HKCU\$chromeValuePath"; Dll = $dllPath; Value = $target; ValueKind = [string]$kind; View = [string]$view })
                    }
                }
            } else {
                Add-Finding Review $messages.ChromeRegistryReview $label
            }
        } catch { Add-Gap $label $_.Exception.GetType().Name }
        finally {
            foreach ($handle in $server, $key, $baseKey) { if ($handle) { $handle.Dispose() } }
        }
    }
    foreach ($local in $localPaths) {
        $userHelper = Join-Path $local 'Google\Chrome\User Data\PlatformExperienceHelper'
        Write-Report ($messages.Scope -f $userHelper)
        foreach ($file in Get-ScanFiles $userHelper 2) {
            if ($file.Name -eq 'platform_experience_helper.dll' -and $file.Directory.Name -match '^[0-9a-f]{64}$') {
                Add-Finding Persistence $messages.ChromeDll $file.FullName
            } elseif ($file.Name -in 'platform_experience_helper.dll', 'service_util.dll') {
                Add-Finding Review $messages.ChromeUserReview $file.FullName
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
            Write-Report ($messages.Scope -f $location)
            foreach ($file in Get-ScanFiles $location 2) {
                if ($file.Name -in 'platform_experience_helper.dll', 'service_util.dll') {
                    Add-Finding Review $messages.ChromeInstallReview $file.FullName
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
        throw $messages.UnsafePath
    }
    for ($part = $Path; $part; $part = [IO.Path]::GetDirectoryName($part)) {
        try { $entry = Get-Item -LiteralPath $part -Force -ErrorAction Stop }
        catch [System.Management.Automation.ItemNotFoundException] { continue }
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw $messages.ReparsePath
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

    private static void CheckHandle(SafeFileHandle handle, string path, string unsafeFile, string pathMismatch) {
        FileInfo info;
        if (!GetFileInformationByHandle(handle, out info)) throw new Win32Exception();
        if ((info.Attributes & 0x410) != 0 || info.Links != 1)
            throw new IOException(unsafeFile);
        var final = new StringBuilder(32768);
        uint length = GetFinalPathNameByHandleW(handle, final, (uint)final.Capacity, 0);
        if (length == 0) throw new Win32Exception();
        if (length >= final.Capacity || !String.Equals(final.ToString(), @"\\?\" + path, StringComparison.OrdinalIgnoreCase))
            throw new IOException(pathMismatch);
    }

    public static FileStream OpenForQuarantine(string path, string unsafeFile, string pathMismatch) {
        var handle = CreateFileW(path, GenericRead | DeleteAccess, 0, IntPtr.Zero, OpenExisting, OpenReparsePoint, IntPtr.Zero);
        try {
            if (handle.IsInvalid) throw new Win32Exception();
            CheckHandle(handle, path, unsafeFile, pathMismatch);
            return new FileStream(handle, FileAccess.Read);
        } catch { handle.Dispose(); throw; }
    }

    private static void MarkForRemoval(SafeFileHandle handle) {
        byte remove = 1;
        if (!SetFileInformationByHandle(handle, 4, ref remove, 1)) throw new Win32Exception();
    }

    public static void Quarantine(FileStream file) { MarkForRemoval(file.SafeFileHandle); }

    public static void Restore(string path, byte[] bytes, string unsafeFile, string pathMismatch) {
        using (var handle = CreateFileW(path, GenericRead | GenericWrite | DeleteAccess, 0, IntPtr.Zero, CreateNew, OpenReparsePoint, IntPtr.Zero)) {
            if (handle.IsInvalid) throw new Win32Exception();
            try { CheckHandle(handle, path, unsafeFile, pathMismatch); }
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
        throw $messages.BackupVerificationFailed
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
        @{ Kind = 'File'; Path = $path; Hash = $verifiedDlls[$path]; Evidence = $messages.ChromeActionEvidence }
    }
    if ($scan.ConfirmedExecution -or $verifiedDlls.Count) {
        foreach ($path in $payloadCandidates.Keys) {
            @{ Kind = 'File'; Path = $path; Hash = $payloadCandidates[$path]; Evidence = $messages.PayloadActionEvidence }
        }
    }
}

function Invoke-RegistryAction([System.Collections.IDictionary]$Record, [string]$Backup, [switch]$Restore) {
    if ($Record.Path -cne "HKCU\$chromeValuePath" -or $Record.View -notin $registryViews -or
        $Record.ValueKind -notin 'String','ExpandString' -or
        [Environment]::ExpandEnvironmentVariables(([string]$Record.Value).Trim('"')) -cne $Record.Dll -or
        !(Test-ActionChromePath $Record.Dll)) {
        throw $messages.RegistryTargetMismatch
    }
    Assert-LocalActionPath $Record.Dll
    $view = [Microsoft.Win32.RegistryView]$Record.View
    $kind = [Microsoft.Win32.RegistryValueKind]$Record.ValueKind
    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey('CurrentUser', $view)
    $key = $null
    try {
        $key = $baseKey.OpenSubKey($chromeValuePath, $true)
        if (!$key) { throw $messages.RegistryKeyUnreadable }
        $options = [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        if ($Restore) {
            if ('' -in $key.GetValueNames()) { throw $messages.RegistryValueExists }
            $key.SetValue('', $Record.Value, $kind)
            if ($key.GetValue('', $null, $options) -cne $Record.Value -or $key.GetValueKind('') -ne $kind) {
                throw $messages.RegistryRestoreUnverified
            }
        } else {
            if ($key.GetValue('', $null, $options) -cne $Record.Value -or $key.GetValueKind('') -ne $kind) {
                throw $messages.RegistryValueChanged
            }
            Save-ActionBackup $Record $Backup
            if ($key.GetValue('', $null, $options) -cne $Record.Value -or $key.GetValueKind('') -ne $kind) {
                throw $messages.RegistryValueChangedDuringBackup
            }
            $key.DeleteValue('', $true)
            if ('' -in $key.GetValueNames()) { throw $messages.RegistryRemovalUnverified }
        }
    } finally {
        if ($key) { $key.Dispose() }
        $baseKey.Dispose()
    }
}

function Show-RecoveryCommand([string]$Path) {
    Write-Host $messages.RecoveryInstructions
    Write-Host ('.\Run-Nikke-Check.bat -Language {0} -Restore "{1}"' -f $Language, $Path)
}

function Invoke-ConfirmedActions {
    $items = @(Get-RemediationItems)
    if (!$items.Count) {
        Write-Report $messages.NoActionTargets -Show
        return
    }
    Write-Report $messages.OptionalActions -Show
    Write-Report $messages.BeforeActions -Show
    foreach ($item in $items) {
        $backup = Join-Path $backupRoot ([Guid]::NewGuid().ToString('N') + '.nikke-backup')
        Write-Host ''
        if ($item.Kind -eq 'File') {
            Write-Host ($messages.FileQuarantine -f $item.Path)
            Write-Host $item.Evidence
            Write-Host "SHA-256  $($item.Hash)"
            Write-Host $messages.FileQuarantineEffect
        } else {
            Write-Host ($messages.RegistryRemove -f $item.Path, $item.View)
            Write-Host ($messages.RegistryDll -f $item.Dll)
            Write-Host $messages.RegistryRemoveEffect
        }
        Write-Host ($messages.BackupFile -f $backup)
        Show-RecoveryCommand $backup
        if ((Read-Host $messages.ConfirmAction) -ine 'Y') {
            Write-Report ($messages.ActionSkipped -f $item.Path) -Show
            continue
        }
        try {
            Initialize-ResponseTools
            if ($item.Kind -eq 'File') {
                Assert-LocalActionPath $item.Path
                $stream = [NikkeCheckedFile]::OpenForQuarantine($item.Path, $messages.UnsafeFileHandle, $messages.OpenedPathMismatch)
                try {
                    if ($stream.Length -gt 1MB) { throw $messages.ActionSizeLimit }
                    $bytes = [byte[]]::new([int]$stream.Length)
                    for ($offset = 0; $offset -lt $bytes.Length; $offset += $read) {
                        $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
                        if (!$read) { throw $messages.FileReadIncomplete }
                    }
                    if ((Get-BytesHash $bytes) -ne $item.Hash) { throw $messages.FileChanged }
                    Save-ActionBackup @{ Kind = 'File'; Path = $item.Path; Hash = $item.Hash; Data = [Convert]::ToBase64String($bytes) } $backup
                    [NikkeCheckedFile]::Quarantine($stream)
                } finally { $stream.Dispose() }
                if (Test-Path -LiteralPath $item.Path) { throw $messages.OriginalFilePresent }
            } else {
                Invoke-RegistryAction $item $backup
            }
            Write-Report ($messages.ActionDone -f $item.Path) -Show
        } catch {
            Write-Report ($messages.ActionFailed -f $item.Path, $_.Exception.GetBaseException().Message) -Show
            $scan.Issues++
        } finally {
            if ([IO.File]::Exists($backup)) { Write-Report ($messages.BackupSaved -f $backup) -Show }
        }
    }
}

function Restore-ActionBackup([string]$Path) {
    if ([IO.Path]::GetDirectoryName($Path) -ine $backupRoot -or [IO.Path]::GetFileName($Path) -notmatch '^[0-9a-f]{32}\.nikke-backup$') {
        throw $messages.BackupPathRequired
    }
    Assert-LocalActionPath $Path
    $file = Get-Item -LiteralPath $Path -Force
    if ($file.PSIsContainer -or $file.Length -gt 2MB) { throw $messages.BackupUnreadable }
    Initialize-ResponseTools
    $encrypted = [IO.File]::ReadAllBytes($Path)
    $plain = [Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, 'CurrentUser')
    $data = [Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json
    if ($data.Version -ne 1 -or $data.Kind -notin 'File','Registry') { throw $messages.BackupFormatUnknown }
    if ($data.Kind -eq 'File') {
        Assert-LocalActionPath $data.Path
        $bytes = [Convert]::FromBase64String($data.Data)
        $knownPayload = $payloadHashes.ContainsKey($bytes.Length) -and $payloadHashes[$bytes.Length] -eq $data.Hash -and
            $data.Path -match '\\log\\tinyget\\'
        $knownDll = (Test-ActionChromePath $data.Path) -and
            [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($data.Path)) -eq $data.Hash
        if ($bytes.Length -gt 1MB -or (Get-BytesHash $bytes) -ne $data.Hash -or !($knownPayload -or $knownDll)) {
            throw $messages.BackupMismatch
        }
        Write-Host ($messages.FileRestore -f $data.Path)
    } else {
        Write-Host ($messages.RegistryRestore -f $data.Path, $data.View)
        Write-Host ($messages.RegistryDll -f $data.Dll)
    }
    Write-Host $messages.BeforeRestore
    if ((Read-Host $messages.ConfirmRestore) -cne 'RESTORE') {
        Write-Host $messages.RestoreCancelled
        return
    }
    if ($data.Kind -eq 'File') {
        Assert-LocalActionPath $data.Path
        [NikkeCheckedFile]::Restore($data.Path, $bytes, $messages.UnsafeFileHandle, $messages.OpenedPathMismatch)
    } else {
        $record = @{}
        foreach ($property in $data.PSObject.Properties) { $record[$property.Name] = $property.Value }
        Invoke-RegistryAction $record -Restore
    }
    Write-Host $messages.RestoreDone
}

if ($env:OS -ne 'Windows_NT') { throw $messages.WindowsOnly }
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
        Write-Host ($messages.RestoreFailed -f $_.Exception.GetBaseException().Message)
        exit 2
    }
    exit 0
}
Write-Report $messages.Title -Show
Write-Report $messages.Author -Show
Write-Report ($messages.ScanTime -f [DateTimeOffset]::Now)
Write-Report $messages.ScanIntro -Show
$headerLineCount = $lines.Count

try {
    Write-Report ("`n" + $messages.LogSection)
    $checked = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($root in Get-LauncherDirectories) {
        foreach ($launcher in $root, (Join-Path $root 'Launcher')) {
            if (!$checked.Add($launcher)) { continue }
            $debug = Get-ScanItem (Join-Path $launcher 'intl_service\debug.log')
            if ($debug -and !$debug.PSIsContainer) {
                Write-Report ($messages.DebugLogFile -f $debug.FullName, $debug.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))
                Test-LauncherFile $debug 'Debug'
            }
            foreach ($file in Get-ScanFiles (Join-Path $launcher 'log\tinyget') 1) { Test-LauncherFile $file 'Tinyget' }
        }
    }
    if (!$scan.DebugLogs) { Write-Report $messages.NoDebugLogs }

    Write-Report ("`n" + $messages.CacheSection)
    $profileRoots = @($roamingPath; $localPaths) | Where-Object { $_ } | Select-Object -Unique
    foreach ($root in $profileRoots) {
        Write-Report ($messages.Scope -f "$root\nikke_launcher*\tbs_cache")
        try {
            $profiles = @(Get-ChildItem -LiteralPath $root -Filter 'nikke_launcher*' -Directory -Force -ErrorAction Stop)
        } catch { Add-Gap $root $_.CategoryInfo.Category.ToString(); continue }
        foreach ($profile in $profiles) {
            if ($profile.Attributes -band [IO.FileAttributes]::ReparsePoint) { Add-Gap $profile.FullName $messages.ProfileLinkSkipped; continue }
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
    if (!$scan.CacheFiles) { Write-Report $messages.NoCache }

    Write-Report ("`n" + $messages.ChromeSection)
    Test-ChromePersistence
} catch {
    Add-Gap $messages.ScanInterrupted ($messages.ScriptLine -f $_.Exception.GetType().Name, $_.InvocationInfo.ScriptLineNumber)
}
$detailLineCount = $lines.Count - $headerLineCount
$details = $lines.GetRange($headerLineCount, $detailLineCount)
$lines.RemoveRange($headerLineCount, $detailLineCount)

$stopLauncher = $messages.StopLauncher
$preserve = $messages.PreserveEvidence
$removeLauncher = @($messages.RemoveLauncher)
if ($affectedCaches.Count) {
    $removeLauncher += $messages.RemoveCache
}
$reinstallLauncher = $messages.ReinstallLauncher
$isolate = @(
    $messages.Disconnect
    $stopLauncher
    $preserve
)
$accounts = $messages.ProtectAccounts
$keys = $messages.RotateKeys
$scanForThreats = $messages.RunAntivirus
$reviewQuarantine = $messages.ReviewQuarantine
$reinstall = @(
    $messages.CleanInstallPrepare
    $messages.CleanInstallUsb
    $messages.CleanInstallRestore
)

Write-Report ("`n" + $messages.Results) -Show
if ($hits.Execution -or $hits.Persistence) {
    if ($hits.Execution) { Write-Report $messages.ResultExecution -Show }
    if ($hits.Persistence) { Write-Report $messages.ResultPersistence -Show }
    Write-Report $messages.UnknownDisclosure -Show
    $steps = $isolate + $accounts + $keys + $scanForThreats + $reviewQuarantine + $removeLauncher + $reinstall + $reinstallLauncher
} elseif ($hits.Download) {
    Write-Report $messages.ResultDownload -Show
    $steps = $isolate + ($messages.ProtectIfExecutionPossible + ' ' + $accounts) +
        $scanForThreats + $reviewQuarantine + $removeLauncher +
        $messages.CheckAgain + $reinstallLauncher
} elseif ($hits.Request) {
    Write-Report $messages.ResultRequest -Show
    $steps = @($stopLauncher, $preserve) + $removeLauncher + $reinstallLauncher
} elseif ($hits.Exposure) {
    Write-Report $messages.ResultExposure -Show
    $steps = @($stopLauncher, $preserve) + $removeLauncher + $reinstallLauncher
} elseif ($hits.Review -or $scan.Issues -or (!$scan.DebugLogs -and !$scan.CacheFiles -and !$scan.PayloadFiles)) {
    Write-Report $messages.ResultInconclusive -Show
    $steps = @($messages.CheckAccountAndPath)
} else {
    Write-Report $messages.ResultNoTraces -Show
    Write-Report $messages.MissingHistory -Show
    $steps = @()
}
if ($scan.Issues) { Write-Report ($messages.UncheckedCount -f $scan.Issues) -Show }

if ($steps.Count) {
    Write-Report ("`n" + $messages.NextSteps) -Show
    for ($index = 0; $index -lt $steps.Count; $index++) {
        Write-Report ('{0}. {1}' -f ($index + 1), $steps[$index]) -Show
    }
}
if ($affectedCaches.Count) {
    Write-Report ("`n" + $messages.AffectedCaches) -Show
    foreach ($cache in $affectedCaches) { Write-Report $cache -Show }
}

$lines.AddRange($details)
Write-Report ("`n" + $messages.ScopeAndSources)
Write-Report (($hits.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value }) -join '  ')
Write-Report ($messages.FileCounts -f $scan.DebugLogs, $scan.CacheFiles, $scan.PayloadFiles)
Write-Report $messages.ScopeLimits
Write-Report $messages.EvidenceLimits
Write-Report $messages.LogPrivacy
Write-Report ($messages.IndicatorsSource + ' https://github.com/MotherSphere/NIKKE-Launcher-Check/blob/main/docs/incident.md#indicators-of-compromise')
Write-Report ($messages.AnalysisSource + ' https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5')
Write-Report ($messages.OfficialNotice + ' https://x.com/NIKKE_kr/status/2117817404399210900')
Write-Report ($messages.AppRemovalSource + ' https://support.microsoft.com/en-gb/windows/apps/uninstall-or-remove-apps-and-programs-in-windows')
Write-Report ($messages.ProtectionHistorySource + ' https://support.microsoft.com/en-us/windows/security/windows-security/protection-history-in-the-windows-security-app')
Write-Report ($messages.InstallWindowsSource + ' https://support.microsoft.com/en-us/windows/deployment/install-upgrade/reinstall-windows-with-the-installation-media')

try {
    $LogDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogDirectory)
    $null = [IO.Directory]::CreateDirectory($LogDirectory)
    $logPath = Join-Path $LogDirectory ('Nikke-Check-{0:yyyyMMdd-HHmmss-fff}-{1}.txt' -f [DateTime]::Now, $PID)
    [IO.File]::WriteAllLines($logPath, $lines.ToArray(), [Text.UTF8Encoding]::new($true))
    Write-Host ("`n{0}`n{1}" -f $messages.LogLocation, $logPath)
} catch {
    Write-Host $messages.LogSaveFailed
    exit 2
}
if ($OfferRemediation -and ($scan.ConfirmedExecution -or $registeredDlls.Count)) {
    $firstActionLine = $lines.Count
    try { Invoke-ConfirmedActions }
    catch {
        Write-Report ($messages.ActionsStopped -f $_.Exception.GetBaseException().Message) -Show
        $scan.Issues++
    }
    try { [IO.File]::AppendAllLines($logPath, $lines.GetRange($firstActionLine, $lines.Count - $firstActionLine)) }
    catch {
        Write-Host $messages.ActionLogFailed
        exit 2
    }
}
if ($scan.Issues) { exit 1 }
exit 0

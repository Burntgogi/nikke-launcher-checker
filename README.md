# NIKKE Launcher Checker

니케 PC 런처 침해 사건의 알려진 흔적을 Windows에서 확인하는 도구입니다. 제작자는 **Serio_ai**입니다.

[설명 페이지](https://burntgogi.github.io/nikke-launcher-checker/) · [점검 도구 ZIP 받기](https://burntgogi.github.io/nikke-launcher-checker/Nikke-Launcher-Checker.zip)

![작동 순서. 배치 파일 실행, 현재 계정의 런처와 Chrome 기록 읽기, 결과 표시와 로그 저장.](docs/check-flow.svg)

## 실행

1. ZIP을 풀고 `Run-Nikke-Check.bat`와 `Check-Nikke.ps1`을 같은 폴더에 둡니다.
2. 니케를 사용한 Windows 계정에서 배치 파일을 두 번 클릭합니다. 설치 폴더가 따로 있으면 그 폴더를 배치 파일 위로 끌어 놓습니다.
3. 화면의 **지금 할 일**을 확인합니다. 상세 결과는 `logs` 폴더에 저장됩니다.

Windows PowerShell 5.1 이상에서 실행합니다. 도구는 점검 로그만 저장하며 런처를 실행하거나 시스템 설정을 바꾸지 않습니다. 배치 파일의 실행 정책 옵션은 그 배치가 시작한 PowerShell에만 적용됩니다.

## 결과별 첫 조치

| 결과 | 할 일 |
| --- | --- |
| 실행 또는 Chrome 자동 실행 흔적 | Wi-Fi를 끄고 연결된 인터넷 케이블을 뽑으세요. 다른 기기에서 비밀번호를 바꾸고 기존 로그인을 종료하세요. 점검 로그와 필요한 파일을 보관한 뒤 Windows 클린 설치를 검토하세요. |
| 다운로드 흔적 | 인터넷 연결을 끊고 점검 로그를 보관하세요. 악성코드가 실행됐는지는 추가 확인이 필요합니다. |
| 노출 또는 다운로드 주소 | 런처를 다시 열지 말고 공식 업데이트 안내를 확인하세요. 주소가 남아 있어도 파일을 받았는지는 알 수 없습니다. |
| 판정 보류 | 니케를 사용한 Windows 계정과 실제 설치 폴더에서 다시 확인하세요. |
| 흔적 미발견 | 읽은 자료에서 알려진 흔적을 찾지 못했습니다. 지워졌거나 읽지 못한 기록은 확인 범위에서 빠집니다. |

이 도구는 현재 Windows 계정에 남은 기록을 읽습니다. 과거 감염이나 정보 유출 여부는 이 결과만으로 알 수 없습니다. 로그를 공유할 때는 설치 경로에 이름 등 개인정보가 들어 있는지 확인하세요.

## 참고 자료

### 점검 지표

이 도구는 공개 자료에 나온 런처 로그의 실행 문자열, 캐시 파일과 다운로드 주소, 파일 지문(SHA-256), Chrome의 의심 DLL 경로와 사용자 레지스트리를 대조합니다. 다운로드 주소와 파일 저장 기록, 실제 실행 기록은 각각 구분합니다.

- 지표 목록과 흔적이 남는 위치. [MotherSphere의 침해 지표 목록](https://github.com/MotherSphere/NIKKE-Launcher-Check/blob/main/docs/incident.md#indicators-of-compromise)
- 배포 경로와 악성코드 분석, 추가 해시와 이용자 관측 기록. [MotherSphere의 니케 PC 런처 분석 보고서](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5)

### 사건 경과

- 운영진이 밝힌 클라이언트 수정 시점과 영향 범위 조사 안내. [니케 PC 런처 이상 상황 공지](https://x.com/NIKKE_kr/status/2117817404399210900) · [엑스포츠뉴스의 공지 인용 보도](https://www.xportsnews.com/article/2215288)
- 수정 발표와 별도로 일부 CDN 노드의 배포 파일을 다시 확인한 기록. [Iwassoobsessedwith의 후속 관측](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5#gistcomment-6456165)

### 대응과 복구

- 개인 PC를 새로 설치할 때 필요한 준비와 절차. [Microsoft Windows 클린 설치 안내](https://support.microsoft.com/en-us/windows/deployment/install-upgrade/reinstall-windows-with-the-installation-media)
- 조직의 사고 조사, 격리와 복구. [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) · [CISA 사고 대응 절차](https://www.cisa.gov/sites/default/files/2024-08/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf)
- 업무 계정의 세션과 접근 권한 회수. [Microsoft Entra ID 긴급 접근 회수 안내](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access)
- 아웃바운드 방화벽 규칙의 작성과 적용 상태 확인. [New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule) · [Get-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule) · [Windows 방화벽 규칙 우선순위](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules)
- 국내 사업자의 사고 신고와 개인정보 유출 통지·신고. [KrCERT/CC 침해사고 신고 안내](https://www.krcert.or.kr/kr/subPage.do?menuNo=205033) · [개인정보 포털 유출 신고 안내](https://www.privacy.go.kr/front/wcp/spl/splRptInfo.do) · [개인정보 보호법 시행령](https://law.go.kr/lsInfoP.do?ancYnChk=0&lsId=011468)

## 감사 인사

분석과 점검 지표를 공개한 MotherSphere, 그리고 런처 로그와 캐시, CDN 응답을 공유해 주신 분들께 감사드립니다.

# NIKKE Launcher Checker

니케 PC 런처 침해 사건의 알려진 흔적을 Windows에서 확인하는 도구입니다. 제작자는 **Serio_ai**입니다.

[설명 페이지](https://burntgogi.github.io/nikke-launcher-checker/) · [ZIP 받기](https://github.com/Burntgogi/nikke-launcher-checker/archive/refs/heads/main.zip)

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

[판정에 사용한 침해 지표](https://github.com/MotherSphere/NIKKE-Launcher-Check/blob/main/docs/incident.md#indicators-of-compromise) · [Microsoft Windows 클린 설치 안내](https://support.microsoft.com/en-us/windows/deployment/install-upgrade/reinstall-windows-with-the-installation-media)

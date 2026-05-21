# evasion_patcher

Windows EXE 악성코드의 **샌드박스 회피 기법을 자동으로 탐지·패치**하는 정적/런타임 분석 도구.

패치된 바이너리를 Triage 등 샌드박스에 제출하면 회피 기법 없이 실제 악성 행위를 관찰할 수 있다.

---

## 탐지 대상

| 카테고리 | 기법 | 세부 내용 |
|---|---|---|
| `sleep` | RDTSC | `0F 31` — 실행 시간 측정으로 sandbox timeout 유도 |
| `sleep` | Sleep / SleepEx | 수 분~수 시간 sleep으로 분석 시간 소진 |
| `sleep` | NtDelayExecution | 저수준 Sleep (커널 직접 호출) |
| `sleep` | GetTickCount(64) | 경과 시간 비교로 sandbox 판단 |
| `vm` | CPUID | ECX bit31(하이퍼바이저 비트)으로 VM 탐지 |
| `vm` | VM 문자열 | VMware·VBox·QEMU·Cuckoo·Triage 아티팩트 문자열 |
| `vm` | RegOpenKeyEx | VM 전용 레지스트리 키 확인 |
| `vm` | GetModuleHandle | vmtoolsd·vboxservice 모듈 로드 여부 확인 |
| `userinput` | GetCursorPos | 마우스 움직임 없음 = sandbox |
| `userinput` | GetAsyncKeyState | 키 입력 없음 = sandbox |
| `userinput` | GetSystemMetrics | 화면 해상도가 낮음 = sandbox |
| `userinput` | GetLastInputInfo | 마지막 입력 시간이 오래됨 = sandbox |
| `antidebug` | IsDebuggerPresent | 기본 디버거 탐지 |
| `antidebug` | CheckRemoteDebuggerPresent | 원격 디버거 탐지 |
| `antidebug` | NtQueryInformationProcess | ProcessDebugPort / ProcessDebugFlags |
| `antidebug` | FindWindow | OllyDbg·x64dbg 윈도우 탐색 |

---

## 설치

```bash
pip install -r requirements.txt
```

**요구사항**: Python 3.11+, Windows (Frida 훅은 분석 대상과 같은 머신에서 실행)

---

## 테스트

### 환경 준비

```bash
# 1. 의존성 설치
pip install -r requirements.txt

# 2. 예제 샘플 EXE 생성 (컴파일러 불필요 — Python으로 PE 직접 생성)
python samples/create_samples.py
```

```
샘플 PE32 파일 생성 중...

  ✔ sleep_evasion.exe          1536 bytes  [RDTSC×2, Sleep(600000), SleepEx(180000), GetTickCount+JZ]
  ✔ vm_evasion.exe             1536 bytes  [CPUID×2, GetModuleHandleA+JNZ, RegOpenKeyExA+JZ, CreateFileA+JNZ]
  ✔ userinput_evasion.exe      1536 bytes  [GetCursorPos+JZ, GetAsyncKeyState+JZ, GetSystemMetrics+JL, GetLastInputInfo+JZ]
  ✔ antidebug_evasion.exe      1536 bytes  [IsDebuggerPresent+JNZ, CheckRemote+JZ, NtQueryInfo+JZ, FindWindow+JNZ]
  ✔ combined_evasion.exe       1536 bytes  [sleep+vm+userinput+antidebug 복합]
```

---

### 테스트 1 — 카테고리별 탐지 확인 (dry-run)

각 샘플에 맞는 카테고리만 지정해서 탐지 결과를 확인한다. `--dry-run`이므로 파일은 수정되지 않는다.

```bash
# Sleep / 타이밍 회피
python patcher.py samples/sleep_evasion.exe -c sleep --dry-run

# VM / 환경 탐지
python patcher.py samples/vm_evasion.exe -c vm --dry-run

# 사용자 상호작용 체크
python patcher.py samples/userinput_evasion.exe -c userinput --dry-run

# 안티디버깅
python patcher.py samples/antidebug_evasion.exe -c antidebug --dry-run
```

**예상 출력 — `sleep_evasion.exe`**

```
[*] 회피 기법 탐지 중...
  sleep       4건 탐지

  총 4건 탐지 (4 패치 가능 / 0 수동 확인)

  ⏱  SLEEP
  VA            기법            설명                                 패치
  0x00401003    RDTSC           RDTSC 타이밍 체크 @ 0x00401003       ✔
  0x0040100A    Sleep           Sleep(600,000 ms) 호출 — 인자 패치   ✔
  0x00401016    SleepEx         SleepEx(180,000 ms) 호출 — 인자 패치 ✔
  0x00401022    GetTickCount    이후 Jcc @ 0x0040102A NOP            ✔

  [DRY RUN] 적용: 4  스킵: 0  오류: 0

  파일 오프셋   기법          패치 내용
  0x203         RDTSC         0f31 → 9090
  0x205         Sleep         68c0270900 → 6801000000
  0x20c         SleepEx       68203b0200 → 6801000000
  0x22a         GetTickCount  7408 → 9090
```

**체크포인트**
- `패치 가능` 수 = `적용` 수와 일치하는지 확인
- `스킵` > 0 이면 원본 바이트 불일치 (샘플 파일 재생성 필요)
- `오류` > 0 이면 오프셋 범위 초과 (PE 구조 이상)

---

### 테스트 2 — 전체 카테고리 복합 탐지

```bash
python patcher.py samples/combined_evasion.exe --dry-run
```

**예상 결과**

```
  sleep       4건 탐지    ← RDTSC, Sleep, GetTickCount, NtDelayExecution
  vm          3건 탐지    ← CPUID, GetModuleHandleA, RegOpenKeyExA
  userinput   2건 탐지    ← GetCursorPos, GetSystemMetrics
  antidebug   1건 탐지    ← IsDebuggerPresent

  총 10건 탐지 (10 패치 가능 / 0 수동 확인)
  [DRY RUN] 적용: 11  스킵: 0  오류: 0
```

> `탐지 10건 / 패치 11건`인 이유:  
> `IsDebuggerPresent`는 CALL 자체를 `XOR EAX,EAX`로 교체(1건) + 이후 Jcc NOP(1건) = 2개 PatchAction을 생성하기 때문.

---

### 테스트 3 — 실제 패치 적용 및 바이트 검증

패치를 실제로 적용하고, 이전/이후 바이트를 비교해 패치가 올바르게 들어갔는지 확인한다.

```bash
# 패치 적용
python patcher.py samples/sleep_evasion.exe \
    -o samples/sleep_patched.exe \
    -r samples/sleep_report.json \
    -c sleep
```

**패치 전/후 바이트 비교 (Python)**

```python
# verify_patch.py
orig   = open("samples/sleep_evasion.exe",  "rb").read()
patched = open("samples/sleep_patched.exe", "rb").read()

# RDTSC 패치 확인 (파일 오프셋 0x203)
offset = 0x203
print(f"RDTSC @ 0x{offset:X}")
print(f"  원본:  {orig[offset:offset+2].hex()}")    # 예상: 0f31
print(f"  패치후: {patched[offset:offset+2].hex()}") # 예상: 9090

# Sleep 인자 패치 확인 (파일 오프셋 0x205)
offset = 0x205
print(f"\nSleep arg @ 0x{offset:X}")
print(f"  원본:  {orig[offset:offset+5].hex()}")     # 예상: 68 c0270900 (600000)
print(f"  패치후: {patched[offset:offset+5].hex()}")  # 예상: 68 01000000 (1)
```

```
RDTSC @ 0x203
  원본:   0f31
  패치후:  9090

Sleep arg @ 0x205
  원본:   68c0270900
  패치후:  6801000000
```

---

### 테스트 4 — JSON 보고서 읽기

```bash
python patcher.py samples/combined_evasion.exe \
    -o samples/combined_patched.exe \
    -r samples/combined_report.json
```

생성된 `combined_report.json` 구조:

```json
{
  "generated": "2026-05-22T...",
  "target": "samples/combined_evasion.exe",
  "summary": {
    "total_findings": 10,
    "patchable": 10,
    "patch_applied": 11,
    "patch_skipped": 0
  },
  "findings": [
    {
      "category": "sleep",
      "technique": "RDTSC",
      "va": "0x401003",
      "file_offset": "0x203",
      "description": "RDTSC 타이밍 체크 @ 0x00401003",
      "patchable": true,
      "patch_actions": [
        {
          "file_offset": "0x203",
          "original_bytes": "0f31",
          "new_bytes": "9090",
          "description": "RDTSC → NOP NOP"
        }
      ]
    },
    ...
  ]
}
```

**보고서 파싱 스크립트**

```python
import json

report = json.load(open("samples/combined_report.json", encoding="utf-8"))
print(f"탐지: {report['summary']['total_findings']}건  패치: {report['summary']['patch_applied']}건")

for f in report["findings"]:
    status = "✔" if f["patchable"] else "—"
    print(f"  [{f['category']:10s}] {f['technique']:<30} {status}  VA={f['va']}")
```

---

### 테스트 5 — 탐지 누락 검증

특정 카테고리를 제외했을 때 해당 기법이 탐지되지 않는지 확인한다.

```bash
# antidebug만 제외 → combined 샘플에서 IsDebuggerPresent가 나오면 안 됨
python patcher.py samples/combined_evasion.exe -c sleep vm userinput --dry-run
```

```
  sleep       4건 탐지
  vm          3건 탐지
  userinput   2건 탐지

  총 9건 탐지  ← antidebug 1건 빠짐 (정상)
```

---

### 테스트 요약표

| 명령 | 예상 탐지 | 체크 포인트 |
|---|---|---|
| `patcher.py samples/sleep_evasion.exe -c sleep --dry-run` | 4건 (RDTSC×2 + Sleep + SleepEx + GetTickCount) | 스킵 0, 오류 0 |
| `patcher.py samples/vm_evasion.exe -c vm --dry-run` | 4~5건 (CPUID×2 + API 3개) | VM_STRING은 패치 불가(—) |
| `patcher.py samples/userinput_evasion.exe -c userinput --dry-run` | 4건 | Jcc 오프셋 정확성 확인 |
| `patcher.py samples/antidebug_evasion.exe -c antidebug --dry-run` | 4건 | IsDebuggerPresent PatchAction 2개 |
| `patcher.py samples/combined_evasion.exe --dry-run` | 10건 / 패치 11건 | 카테고리 4개 모두 탐지 |

---

## 사용법

### 1. 정적 패치 (`patcher.py`)

PE 바이너리를 직접 수정해 패치된 파일을 생성한다. 패치본을 샌드박스에 제출하는 방식.

#### 기본 패턴

```
python patcher.py <입력파일> [옵션]
```

#### 옵션

| 옵션 | 설명 | 기본값 |
|---|---|---|
| `--output`, `-o` | 패치된 EXE 저장 경로 | `<입력>_patched.exe` |
| `--report`, `-r` | JSON 보고서 저장 경로 | `<입력>_report.json` |
| `--no-report` | 보고서 저장 안 함 | — |
| `--dry-run` | 탐지만 수행, 파일 수정 없음 | — |
| `--categories`, `-c` | 탐지 카테고리 지정 | 전체 |

#### 예시

```bash
# 탐지 결과만 확인 (파일 수정 없음)
python patcher.py sample.exe --dry-run

# 전체 패치 + 보고서 생성
python patcher.py sample.exe --output patched.exe --report report.json

# Sleep·안티디버그 카테고리만 패치
python patcher.py sample.exe -c sleep antidebug

# 출력 경로 지정, 보고서 저장 안 함
python patcher.py sample.exe -o C:\analysis\patched.exe --no-report

# VM 탐지만 dry-run으로 확인
python patcher.py sample.exe -c vm --dry-run
```

---

### 2. 런타임 훅 (`hooker/run_frida.py`)

Frida를 이용해 **실행 중인 프로세스에 API 훅을 인젝션**한다.
정적 패치가 어려운 경우(패킹, 암호화 등)나 로컬 동적 분석 시 사용.

#### 기본 패턴

```
python hooker/run_frida.py <--spawn | --pid | --name> [대상]
```

#### 옵션

| 옵션 | 설명 |
|---|---|
| `--spawn PATH` | EXE를 직접 실행하면서 훅 주입 (권장) |
| `--pid PID` | 이미 실행 중인 프로세스 PID에 붙기 |
| `--name NAME` | 프로세스 이름으로 붙기 |

#### 예시

```bash
# EXE 스폰 후 훅 주입
python hooker/run_frida.py --spawn C:\malware\sample.exe

# 실행 중인 PID에 붙기
python hooker/run_frida.py --pid 4892

# 프로세스 이름으로 붙기
python hooker/run_frida.py --name sample.exe
```

#### 훅 동작 요약

| API | 훅 동작 |
|---|---|
| `Sleep` / `SleepEx` | 100ms 초과 인자 → 1ms로 단축 |
| `NtDelayExecution` | 대기 시간 → 1ms로 단축 |
| `GetTickCount(64)` | 자연스럽게 증가하는 fake 값 반환 |
| `IsDebuggerPresent` | 항상 0 반환 |
| `CheckRemoteDebuggerPresent` | `*pbDebuggerPresent = FALSE` 강제 |
| `NtQueryInformationProcess` | DebugPort/Flags → 0 반환 |
| `RegOpenKeyExA/W` | VM 관련 경로 → `ERROR_FILE_NOT_FOUND` |
| `GetModuleHandle` | VM 프로세스 모듈 → `NULL` 반환 |
| `GetCursorPos` | 매 호출마다 조금씩 이동하는 fake 좌표 |
| `GetAsyncKeyState` | `0x8001` (키 눌림 상태) 반환 |
| `GetSystemMetrics` | 해상도 → 1920×1080 반환 |
| `FindWindow` | 디버거 윈도우 탐색 → `NULL` 반환 |

---

## 권장 워크플로우

```
① sample.exe 입수
        │
        ▼
② python patcher.py sample.exe --dry-run
        │  ← 탐지 결과 확인, 오탐 여부 검토
        ▼
③ python patcher.py sample.exe --output patched.exe
        │  ← 바이트 패치 적용
        ▼
④ patched.exe → Triage 샌드박스 제출
        │  ← 실제 악성 행위 관찰
        ▼
⑤ (패킹/암호화로 정적 패치 불가 시)
   python hooker/run_frida.py --spawn sample.exe
        │  ← 언패킹 후 런타임 훅 적용
        ▼
⑥ report.json → triage_analyzer2.py 와 연계 분석
```

---

## 한계 및 주의사항

- **VM 문자열**: 자동 패치 미지원. 탐지 후 수동으로 참조 코드의 조건부 점프를 확인해야 한다.
- **Jcc 미발견**: IAT 콜사이트 이후 128바이트 내에 조건부 점프가 없으면 탐지만 기록하고 패치하지 않는다.
- **패킹/암호화된 EXE**: 정적 패치 효과 없음 → Frida 런타임 훅 사용.
- **인라인 syscall**: `int 0x2e` / `syscall` 직접 호출은 IAT 기반 탐지 불가.
- **원본 바이트 검증**: 정적 패치는 원본 바이트가 예상과 다르면 스킵하여 오패치를 방지한다.

---

## 프로젝트 구조

```
evasion_patcher/
├── patcher.py                 ← CLI 진입점 (정적 패치)
├── report.py                  ← 콘솔·JSON 보고서
├── requirements.txt
│
├── core/
│   ├── pe_utils.py            ← PE 로드·섹션·임포트·패치·저장
│   └── disasm.py              ← Capstone 역어셈블 헬퍼
│                                 (콜사이트·Jcc·인자 탐색)
│
├── detectors/
│   ├── base.py                ← Finding / PatchAction 데이터클래스
│   ├── sleep_detector.py      ← RDTSC, Sleep, GetTickCount
│   ├── vm_detector.py         ← CPUID, VM 문자열, 레지 API
│   ├── userinput_detector.py  ← GetCursorPos, GetAsyncKeyState 등
│   └── antidebug_detector.py  ← IsDebuggerPresent, NtQueryInfo 등
│
├── patchers/
│   └── apply.py               ← 원본 검증 후 바이트 패치 적용
│
├── hooker/
│   ├── frida_hooks.js          ← 런타임 API 훅 스크립트 (JS)
│   └── run_frida.py            ← Frida 인젝터 (Python)
│
└── samples/
    ├── create_samples.py       ← 예제 PE32 샘플 생성기
    ├── sleep_evasion.exe       ← Sleep/RDTSC 회피 샘플
    ├── vm_evasion.exe          ← VM 탐지 회피 샘플
    ├── userinput_evasion.exe   ← 사용자 입력 체크 샘플
    ├── antidebug_evasion.exe   ← 안티디버깅 샘플
    └── combined_evasion.exe    ← 전체 카테고리 복합 샘플
```

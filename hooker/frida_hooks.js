/**
 * frida_hooks.js
 * 샌드박스 회피 기법 런타임 무력화 (Frida 인젝션용)
 *
 * 커버 범위
 * ---------
 * [Sleep]      Sleep / SleepEx / NtDelayExecution / timeGetTime / GetTickCount
 * [VM]         RegOpenKeyEx / RegQueryValueEx / CreateFile / GetModuleHandle
 * [UserInput]  GetCursorPos / GetAsyncKeyState / GetSystemMetrics / GetLastInputInfo
 * [AntiDebug]  IsDebuggerPresent / CheckRemoteDebuggerPresent / NtQueryInformationProcess
 *              FindWindow / OutputDebugString
 *
 * 사용법
 * ------
 * frida -l frida_hooks.js -f target.exe --no-pause
 * frida -l frida_hooks.js --pid 1234
 */

'use strict';

// ── 유틸 ─────────────────────────────────────────────────────────
function log(tag, msg) {
    console.log('[' + tag + '] ' + msg);
}

// 커서 위치 시뮬레이션 (매 호출마다 조금씩 이동)
let _cursorX = 640, _cursorY = 400;
function fakeCursorMove() {
    _cursorX = (_cursorX + 3) % 1920;
    _cursorY = (_cursorY + 2) % 1080;
}

// GetTickCount 카운터 (실제처럼 증가)
let _tickCount = Date.now();

// VM 관련 레지스트리 경로 패턴 (소문자)
const VM_REG_PATTERNS = [
    'vmware', 'virtualbox', 'vbox', 'qemu', 'cuckoo',
    'sandboxie', 'virtual machine', 'triage',
];
function isVMRegPath(path) {
    if (!path) return false;
    const lower = path.toLowerCase();
    return VM_REG_PATTERNS.some(p => lower.includes(p));
}

// ─────────────────────────────────────────────────────────────────
// SLEEP 계열
// ─────────────────────────────────────────────────────────────────
const Sleep = Module.findExportByName('kernel32.dll', 'Sleep');
if (Sleep) {
    Interceptor.attach(Sleep, {
        onEnter(args) {
            const ms = args[0].toUInt32();
            if (ms > 100) {
                log('Sleep', `Sleep(${ms}ms) → 1ms 로 단축`);
                args[0] = ptr(1);
            }
        }
    });
}

const SleepEx = Module.findExportByName('kernel32.dll', 'SleepEx');
if (SleepEx) {
    Interceptor.attach(SleepEx, {
        onEnter(args) {
            const ms = args[0].toUInt32();
            if (ms > 100) {
                log('Sleep', `SleepEx(${ms}ms) → 1ms 로 단축`);
                args[0] = ptr(1);
            }
        }
    });
}

const NtDelayExecution = Module.findExportByName('ntdll.dll', 'NtDelayExecution');
if (NtDelayExecution) {
    Interceptor.attach(NtDelayExecution, {
        onEnter(args) {
            // args[1] = PLARGE_INTEGER pInterval (100ns 단위, 음수=상대시간)
            try {
                const interval = args[1];
                if (!interval.isNull()) {
                    // 100ns 단위로 1ms = -10000 (상대값은 음수)
                    interval.writeS64(-10000);
                    log('Sleep', 'NtDelayExecution → 1ms 로 단축');
                }
            } catch (_) {}
        }
    });
}

const GetTickCount = Module.findExportByName('kernel32.dll', 'GetTickCount');
if (GetTickCount) {
    Interceptor.attach(GetTickCount, {
        onLeave(retval) {
            // 실제처럼 증가하는 값 반환 (sandox detection 우회)
            _tickCount += 15;
            retval.replace(_tickCount & 0xFFFFFFFF);
        }
    });
}

const GetTickCount64 = Module.findExportByName('kernel32.dll', 'GetTickCount64');
if (GetTickCount64) {
    Interceptor.attach(GetTickCount64, {
        onLeave(retval) {
            _tickCount += 15;
            retval.replace(ptr(_tickCount));
        }
    });
}

// ─────────────────────────────────────────────────────────────────
// VM / 환경 탐지
// ─────────────────────────────────────────────────────────────────
['RegOpenKeyExA', 'RegOpenKeyExW'].forEach(api => {
    const fn = Module.findExportByName('advapi32.dll', api);
    if (!fn) return;
    Interceptor.attach(fn, {
        onEnter(args) {
            try {
                const isWide = api.endsWith('W');
                const keyPath = isWide
                    ? args[1].readUtf16String()
                    : args[1].readAnsiString();
                if (isVMRegPath(keyPath)) {
                    log('VM', `${api}("${keyPath}") → ERROR_FILE_NOT_FOUND 반환`);
                    this._block = true;
                }
            } catch (_) {}
        },
        onLeave(retval) {
            if (this._block) {
                retval.replace(2);  // ERROR_FILE_NOT_FOUND
            }
        }
    });
});

['RegQueryValueExA', 'RegQueryValueExW'].forEach(api => {
    const fn = Module.findExportByName('advapi32.dll', api);
    if (!fn) return;
    Interceptor.attach(fn, {
        onEnter(args) {
            try {
                const isWide = api.endsWith('W');
                const valName = isWide
                    ? args[1].readUtf16String()
                    : args[1].readAnsiString();
                if (isVMRegPath(valName || '')) {
                    this._block = true;
                }
            } catch (_) {}
        },
        onLeave(retval) {
            if (this._block) {
                retval.replace(2);
            }
        }
    });
});

['GetModuleHandleA', 'GetModuleHandleW'].forEach(api => {
    const fn = Module.findExportByName('kernel32.dll', api);
    if (!fn) return;
    const VM_MODULES = ['vmtoolsd', 'vboxservice', 'vboxtray', 'vboxhook', 'sandboxie'];
    Interceptor.attach(fn, {
        onEnter(args) {
            try {
                const isWide = api.endsWith('W');
                const name = (isWide
                    ? args[0].readUtf16String()
                    : args[0].readAnsiString()) || '';
                if (VM_MODULES.some(m => name.toLowerCase().includes(m))) {
                    log('VM', `${api}("${name}") → NULL 반환`);
                    this._block = true;
                }
            } catch (_) {}
        },
        onLeave(retval) {
            if (this._block) {
                retval.replace(ptr(0));  // NULL = 모듈 없음
            }
        }
    });
});

// ─────────────────────────────────────────────────────────────────
// 사용자 상호작용 체크
// ─────────────────────────────────────────────────────────────────
const GetCursorPos = Module.findExportByName('user32.dll', 'GetCursorPos');
if (GetCursorPos) {
    Interceptor.attach(GetCursorPos, {
        onLeave(retval) {
            // 정상 반환 후 POINT 구조체에 fake 값 주입
            try {
                fakeCursorMove();
                const point = this.context.rcx || this.context.ecx;
                if (point) {
                    Memory.writeS32(ptr(point),        _cursorX);
                    Memory.writeS32(ptr(point).add(4), _cursorY);
                }
            } catch (_) {}
            retval.replace(1);  // TRUE
        }
    });
}

const GetAsyncKeyState = Module.findExportByName('user32.dll', 'GetAsyncKeyState');
if (GetAsyncKeyState) {
    Interceptor.attach(GetAsyncKeyState, {
        onLeave(retval) {
            // 0x8001 = 키가 눌려 있고 이전에도 눌렸음
            retval.replace(0x8001);
            log('UserInput', 'GetAsyncKeyState → 0x8001 (키 입력 시뮬레이션)');
        }
    });
}

const GetSystemMetrics = Module.findExportByName('user32.dll', 'GetSystemMetrics');
if (GetSystemMetrics) {
    const SM_CXSCREEN = 0, SM_CYSCREEN = 1;
    Interceptor.attach(GetSystemMetrics, {
        onEnter(args) { this._index = args[0].toUInt32(); },
        onLeave(retval) {
            if (this._index === SM_CXSCREEN) retval.replace(1920);
            else if (this._index === SM_CYSCREEN) retval.replace(1080);
        }
    });
}

const GetLastInputInfo = Module.findExportByName('user32.dll', 'GetLastInputInfo');
if (GetLastInputInfo) {
    Interceptor.attach(GetLastInputInfo, {
        onLeave(retval) {
            // LASTINPUTINFO.dwTime = 현재 TickCount에 가까운 값 → "최근 입력"
            try {
                const pInfo = this.context.rcx || this.context.ecx;
                if (pInfo) {
                    // 구조체: UINT cbSize(4) + DWORD dwTime(4)
                    Memory.writeU32(ptr(pInfo).add(4), (_tickCount - 100) & 0xFFFFFFFF);
                }
            } catch (_) {}
            retval.replace(1);
        }
    });
}

// ─────────────────────────────────────────────────────────────────
// 안티디버깅
// ─────────────────────────────────────────────────────────────────
const IsDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
if (IsDebuggerPresent) {
    Interceptor.attach(IsDebuggerPresent, {
        onLeave(retval) {
            if (retval.toUInt32() !== 0) {
                log('AntiDebug', 'IsDebuggerPresent → 0 으로 패치');
                retval.replace(0);
            }
        }
    });
}

const CheckRemoteDebuggerPresent = Module.findExportByName(
    'kernel32.dll', 'CheckRemoteDebuggerPresent'
);
if (CheckRemoteDebuggerPresent) {
    Interceptor.attach(CheckRemoteDebuggerPresent, {
        onEnter(args) { this._pbDebugger = args[1]; },
        onLeave(retval) {
            try {
                if (this._pbDebugger && !this._pbDebugger.isNull()) {
                    Memory.writeU32(this._pbDebugger, 0);  // FALSE
                }
            } catch (_) {}
            retval.replace(1);  // 함수 자체는 TRUE(성공) 반환
        }
    });
}

const NtQueryInformationProcess = Module.findExportByName(
    'ntdll.dll', 'NtQueryInformationProcess'
);
if (NtQueryInformationProcess) {
    const ProcessDebugPort  = 7;
    const ProcessDebugFlags = 31;
    const ProcessDebugObject= 30;
    Interceptor.attach(NtQueryInformationProcess, {
        onEnter(args) {
            this._class  = args[1].toUInt32();
            this._pInfo  = args[2];
            this._infoSz = args[3].toUInt32();
        },
        onLeave(retval) {
            if ([ProcessDebugPort, ProcessDebugFlags, ProcessDebugObject]
                    .includes(this._class)) {
                try {
                    if (this._pInfo && !this._pInfo.isNull() && this._infoSz >= 4) {
                        Memory.writeU32(this._pInfo, 0);  // 디버거 없음
                    }
                } catch (_) {}
                log('AntiDebug',
                    `NtQueryInformationProcess(class=${this._class}) → 0`);
            }
        }
    });
}

['FindWindowA', 'FindWindowW'].forEach(api => {
    const fn = Module.findExportByName('user32.dll', api);
    if (!fn) return;
    const DBG_WINDOWS = ['ollydbg', 'x64dbg', 'x32dbg', 'immunity debugger', 'windbg'];
    Interceptor.attach(fn, {
        onEnter(args) {
            try {
                const isWide = api.endsWith('W');
                const cls  = isWide ? args[0].readUtf16String() : args[0].readAnsiString();
                const name = isWide ? args[1].readUtf16String() : args[1].readAnsiString();
                const combined = ((cls || '') + (name || '')).toLowerCase();
                if (DBG_WINDOWS.some(d => combined.includes(d))) {
                    log('AntiDebug', `${api} 디버거 윈도우 탐색 → NULL`);
                    this._block = true;
                }
            } catch (_) {}
        },
        onLeave(retval) {
            if (this._block) retval.replace(ptr(0));
        }
    });
});

['OutputDebugStringA', 'OutputDebugStringW'].forEach(api => {
    const fn = Module.findExportByName('kernel32.dll', api);
    if (!fn) return;
    Interceptor.attach(fn, {
        onEnter(_args) {
            // 타이밍 측정용 안티디버그 — 호출 자체는 허용, 단 로그만 기록
            log('AntiDebug', `${api} 호출 감지`);
        }
    });
});

// ─────────────────────────────────────────────────────────────────
// 스레드 숨김 (ThreadHideFromDebugger 무력화)
// ─────────────────────────────────────────────────────────────────
const NtSetInformationThread = Module.findExportByName('ntdll.dll', 'NtSetInformationThread');
if (NtSetInformationThread) {
    const ThreadHideFromDebugger = 17;
    Interceptor.attach(NtSetInformationThread, {
        onEnter(args) {
            if (args[1].toUInt32() === ThreadHideFromDebugger) {
                log('AntiDebug', 'NtSetInformationThread(ThreadHideFromDebugger) → 무력화');
                this._nop = true;
            }
        },
        onLeave(retval) {
            if (this._nop) retval.replace(ptr(0));  // STATUS_SUCCESS (no-op)
        }
    });
}

// ─────────────────────────────────────────────────────────────────
// 타이밍 — QueryPerformanceCounter / QueryPerformanceFrequency
// RDTSC는 static patcher 가 NOP 처리, 여기서는 QPC 계열 커버
// ─────────────────────────────────────────────────────────────────
let _qpcCounter = 1000000;

const QueryPerformanceCounter = Module.findExportByName('kernel32.dll', 'QueryPerformanceCounter');
if (QueryPerformanceCounter) {
    Interceptor.attach(QueryPerformanceCounter, {
        onEnter(args) { this._pCount = args[0]; },
        onLeave(retval) {
            _qpcCounter += 10000;   // 10µs씩 증가 (정상 PC처럼)
            try {
                if (this._pCount && !this._pCount.isNull())
                    this._pCount.writeS64(_qpcCounter);
            } catch (_) {}
            retval.replace(ptr(1));
        }
    });
}

// ─────────────────────────────────────────────────────────────────
// 프로세스 목록 숨기기 — 분석 툴 프로세스 이름 위장
// Process32NextW/A 에서 분석 툴 이름을 "explorer.exe"로 교체
// ─────────────────────────────────────────────────────────────────
const ANALYSIS_TOOLS = [
    'x64dbg', 'x32dbg', 'ollydbg', 'windbg', 'ida64', 'ida.exe',
    'procmon', 'procexp', 'wireshark', 'fiddler', 'processhacker',
    'immunitydebugger', 'cheatengine', 'dnspy', 'de4dot', 'pestudio',
    'hollows_hunter', 'pe-sieve', 'pebear', 'lordpe', 'cffexplorer',
    'apimonitor', 'regshot', 'autoruns',
];

// PROCESSENTRY32W.szExeFile 오프셋
// x86: DWORD*5 + ULONG_PTR(4) + LONG + DWORD = 36
// x64: DWORD*5 + ULONG_PTR(8) + LONG + DWORD = 40
const _szExeOffset = Process.pointerSize === 8 ? 44 : 36;

['Process32NextW', 'Process32NextA', 'Process32FirstW', 'Process32FirstA'].forEach(api => {
    const fn = Module.findExportByName('kernel32.dll', api);
    if (!fn) return;
    const isWide = api.endsWith('W');
    Interceptor.attach(fn, {
        onEnter(args) { this._pEntry = args[1]; },
        onLeave(retval) {
            if (!retval.toUInt32() || !this._pEntry) return;
            try {
                const namePtr = this._pEntry.add(_szExeOffset);
                const exeName = isWide
                    ? namePtr.readUtf16String()
                    : namePtr.readAnsiString();
                if (!exeName) return;
                const lower = exeName.toLowerCase();
                if (ANALYSIS_TOOLS.some(t => lower.includes(t))) {
                    log('ProcHide', `${api}: "${exeName}" → "explorer.exe" 위장`);
                    if (isWide) namePtr.writeUtf16String('explorer.exe');
                    else        namePtr.writeAnsiString('explorer.exe');
                    // PID도 탐색기 PID(4)로 교체해 일관성 유지
                    this._pEntry.add(8).writeU32(4);
                }
            } catch (_) {}
        }
    });
});

// ─────────────────────────────────────────────────────────────────
// 오류 대화상자 차단 + 조기 종료 방지
// Joe Sandbox의 핵심: 바이너리 무수정 → 자체 해시 통과
// 여기서는 다이얼로그 자체를 막고 ExitProcess 를 무력화
// ─────────────────────────────────────────────────────────────────

// MessageBoxA/W — 오류 메시지 표시 차단
['MessageBoxA', 'MessageBoxW', 'MessageBoxExA', 'MessageBoxExW'].forEach(api => {
    const fn = Module.findExportByName('user32.dll', api);
    if (!fn) return;
    const isWide = api.includes('W');
    Interceptor.replace(fn, new NativeCallback(function(hWnd, lpText, lpCaption, uType) {
        try {
            const text = lpText && !ptr(lpText).isNull()
                ? (isWide ? ptr(lpText).readUtf16String() : ptr(lpText).readAnsiString())
                : '';
            const cap  = lpCaption && !ptr(lpCaption).isNull()
                ? (isWide ? ptr(lpCaption).readUtf16String() : ptr(lpCaption).readAnsiString())
                : '';
            log('MsgBlock', `${api} 차단 — [${cap}] ${text}`);
        } catch (_) {}
        return 1;  // IDOK — 다이얼로그 없이 즉시 확인 반환
    }, 'int', ['pointer', 'pointer', 'pointer', 'uint']));
});

// TaskDialog / TaskDialogIndirect — 현대 오류 다이얼로그
const TaskDialog = Module.findExportByName('comctl32.dll', 'TaskDialog');
if (TaskDialog) {
    Interceptor.replace(TaskDialog, new NativeCallback(
        function(hwnd, hInst, title, content, btn) {
            log('MsgBlock', 'TaskDialog 차단');
            return 0;  // S_OK
        }, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'uint']
    ));
}

// ExitProcess — 프로세스 강제 종료 차단
const ExitProcess = Module.findExportByName('kernel32.dll', 'ExitProcess');
if (ExitProcess) {
    Interceptor.replace(ExitProcess, new NativeCallback(function(exitCode) {
        log('AntiKill', `ExitProcess(${exitCode}) 차단 — 프로세스 계속 실행`);
        // 실제로 종료하지 않음
    }, 'void', ['uint']));
}

// TerminateProcess — 타 프로세스 종료 시도도 차단 (자기 자신 대상만)
const TerminateProcess = Module.findExportByName('kernel32.dll', 'TerminateProcess');
if (TerminateProcess) {
    Interceptor.attach(TerminateProcess, {
        onEnter(args) {
            // GetCurrentProcess() = 0xFFFFFFFF (-1) = 자기 자신
            const handle = args[0].toUInt32();
            if (handle === 0xFFFFFFFF || handle === Process.id) {
                log('AntiKill', `TerminateProcess(self, ${args[1].toUInt32()}) 차단`);
                this._blockSelf = true;
            }
        },
        onLeave(retval) {
            if (this._blockSelf) retval.replace(ptr(1));  // TRUE (성공인 척)
        }
    });
}

// ─────────────────────────────────────────────────────────────────
// 자체 무결성 검사 모니터링 (CryptHash / BCryptHash)
// 패치한 바이너리가 해시 불일치를 일으키는지 탐지 목적
// ─────────────────────────────────────────────────────────────────
['CryptHashData', 'CryptGetHashParam'].forEach(api => {
    const fn = Module.findExportByName('advapi32.dll', api);
    if (!fn) return;
    Interceptor.attach(fn, {
        onEnter(args) {
            if (api === 'CryptHashData') {
                log('Integrity', `CryptHashData: ${args[2].toUInt32()} bytes 해싱`);
            } else {
                log('Integrity', `CryptGetHashParam: param=${args[1].toUInt32()}`);
            }
        }
    });
});

const BCryptHashData = Module.findExportByName('bcrypt.dll', 'BCryptHashData');
if (BCryptHashData) {
    Interceptor.attach(BCryptHashData, {
        onEnter(args) {
            log('Integrity', `BCryptHashData: ${args[2].toUInt32()} bytes 해싱`);
        }
    });
}

// ─────────────────────────────────────────────────────────────────
// GetProcAddress 모니터링 — 동적 API 로딩 탐지
// ─────────────────────────────────────────────────────────────────
const _GP_WATCH = [
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
    'NtQueryInformationProcess', 'MessageBoxW', 'MessageBoxA',
    'ExitProcess', 'GetModuleFileNameW',
];
const GetProcAddress = Module.findExportByName('kernel32.dll', 'GetProcAddress');
if (GetProcAddress) {
    Interceptor.attach(GetProcAddress, {
        onEnter(args) {
            try {
                // 서수(ordinal) 로딩은 args[1]이 정수 — 문자열 읽기 전 확인
                const ordinal = args[1].toUInt32();
                if (ordinal < 0x10000) return;
                const name = args[1].readAnsiString() || '';
                if (_GP_WATCH.some(w => name.includes(w))) {
                    log('DynImport', `GetProcAddress("${name}") 동적 로딩 탐지`);
                }
            } catch (_) {}
        }
    });
}

log('INIT', '샌드박스 회피 무력화 훅 로드 완료 (Joe Sandbox 동등 모드)');

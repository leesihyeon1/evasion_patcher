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

log('INIT', '샌드박스 회피 무력화 훅 로드 완료');

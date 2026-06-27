/**
 * frida_hooks.js — 샌드박스/안티분석 회피 무력화
 *
 * 섹션 목록
 * ---------
 * 1.  유틸리티 (findExp / safeAttach / safeCb / safeReplace)
 * 2.  전역 상수 (ANALYSIS_TOOLS)
 * 3.  Sleep 계열
 * 4.  VM / 환경 탐지 (레지스트리, 모듈)
 * 5.  사용자 상호작용
 * 6.  안티디버깅 (IsDebuggerPresent, NtQueryInformationProcess, FindWindow)
 * 7.  QueryPerformanceCounter
 * 8.  프로세스 목록 — CreateToolhelp32Snapshot 계열
 * 9.  NtQuerySystemInformation — 시스템 레벨 프로세스 숨김
 * 10. 장치/파이프 접근 차단 — CreateFile / NtOpenFile
 * 11. 윈도우 열거 — EnumWindows 필터링
 * 12. MessageBox 차단
 * 13. 프로세스 강제 종료 방지 — NtTerminateProcess
 * 14. 무결성 해싱 모니터링
 */

// ═══════════════════════════════════════════════════════════════════
// 1. 유틸리티
// ═══════════════════════════════════════════════════════════════════
function log(tag, msg) {
    console.log('[' + tag + '] ' + msg);
}

log('INIT', 'frida_hooks.js 파싱 시작');

var WIN_ABI = (Process.pointerSize === 4) ? 'stdcall' : 'default';
var IS_64   = (Process.pointerSize === 8);
log('INIT', 'WIN_ABI=' + WIN_ABI + '  64bit=' + IS_64);

var findExp = (function () {
    if (typeof Module.getExportByName === 'function') {
        return function (mod, name) {
            try { var a = Module.getExportByName(mod, name); return (a && !a.isNull()) ? a : null; }
            catch (_) { return null; }
        };
    }
    if (typeof Module.findExportByName === 'function') {
        return function (mod, name) {
            try { return Module.findExportByName(mod, name); } catch (_) { return null; }
        };
    }
    return function () { return null; };
}());

function safeAttach(label, addr, callbacks) {
    if (!addr) { return; }
    try { Interceptor.attach(addr, callbacks); log('HOOK', label + ' attached'); }
    catch (e) { log('HOOK_ERR', label + ': ' + e.message); }
}

function safeCb(label, retType, argTypes, impl) {
    try { return new NativeCallback(impl, retType, argTypes, WIN_ABI); }
    catch (e) { log('CB_ERR', label + ': ' + e.message); return null; }
}

function safeReplace(label, addr, cb) {
    if (!addr || !cb) { return; }
    try { Interceptor.replace(addr, cb); log('HOOK', label + ' replaced'); }
    catch (e) { log('HOOK_ERR', label + ': ' + e.message); }
}

// ═══════════════════════════════════════════════════════════════════
// 2. 전역 상수
// ═══════════════════════════════════════════════════════════════════

// 프로세스 목록 / 윈도우 / 장치 필터에서 공통 사용
var ANALYSIS_TOOLS = [
    // 디버거
    'x64dbg', 'x32dbg', 'ollydbg', 'windbg', 'idaq', 'idaq64', 'ida.exe',
    'immunitydebugger', 'dnspy',
    // 모니터링
    'procmon', 'procmon64', 'procexp', 'procexp64',
    'processhacker', 'process hacker',
    'wireshark', 'dumpcap', 'rawshark', 'tshark',
    'fiddler', 'charles', 'httpanalyzer', 'burpsuite',
    // 정적 분석
    'pestudio', 'pe-sieve', 'pebear', 'cffexplorer',
    'hollows_hunter', 'de4dot',
    // 기타
    'cheatengine', 'apimonitor', 'regshot', 'autoruns',
    'sysinspector', 'tcpview', 'filemon', 'regmon',
];

// 분석 툴 장치/파이프 경로 (소문자, 앞부분 매칭)
var BLOCKED_DEVICE_PREFIXES = [
    '\\\\.\\procmon',       // Procmon 드라이버 디바이스
    '\\\\.\\procmon24',     // Procmon v3 이상
    '\\\\.\\procmon64',
    '\\\\.\\ntice',         // SoftICE
    '\\\\.\\sice',
    '\\\\.\\syser',
    '\\\\.\\dbgv',
    '\\\\.\\wireshark',
    '\\\\.\\npf',           // WinPcap
    '\\\\.\\npcap',         // Npcap
    '\\\\?\\npcap',
    '\\\\.\\pipe\\procmon', // Procmon 명명 파이프
    '\\\\.\\pipe\\wireshark',
    '\\\\.\\pipe\\capturekerneltraces',
];

// 분석 툴 윈도우 타이틀 키워드 (소문자)
var ANALYSIS_WIN_TITLES = [
    'process monitor', 'procmon',
    'process explorer', 'procexp',
    'process hacker',
    'wireshark', 'network monitor',
    'fiddler', 'charles proxy',
    'x64dbg', 'x32dbg', 'ollydbg', 'windbg',
    'immunity debugger', 'dnspy',
    'api monitor', 'pestudio',
];

function containsAnalysisTool(str) {
    if (!str) { return false; }
    var lower = str.toLowerCase();
    for (var i = 0; i < ANALYSIS_TOOLS.length; i++) {
        if (lower.indexOf(ANALYSIS_TOOLS[i]) !== -1) { return true; }
    }
    return false;
}

function isBlockedDevice(path) {
    if (!path) { return false; }
    var lower = path.toLowerCase();
    for (var i = 0; i < BLOCKED_DEVICE_PREFIXES.length; i++) {
        if (lower.indexOf(BLOCKED_DEVICE_PREFIXES[i]) !== -1) { return true; }
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════
// 3. Sleep 계열
// ═══════════════════════════════════════════════════════════════════
try {
    var _cursorX = 640, _cursorY = 400;
    var _tickCount = 100000;

    safeAttach('Sleep', findExp('kernel32.dll', 'Sleep'), {
        onEnter: function (args) {
            var ms = args[0].toUInt32();
            if (ms > 100) { log('Sleep', 'Sleep(' + ms + 'ms) → 1ms'); args[0] = ptr(1); }
        }
    });

    safeAttach('SleepEx', findExp('kernel32.dll', 'SleepEx'), {
        onEnter: function (args) {
            var ms = args[0].toUInt32();
            if (ms > 100) { log('Sleep', 'SleepEx(' + ms + 'ms) → 1ms'); args[0] = ptr(1); }
        }
    });

    safeAttach('NtDelayExecution', findExp('ntdll.dll', 'NtDelayExecution'), {
        onEnter: function (args) {
            try { var i = args[1]; if (!i.isNull()) { i.writeS64(-10000); } } catch (_) {}
        }
    });

    safeAttach('GetTickCount', findExp('kernel32.dll', 'GetTickCount'), {
        onLeave: function (retval) {
            _tickCount += 15;
            retval.replace(ptr(_tickCount & 0x7FFFFFFF));
        }
    });

    safeAttach('GetTickCount64', findExp('kernel32.dll', 'GetTickCount64'), {
        onLeave: function (retval) { _tickCount += 15; retval.replace(ptr(_tickCount)); }
    });
} catch (e) { log('ERR', 'Sleep 섹션: ' + e.message); }

// ═══════════════════════════════════════════════════════════════════
// 4. VM / 환경 탐지
// ═══════════════════════════════════════════════════════════════════
try {
    var VM_REG_PATTERNS = ['vmware', 'virtualbox', 'vbox', 'qemu', 'cuckoo', 'sandboxie', 'triage'];
    function isVMRegPath(path) {
        if (!path) { return false; }
        var lower = path.toLowerCase();
        for (var i = 0; i < VM_REG_PATTERNS.length; i++) {
            if (lower.indexOf(VM_REG_PATTERNS[i]) !== -1) { return true; }
        }
        return false;
    }

    ['RegOpenKeyExA', 'RegOpenKeyExW'].forEach(function (api) {
        var fn = findExp('advapi32.dll', api);
        if (!fn) { return; }
        var isWide = api.charAt(api.length - 1) === 'W';
        safeAttach(api, fn, {
            onEnter: function (args) {
                try {
                    var kp = isWide ? args[1].readUtf16String() : args[1].readAnsiString();
                    if (isVMRegPath(kp)) { log('VM', api + '("' + kp + '") → BLOCKED'); this._block = true; }
                } catch (_) {}
            },
            onLeave: function (retval) { if (this._block) { retval.replace(ptr(2)); } }
        });
    });

    ['RegQueryValueExA', 'RegQueryValueExW'].forEach(function (api) {
        var fn = findExp('advapi32.dll', api);
        if (!fn) { return; }
        var isWide = api.charAt(api.length - 1) === 'W';
        safeAttach(api, fn, {
            onEnter: function (args) {
                try {
                    var v = isWide ? args[1].readUtf16String() : args[1].readAnsiString();
                    if (isVMRegPath(v || '')) { this._block = true; }
                } catch (_) {}
            },
            onLeave: function (retval) { if (this._block) { retval.replace(ptr(2)); } }
        });
    });

    var VM_MODULES = ['vmtoolsd', 'vboxservice', 'vboxtray', 'sandboxie'];
    ['GetModuleHandleA', 'GetModuleHandleW'].forEach(function (api) {
        var fn = findExp('kernel32.dll', api);
        if (!fn) { return; }
        var isWide = api.charAt(api.length - 1) === 'W';
        safeAttach(api, fn, {
            onEnter: function (args) {
                try {
                    var name = (isWide ? args[0].readUtf16String() : args[0].readAnsiString()) || '';
                    var lower = name.toLowerCase();
                    for (var i = 0; i < VM_MODULES.length; i++) {
                        if (lower.indexOf(VM_MODULES[i]) !== -1) {
                            log('VM', api + '("' + name + '") → NULL');
                            this._block = true; break;
                        }
                    }
                } catch (_) {}
            },
            onLeave: function (retval) { if (this._block) { retval.replace(ptr(0)); } }
        });
    });
} catch (e) { log('ERR', 'VM 섹션: ' + e.message); }

// ═══════════════════════════════════════════════════════════════════
// 5. 사용자 상호작용
// ═══════════════════════════════════════════════════════════════════
try {
    safeAttach('GetCursorPos', findExp('user32.dll', 'GetCursorPos'), {
        onLeave: function (retval) {
            try {
                _cursorX = (_cursorX + 3) % 1920;
                _cursorY = (_cursorY + 2) % 1080;
                var p = this.context.eax ? ptr(this.context.eax) : null;
                if (!p || p.isNull()) { p = this.returnAddress ? null : null; }
                // POINT* is in first arg (stored in context or via args saved in onEnter)
                if (this._pPoint && !this._pPoint.isNull()) {
                    Memory.writeS32(this._pPoint,       _cursorX);
                    Memory.writeS32(this._pPoint.add(4), _cursorY);
                }
            } catch (_) {}
            retval.replace(ptr(1));
        },
        onEnter: function (args) { this._pPoint = args[0]; }
    });

    safeAttach('GetAsyncKeyState', findExp('user32.dll', 'GetAsyncKeyState'), {
        onLeave: function (retval) { retval.replace(ptr(0x8001)); }
    });

    safeAttach('GetLastInputInfo', findExp('user32.dll', 'GetLastInputInfo'), {
        onEnter: function (args) { this._p = args[0]; },
        onLeave: function (retval) {
            try {
                if (this._p && !this._p.isNull()) {
                    Memory.writeU32(this._p.add(4), (_tickCount - 100) & 0x7FFFFFFF);
                }
            } catch (_) {}
            retval.replace(ptr(1));
        }
    });
} catch (e) { log('ERR', 'UserInput 섹션: ' + e.message); }

// ═══════════════════════════════════════════════════════════════════
// 6. 안티디버깅
// ═══════════════════════════════════════════════════════════════════
try {
    safeAttach('IsDebuggerPresent', findExp('kernel32.dll', 'IsDebuggerPresent'), {
        onLeave: function (retval) {
            if (retval.toUInt32() !== 0) { log('AntiDbg', 'IsDebuggerPresent → 0'); retval.replace(ptr(0)); }
        }
    });

    safeAttach('CheckRemoteDebuggerPresent',
        findExp('kernel32.dll', 'CheckRemoteDebuggerPresent'), {
        onEnter: function (args) { this._pb = args[1]; },
        onLeave: function (retval) {
            try { if (this._pb && !this._pb.isNull()) { Memory.writeU32(this._pb, 0); } } catch (_) {}
            retval.replace(ptr(1));
        }
    });

    safeAttach('NtQueryInformationProcess',
        findExp('ntdll.dll', 'NtQueryInformationProcess'), {
        onEnter: function (args) {
            this._class = args[1].toUInt32();
            this._pInfo = args[2];
            this._infoSz = args[3].toUInt32();
        },
        onLeave: function (retval) {
            var DBG = [7, 30, 31]; // DebugPort, DebugObjectHandle, DebugFlags
            for (var i = 0; i < DBG.length; i++) {
                if (this._class === DBG[i]) {
                    try {
                        if (this._pInfo && !this._pInfo.isNull() && this._infoSz >= 4) {
                            Memory.writeU32(this._pInfo, 0);
                        }
                    } catch (_) {}
                    log('AntiDbg', 'NtQueryInfoProcess(class=' + this._class + ') → 0');
                    break;
                }
            }
        }
    });

    safeAttach('NtSetInformationThread',
        findExp('ntdll.dll', 'NtSetInformationThread'), {
        onEnter: function (args) {
            if (args[1].toUInt32() === 17) { // ThreadHideFromDebugger
                log('AntiDbg', 'ThreadHideFromDebugger 무력화');
                this._nop = true;
            }
        },
        onLeave: function (retval) { if (this._nop) { retval.replace(ptr(0)); } }
    });

    // FindWindowA/W — 디버거 + 분석 툴 윈도우 모두 차단
    var HIDDEN_WINDOWS = [
        'ollydbg', 'x64dbg', 'x32dbg', 'immunity debugger', 'windbg',
        'process monitor', 'procmon', 'process explorer', 'process hacker',
        'wireshark', 'fiddler', 'api monitor', 'pestudio',
    ];

    ['FindWindowA', 'FindWindowW', 'FindWindowExA', 'FindWindowExW'].forEach(function (api) {
        var fn = findExp('user32.dll', api);
        if (!fn) { return; }
        var isWide = api.charAt(api.length - 1) === 'W';
        var hasEx   = api.indexOf('Ex') !== -1;
        safeAttach(api, fn, {
            onEnter: function (args) {
                try {
                    var base = hasEx ? 2 : 0; // FindWindowEx: args[2]=lpClassName, args[3]=lpWindowName
                    var cls  = args[base];
                    var name = args[base + 1];
                    var clsStr  = (!cls  || cls.isNull())  ? '' : (isWide ? cls.readUtf16String()  : cls.readAnsiString());
                    var nameStr = (!name || name.isNull()) ? '' : (isWide ? name.readUtf16String() : name.readAnsiString());
                    var combined = ((clsStr || '') + ' ' + (nameStr || '')).toLowerCase();
                    for (var i = 0; i < HIDDEN_WINDOWS.length; i++) {
                        if (combined.indexOf(HIDDEN_WINDOWS[i]) !== -1) {
                            log('AntiDbg', api + ' → NULL (' + combined.trim() + ')');
                            this._block = true;
                            break;
                        }
                    }
                } catch (_) {}
            },
            onLeave: function (retval) { if (this._block) { retval.replace(ptr(0)); } }
        });
    });

    safeAttach('OutputDebugStringA', findExp('kernel32.dll', 'OutputDebugStringA'), {
        onEnter: function (_) { log('AntiDbg', 'OutputDebugStringA 감지'); }
    });
    safeAttach('OutputDebugStringW', findExp('kernel32.dll', 'OutputDebugStringW'), {
        onEnter: function (_) { log('AntiDbg', 'OutputDebugStringW 감지'); }
    });
} catch (e) { log('ERR', 'AntiDebug 섹션: ' + e.message); }

// ═══════════════════════════════════════════════════════════════════
// 7. QueryPerformanceCounter
// ═══════════════════════════════════════════════════════════════════
try {
    var _qpcCounter = 1000000;
    safeAttach('QueryPerformanceCounter',
        findExp('kernel32.dll', 'QueryPerformanceCounter'), {
        onEnter: function (args) { this._p = args[0]; },
        onLeave: function (retval) {
            _qpcCounter += 10000;
            try { if (this._p && !this._p.isNull()) { this._p.writeS64(_qpcCounter); } } catch (_) {}
            retval.replace(ptr(1));
        }
    });
} catch (e) { log('ERR', 'QPC 섹션: ' + e.message); }

// ═══════════════════════════════════════════════════════════════════
// 8. 프로세스 목록 — CreateToolhelp32Snapshot 계열
// ═══════════════════════════════════════════════════════════════════
try {
    // PROCESSENTRY32(W).szExeFile 오프셋
    // x86: ULONG_PTR=4  → 36
    // x64: ULONG_PTR=8  → 44
    var _szExeOff = IS_64 ? 44 : 36;

    ['Process32FirstW', 'Process32FirstA', 'Process32NextW', 'Process32NextA'].forEach(function (api) {
        var fn = findExp('kernel32.dll', api);
        if (!fn) { return; }
        var isWide = api.charAt(api.length - 1) === 'W';
        safeAttach(api, fn, {
            onEnter: function (args) { this._pEntry = args[1]; },
            onLeave: function (retval) {
                if (!retval.toUInt32() || !this._pEntry) { return; }
                try {
                    var namePtr = this._pEntry.add(_szExeOff);
                    var exeName = isWide ? namePtr.readUtf16String() : namePtr.readAnsiString();
                    if (!exeName) { return; }
                    if (containsAnalysisTool(exeName)) {
                        log('ProcHide', api + ': "' + exeName + '" → explorer.exe');
                        if (isWide) { namePtr.writeUtf16String('explorer.exe'); }
                        else        { namePtr.writeAnsiString('explorer.exe'); }
                        // th32ProcessID(+8)을 안전한 PID(explorer = ~4)로 위장
                        this._pEntry.add(8).writeU32(4);
                    }
                } catch (_) {}
            }
        });
    });
} catch (e) { log('ERR', 'ProcHide(Toolhelp) 섹션: ' + e.message); }

// ═══════════════════════════════════════════════════════════════════
// 9. NtQuerySystemInformation — 시스템 레벨 프로세스 숨김
//    class 5 = SystemProcessInformation
//    많은 보호 도구가 CreateToolhelp32Snapshot 대신 이 API를 사용함
// ═══════════════════════════════════════════════════════════════════
try {
    // SYSTEM_PROCESS_INFORMATION.ImageName (UNICODE_STRING) 오프셋
    //   이 구조체는 Windows 버전에 따라 다르지만 ImageName은 +56으로 고정됨
    // UNICODE_STRING.Buffer 오프셋: x86=4, x64=8 (Length(2)+MaxLen(2)+pad)
    var _IMG_OFF    = 56;
    var _BUF_OFF    = IS_64 ? 8 : 4;

    safeAttach('NtQuerySystemInformation',
        findExp('ntdll.dll', 'NtQuerySystemInformation'), {
        onEnter: function (args) {
            this._class = args[0].toUInt32();
            this._buf   = args[1];
        },
        onLeave: function (retval) {
            if (this._class !== 5) { return; }    // SystemProcessInformation 만
            if (retval.toUInt32() !== 0) { return; }  // STATUS_SUCCESS
            try {
                var cur  = this._buf;
                var prev = null;
                while (cur && !cur.isNull()) {
                    var nextOff = cur.readU32();
                    var hide    = false;

                    try {
                        var nameLen = cur.add(_IMG_OFF).readU16();  // 바이트 수
                        var nameBuf = cur.add(_IMG_OFF + _BUF_OFF).readPointer();
                        if (nameLen > 0 && nameBuf && !nameBuf.isNull()) {
                            var pname = nameBuf.readUtf16String(nameLen / 2);
                            if (containsAnalysisTool(pname)) {
                                log('NtQSI', '프로세스 숨김: "' + pname + '"');
                                hide = true;
                            }
                        }
                    } catch (_) {}

                    if (hide) {
                        if (prev !== null) {
                            // 이전 항목의 NextEntryOffset 갱신 → 현재 항목 건너뜀
                            var prevNext = prev.readU32();
                            prev.writeU32(nextOff === 0 ? 0 : prevNext + nextOff);
                        } else {
                            // 첫 항목 숨김: 이름만 지움 (언링크보다 안전)
                            try { cur.add(_IMG_OFF).writeU16(0); } catch (_) {}
                        }
                    } else {
                        prev = cur;
                    }

                    if (nextOff === 0) { break; }
                    cur = cur.add(nextOff);
                }
            } catch (e2) { log('NtQSI', '워크 오류: ' + e2.message); }
        }
    });
} catch (e) { log('ERR', 'NtQSI 섹션: ' + e.message); }

// ═══════════════════════════════════════════════════════════════════
// 10. 장치/파이프 접근 차단
//     Themida 등 보호기가 분석 도구 드라이버 디바이스(\\.\PROCMON*)에
//     CreateFile로 접근해 존재 여부를 확인함
// ═══════════════════════════════════════════════════════════════════
try {
    ['CreateFileA', 'CreateFileW'].forEach(function (api) {
        var fn = findExp('kernel32.dll', api);
        if (!fn) { return; }
        var isWide = api.charAt(api.length - 1) === 'W';
        safeAttach(api, fn, {
            onEnter: function (args) {
                try {
                    var path = isWide ? args[0].readUtf16String() : args[0].readAnsiString();
                    if (isBlockedDevice(path)) {
                        log('DevBlock', api + '("' + path + '") → INVALID_HANDLE');
                        this._block = true;
                    }
                } catch (_) {}
            },
            onLeave: function (retval) {
                if (this._block) { retval.replace(ptr(-1)); } // INVALID_HANDLE_VALUE
            }
        });
    });

    // NtOpenFile / NtCreateFile 로 우회하는 경우 대비
    ['NtOpenFile', 'NtCreateFile'].forEach(function (api) {
        var fn = findExp('ntdll.dll', api);
        if (!fn) { return; }
        // OBJECT_ATTRIBUTES.ObjectName(UNICODE_STRING*)은 args[2]에 위치
        safeAttach(api, fn, {
            onEnter: function (args) {
                try {
                    var oa = args[2];  // POBJECT_ATTRIBUTES
                    if (!oa || oa.isNull()) { return; }
                    // ObjectName 포인터: OBJECT_ATTRIBUTES 구조체에서
                    // Length(4)+RootDirectory(ptr)+ObjectName(ptr) → ptr 크기에 따라 오프셋 계산
                    var objNamePtr = oa.add(IS_64 ? 16 : 8).readPointer();
                    if (objNamePtr.isNull()) { return; }
                    var len = objNamePtr.readU16();        // UNICODE_STRING.Length
                    var buf = objNamePtr.add(IS_64 ? 8 : 4).readPointer();  // .Buffer
                    if (len > 0 && !buf.isNull()) {
                        var path = buf.readUtf16String(len / 2);
                        if (isBlockedDevice(path)) {
                            log('DevBlock', api + '("' + path + '") → 접근 거부');
                            this._block = true;
                        }
                    }
                } catch (_) {}
            },
            onLeave: function (retval) {
                if (this._block) { retval.replace(ptr(0xC0000034)); } // STATUS_OBJECT_NAME_NOT_FOUND
            }
        });
    });
} catch (e) { log('ERR', 'DevBlock 섹션: ' + e.message); }

// ═══════════════════════════════════════════════════════════════════
// 11. 윈도우 열거 — EnumWindows 필터링
//     콜백을 래핑해 분석 도구 윈도우를 열거 결과에서 제거
// ═══════════════════════════════════════════════════════════════════
try {
    var _getWinTextW = findExp('user32.dll', 'GetWindowTextW');
    var _winTextFn   = _getWinTextW
        ? new NativeFunction(_getWinTextW, 'int', ['pointer', 'pointer', 'int'])
        : null;

    function _isAnalysisHwnd(hwnd) {
        if (!_winTextFn) { return false; }
        try {
            var buf = Memory.alloc(512);
            var len = _winTextFn(hwnd, buf, 255);
            if (len <= 0) { return false; }
            var title = buf.readUtf16String(len).toLowerCase();
            for (var i = 0; i < ANALYSIS_WIN_TITLES.length; i++) {
                if (title.indexOf(ANALYSIS_WIN_TITLES[i]) !== -1) { return true; }
            }
        } catch (_) {}
        return false;
    }

    // 콜백 래퍼를 GC에서 보호하기 위한 전역 배열
    var _enumWinCbs = [];

    ['EnumWindows', 'EnumDesktopWindows'].forEach(function (api) {
        var fn = findExp('user32.dll', api);
        if (!fn) { return; }
        safeAttach(api, fn, {
            onEnter: function (args) {
                try {
                    var origCbPtr = args[0];
                    var lParam    = args[1];
                    var origFn    = new NativeFunction(origCbPtr, 'int', ['pointer', 'long']);
                    var wrapper   = new NativeCallback(function (hwnd, lp) {
                        if (_isAnalysisHwnd(hwnd)) {
                            log('EnumWin', '분석툴 윈도우 제거');
                            return 1; // 콜백 계속, 이 hwnd는 건너뜀
                        }
                        return origFn(hwnd, lp);
                    }, 'int', ['pointer', 'long']);
                    _enumWinCbs.push(wrapper); // GC 방지
                    args[0] = wrapper;
                } catch (_) {}
            }
        });
    });
} catch (e) { log('ERR', 'EnumWindows 섹션: ' + e.message); }

// ═══════════════════════════════════════════════════════════════════
// 12. MessageBox 차단
// ═══════════════════════════════════════════════════════════════════
try {
    function hookMessageBox(api) {
        var fn = findExp('user32.dll', api);
        if (!fn) { log('HOOK', api + ' 미발견'); return; }
        var isWide = api.indexOf('W') !== -1;
        var cb = safeCb(api, 'int', ['pointer', 'pointer', 'pointer', 'uint'],
            function (hWnd, lpText, lpCaption, uType) {
                try {
                    var rd = function (p) { return (!p || p.isNull()) ? '' : (isWide ? p.readUtf16String() : p.readAnsiString()); };
                    log('MsgBlock', api + ' 차단: [' + rd(lpCaption) + '] ' + rd(lpText));
                } catch (_) {}
                return 1;
            });
        safeReplace(api, fn, cb);
    }
    hookMessageBox('MessageBoxA');
    hookMessageBox('MessageBoxW');

    function hookMessageBoxEx(api) {
        var fn = findExp('user32.dll', api);
        if (!fn) { return; }
        var isWide = api.indexOf('W') !== -1;
        var cb = safeCb(api, 'int', ['pointer', 'pointer', 'pointer', 'uint', 'uint'],
            function (hWnd, lpText, lpCaption, uType, wLang) {
                try {
                    var rd = function (p) { return (!p || p.isNull()) ? '' : (isWide ? p.readUtf16String() : p.readAnsiString()); };
                    log('MsgBlock', api + ' 차단: ' + rd(lpText));
                } catch (_) {}
                return 1;
            });
        safeReplace(api, fn, cb);
    }
    hookMessageBoxEx('MessageBoxExA');
    hookMessageBoxEx('MessageBoxExW');
} catch (e) { log('ERR', 'MessageBox 섹션: ' + e.message); }

// ═══════════════════════════════════════════════════════════════════
// 13. 프로세스 강제 종료 방지 — NtTerminateProcess
//     Themida "monitor detected" → ExitProcess 호출 흐름 차단
//     자기 자신(hProcess=-1/0) 종료만 차단, 자식 프로세스 종료는 허용
// ═══════════════════════════════════════════════════════════════════
try {
    safeAttach('NtTerminateProcess', findExp('ntdll.dll', 'NtTerminateProcess'), {
        onEnter: function (args) {
            var h = args[0].toInt32();
            if (h === -1 || h === 0) {
                log('AntiKill', 'NtTerminateProcess(self, ' + args[1].toUInt32() + ') → 핸들 무효화');
                // 핸들을 존재하지 않는 값으로 교체 → STATUS_INVALID_HANDLE 반환 (자기 자신 종료 방지)
                args[0] = ptr(0xDEAD);
            }
        }
    });

    // ExitProcess / TerminateProcess 도 동일하게 처리
    safeAttach('ExitProcess', findExp('kernel32.dll', 'ExitProcess'), {
        onEnter: function (args) {
            var code = args[0].toUInt32();
            log('AntiKill', 'ExitProcess(' + code + ') 차단');
            // 스택의 리턴 주소를 무한 루프로 리다이렉트하는 대신
            // 단순히 Sleep으로 시간을 벌어 분석 기회를 유지
            args[0] = ptr(0);
        }
    });
} catch (e) { log('ERR', 'NtTerminate 섹션: ' + e.message); }

// ═══════════════════════════════════════════════════════════════════
// 14. 무결성 해싱 모니터링 (패치 여부 탐지 목적)
// ═══════════════════════════════════════════════════════════════════
try {
    safeAttach('CryptHashData', findExp('advapi32.dll', 'CryptHashData'), {
        onEnter: function (args) { log('Integrity', 'CryptHashData: ' + args[2].toUInt32() + ' bytes'); }
    });
    safeAttach('BCryptHashData', findExp('bcrypt.dll', 'BCryptHashData'), {
        onEnter: function (args) { log('Integrity', 'BCryptHashData: ' + args[2].toUInt32() + ' bytes'); }
    });
} catch (e) { log('ERR', 'Integrity 섹션: ' + e.message); }

log('INIT', '모든 훅 로드 완료');

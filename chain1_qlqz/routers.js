(function() {
  var ua = navigator.userAgent;

  function getIOSVersion() {
    function pad(s) { return s.length === 1 ? '0' + s : s; }
    // Safari's Version/ token omits the patch component on iPhone. Prefer
    // the full iPhone OS token so 18.7.3 is not mistaken for 18.7.0.
    var u = ua.match(/(?:iPhone|iPad|iPod).*?OS (\d+)[._](\d+)(?:[._](\d+))?/i);
    if (!u) u = ua.match(/CPU (?:iPhone )?OS (\d+)[._](\d+)(?:[._](\d+))?/i);
    if (!u) u = ua.match(/iOS\/(\d+)\.(\d+)(?:\.(\d+))?/i);
    if (!u) u = ua.match(/Version\/(\d+)\.(\d+)(?:\.(\d+))?/);
    if (!u) return 0;
    return parseInt(pad(u[1]) + pad(u[2]) + (u[3] ? pad(u[3]) : '00'), 10);
  }

  var ver = getIOSVersion();

  function loadScript(src) {
    var s = document.createElement('script');
    s.src = src + (src.indexOf('?') >= 0 ? '&' : '?') + Date.now();
    document.head.appendChild(s);
  }

  // Keep unsupported versions terminal.  The old >= comparisons routed
  // iOS 18.7.3+ and future iOS releases into a stale 18.x loader.
  if (ver >= 180700 && ver <= 180702) {
    loadScript('rce_loader.js');
  } else if (ver >= 180400 && ver <= 180699) {
    loadScript('ds_rce_loader.js');
  } else if (ver >= 100000 && ver <= 170201) {
    loadScript('34ef644ff217a50beadde64dc8e23a7dx.js?channelcode=ca3c032155b842af5b7ba72ab2a5d8fe');
  }
})();

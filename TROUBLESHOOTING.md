# Troubleshooting Kerno

If you are experiencing issues while setting up or running Kerno, please check the common scenarios below.

## 1. Installation & Dependencies
* **Error:** `clang: command not found` or `llvm: command not found`
    * **Cause:** The required eBPF build toolchain is missing from your system.
    * **Fix:** Install the necessary build dependencies:
        ```bash
        sudo apt-get update
        sudo apt-get install clang llvm libbpf-dev bpftool
        ```

## 2. Kernel & eBPF Errors
* **Error:** `/sys/kernel/btf not found` or `failed to load BPF program`
    * **Cause:** Your current kernel version is likely older than 5.8 or lacks BPF Type Format (BTF) support.
    * **Fix:** Ensure you are running a modern, managed Kubernetes distribution (EKS, GKE, AKS, etc.) or update your host kernel to 5.8+.
* **Error:** `failed to attach kprobe`
    * **Cause:** The kernel may have restrictions on attaching probes, or the specific tracepoint is unavailable.
    * **Fix:** Verify your kernel headers are installed: `sudo apt-get install linux-headers-$(uname -r)`.

## 3. Permissions
* **Error:** `permission denied` or `Operation not permitted`
    * **Cause:** Kerno requires root-level privileges to interact with eBPF hooks in the kernel.
    * **Fix:** * Always run locally with `sudo`: `sudo ./kerno doctor`.
        * If running in Kubernetes, ensure your DaemonSet is configured with the necessary security capabilities: `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE`, `CAP_NET_ADMIN`, and `CAP_DAC_READ_SEARCH`.

## 4. Reporting New Issues
If your problem is not listed here:
1. **Check existing issues:** See if another user has reported the same error on the [GitHub Issues page](https://github.com/optiqor/kerno/issues).
2. **Gather context:** Run `uname -a` to get your kernel version and include it in your report.
3. **Open a new issue:** Provide the full error logs and a brief description of how to reproduce the problem.

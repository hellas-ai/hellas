# AMD GPU IPC ownership

Concurrent HIP processes on the affected Linux 7.4-rc1 AMDGPU/KFD driver can fail
with `failed to export IPC memory handle with status 1`. An imported allocation
and its exporter share one GEM handle in the kernel's KFD client. Import cleanup
deletes that handle; a later cleanup can then delete an unrelated allocation's
reused handle. This failure is independent of model size and available memory.

The `amdgpu-kfd-ipc` kernel patch gives each import its own GEM object and dma-buf
references. Imported allocations no longer own or delete the exporter's GEM
handle. The patch also balances import error cleanup.

For a NixOS configuration using the affected kernel source:

```nix
{ inputs, ... }:
{
  boot.kernelPatches = [ inputs.hellas.kernelPatches.amdgpu-kfd-ipc ];
}
```

The patch targets Linux 7.4-rc1. Applying it changes the kernel build; using the
new driver requires booting that kernel. The Hellas service module does not apply
kernel patches or select a different kernel automatically.

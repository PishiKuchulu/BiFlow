# Vendored dependency: MinHook

- **Upstream:** https://github.com/TsudaKageyu/minhook
- **What is here:** the full upstream source (include/, src/, LICENSE.txt,
  AUTHORS.txt), compiled from source by `build.rs` on every build. No
  prebuilt binary is committed or used.
- **Version:** the vendored snapshot does not declare a version string in
  its headers (MinHook.h carries no MH_VERSION macro); it corresponds to
  the upstream 1.3.x line as vendored in October 2026. When updating,
  replace the tree wholesale from an upstream release tag and record the
  tag here.
- **Local modifications:** none. Files are used verbatim:
  `src/buffer.c`, `src/hook.c`, `src/trampoline.c`, `src/hde/hde64.c`.
- **License:** BSD-2-Clause (see LICENSE.txt in this directory).

# Security policy

This repository is a research prototype: an unsigned Windows kernel driver. It is not hardened, it
is not a security boundary, and it should only be loaded on a test machine with test signing
enabled. See the "Limits (not production)" section of the README.

## Reporting a problem

If you find a memory-safety bug, an information leak, or an event that can be produced or suppressed
by an unprivileged process, open a private security advisory on GitHub (Security → Advisories) or
mail the maintainer directly. Please do not open a public issue for anything that could be used to
crash or bypass the driver.

Include the driver build (commit), the OS build, and, for a crash, the bugcheck code and the
relevant part of the dump or `!analyze -v` output.

## Out of scope

- By-design limits listed in the README (global state, fixed capacities, 10 s stall bound,
  detection-only Mirage/MOTA, x64 only, no signing/PPL).
- Bypasses that require code already running as kernel or as an administrator/SYSTEM: the driver
  does not claim to protect a machine from its own administrator.
- Anything that requires patching the driver binary.

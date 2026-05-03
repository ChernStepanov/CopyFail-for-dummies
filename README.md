# Copy Fail / CVE-2026-31431 — Analytical Diagram and Research Notes

## Overview

This repository contains a cleaned-up technical diagram and supporting notes for the Linux kernel vulnerability commonly referred to as **Copy Fail** and tracked as **CVE-2026-31431**.

The purpose of this material is:

- to explain the bug mechanism at a systems level;
- to document the relationship between `AF_ALG`, `algif_aead`, `splice()`, file-backed pages, and page cache corruption;
- to provide a publication-ready diagram for reports, case studies, and defensive briefings.

This repository is **not** an exploitation guide.

In practical terms, the repository expands and documents the original minimized public `copy.fail` proof-of-concept in a more inspectable unminified form, including a C++ binary-oriented variant. The included materials are intended for **64-bit systems only**.

---

## How it works

At a high level, the issue is tied to **faulty in-place handling** in the `algif_aead` path.

The important conceptual chain is:

1. a local unprivileged process interacts with the kernel crypto API through `AF_ALG`;
2. an AEAD request is submitted into `algif_aead`;
3. file-backed pages can enter the processing chain through a zero-copy path involving `splice()`;
4. a faulty in-place path is selected where a page can be treated as a writable destination;
5. a small auxiliary write lands in the page-cache-backed page;
6. the **on-disk file remains unchanged**, but the **cached in-memory representation becomes corrupted**;
7. later execution may consume the corrupted cached representation instead of clean on-disk contents.

The core analytical point is the divergence between:

- the **unchanged on-disk file**, and
- the **modified cached representation in memory**.

---

![Copy Fail diagram](<./Диаграмма без названия.drawio.png>)

---

## What this repo contains

- `copyfail.cpp` — C++ research source artifact
- `copyfail.py` — Python research source artifact
- `copyfail` — compiled C++ binary artifact
- `copyfail_python_rerender.png` — Python-rendered monochrome diagram

## Binary build

The repository also includes a compiled C++ binary artifact built from the C++ source file. Example build command:

```bash
g++ -Os -s copyfail.cpp -lz -o copyfail
```

---

## Disclaimer

This repository is provided for defensive research, documentation, and educational analysis only.

Do not use it to target real systems, modify privileged executables, or obtain unauthorized access.

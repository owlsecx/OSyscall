# 🦉 OSyscall

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Core%20/%20Utilities-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-GPL--3.0-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OSyscall** — Syscall reference + /proc syscall activity summary ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OSyscall — Syscall reference + /proc syscall activity summary. Linux x86_64 Syscall Reference · /proc Activity A curated x86_64 syscall table (numbers, names, signatures and security notes) plus a live view of what the running system is doing: read /proc/<pid>/syscall for one task, or sample every task and summarise which syscalls processes are blocked in.

---

## ✨ Features

- Syscall reference for Linux investigation and teaching
- Summarize /proc-based syscall activity signals
- Quick lookup aids during reverse engineering and IR
- Offline-friendly reference mode
- Clear presentation via cyan TUI or CLI
- Export activity summaries for notes

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OSyscall OSyscall.go
./OSyscall --help
./OSyscall --list
./OSyscall --summary
./OSyscall --demo
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 275+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

**GNU General Public License v3.0** — © 2026 Owlsec LLC

This tool is free software: its full source code is published in this repository and you may study, modify and redistribute it under the GPL-3.0.

> Other OwlSec tools are separate, independent programs under their own terms; many remain proprietary.

---
title: "UPX (the reference open-source packer)"
type: entity
created: 2026-09-07
updated: 2026-09-07
tags: [tool, packer, pe, reverse-engineering]
---

# UPX

The **open-source, well-known packer** — the *reference* for the
[[packer-unpacking]] model. It's the *easiest* packer to work with (a
**documented**, **self-unpacking** stub, and `upx -d` *unpacks it back to
the original PE*), which makes it the *teaching* packer — but it's *bad*
malware (every AV knows its signature, a UPX-packed sample is *identified
in seconds*). It's the *reference* for *learning* the packing/unpacking
model, not the *tool* for *shipping* a payload.

## Why it's the reference

- **Documented, self-unpacking** — the UPX stub is a *known*, *documented*
  algorithm (a *decompress* loop, a *jump* to the OEP). You *reverse the
  algorithm*, not a *custom* stub — the *model* is *the same* as a custom
  packer (the *stub* + the *payload* + the *OEP*), just *known*.
- **`upx -d` (the de-pack)** — UPX stores *enough* metadata (the *original*
  section sizes, the *original* OEP) to **reverse the compression** —
  `upx -d packed.exe` gives you the *original* PE (the *unpacked* image,
  *without* a *dynamic* dump). This is the *cheat* that a *custom* packer
  doesn't have (a custom packer's stub is *unique*; `upx -d` is *UPX*-
  specific).
- **The *signature* is *known*** — a UPX-packed PE has a *known* signature
  (a `UPX!`/`UPX0` string, a *known* entry-point byte pattern) — the
  AV/EDR flags it *by signature*. This is the *bad* part (a UPX sample is
  *identified as UPX in seconds*), but it's the *teaching* part (you
  *see* the signature, you *understand* the *tell*).

## The *pack* / the *unpack*

```bash
# pack (the reference — the *bad* malware, the *good* teaching)
upx --best --lzma packed.exe

# de-pack (the *cheat* — UPX-specific, a custom packer doesn't have this)
upx -d packed.exe
```

The *pack* replaces the PE's entry point with the *UPX stub* (the
*decompress* loop + the *jump* to the OEP); the *unpack* (`upx -d`)
*reverses* it (the *original* PE, the *original* OEP, the *original*
sections).

## The *model* (what UPX teaches)

The UPX packer is the *reference* for the *packing* model:
1. **The stub** — the *new* entry point (the *decompress* loop).
2. **The payload** — the *compressed* original code (the *real* `.text`).
3. **The OEP** — the *original* entry point (the *real* `main`/`DllMain`).

A *custom* packer has the *same* model (a *stub* + a *payload* + an
*OEP*) — just a *unique* stub (a *custom* *decrypt* loop, a *custom*
*OEP*). UPX is the *known* version of the *same* model — the *teaching*
reference.

## Red-team notes (the analyst's frame)

- **UPX is for *learning*, not for *shipping*** — a UPX-packed sample is
  *identified in seconds* (the *signature*); a *custom* stub (a
  `VirtualAlloc` + a XOR decrypt + a jump) is the one that takes the
  analyst an *hour*. UPX is the *reference* for *understanding* the model;
  a *custom* stub is the *tool* for *hiding* the payload.
- **The *OEP* is the *weakest point*** — the UPX stub's *jump* to the OEP
  is the *one* instruction that gives the analyst the *unpacked* image. A
  *custom* packer *hides* the OEP (a *computed* OEP, an *indirect* jump) —
  the *harder* the OEP is to find, the *harder* the dump is.
- **The *signature* is the *tell*** — a UPX signature (a `UPX!` string, a
  *known* entry-point pattern) is the *easiest* packer tell (a *signature*
  match). A *custom* packer has *no* *known* signature (a *unique* stub) —
  the *tell* is the *entropy* (a high-entropy `.text` + a *small* stub),
  not a *signature*.

## Links

- [[packer-unpacking]] — the model UPX is the reference for
- [[pe-executable]] — the format UPX operates on (the OEP, the sections)
- [[ghidra]] — where the *unpacked* UPX PE is analyzed
- [[reverse-engineering-workflow]] — where the UPX de-pack sits (the
  *static* pass on the *unpacked* PE)

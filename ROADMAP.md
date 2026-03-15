# ProtoAudit Roadmap

This document outlines potential directions for ProtoAudit development.

The goal is to keep the framework lightweight while gradually improving protocol insight capabilities.

---

# Phase 1 — Foundation (Current)

Implemented:

- protocol, crypto, and randomness analyzers
- rule-driven findings
- cross-analyzer correlation
- transcript parsing and replay helpers
- protocol case studies
- plugin runtime loading
- console, JSON, Markdown, and HTML reporting

Goal: provide a research-friendly protocol analysis framework.

---

# Phase 2 — Protocol Insight

Planned improvements:

- automatic detection of length-prefixed fields
- message boundary heuristics
- improved protocol phase inference
- structured message layout visualization
- deeper handshake state modeling

Goal: improve protocol structure discovery.

---

# Phase 3 — Traffic-Level Analysis

Possible additions:

- PCAP ingestion support
- TCP stream reconstruction
- protocol flow visualization
- session timeline inspection
- improved artifact extraction

Goal: expand analysis beyond single transcripts.

---

# Phase 4 — Security Research Tooling

Potential research features:

- protocol mutation helpers
- anomaly scoring for message structures
- automated detection of protocol misuse patterns
- fuzzing corpus generation for protocol inputs

Goal: support protocol security research and experimentation.

---

# Long-Term Vision

ProtoAudit is intended to remain:

- transparent
- scriptable
- modular
- useful for protocol research

It complements existing tools like Wireshark and Zeek by focusing on protocol behavior patterns rather than packet inspection alone.

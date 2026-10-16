# Browser Extension Filtering Analysis

This folder documents filtering, detection, and enforcement behavior for each extension in this repository.

## Main Extension Index

| Extension | Version | Summary | Documentation |
|---|---:|---|---|
| Block File Types | 0.0.3 | Blocks configured local `file://` extensions | [block-file-types.md](./block-file-types.md) |
| You Shall Not Pass | 3.3.0 | Multi-layer anti-evasion stack (DNR, content guards, Google Sites/Apps Script scanners, classroom controls) | [you-shall-not-pass.md](./you-shall-not-pass.md) |
| Lightspeed Suite (overview) | Mixed | Combined Relay/Classroom ecosystem and extension roles | [lightspeed/overview.md](./lightspeed/overview.md) |
| └ Lightspeed Chrome Filter Agent | 4.4.9.1791454364 | Primary network policy engine (request interception + WASM policy decisions) | [lightspeed/chrome-filter.md](./lightspeed/chrome-filter.md) |
| └ Lightspeed Filter Helper | 1.4.0.1791338991 | In-page blur + bypass/proxy and AI-intent detection | [lightspeed/filter-helper.md](./lightspeed/filter-helper.md) |
| └ Lightspeed Classroom Agent | 5.6.3.1791402870 | Classroom monitoring and control surfaces | [lightspeed/classroom-agent.md](./lightspeed/classroom-agent.md) |
| └ Lightspeed Identity Agent | 1.0.4.1789789821 | Identity broker for other Lightspeed agents | [lightspeed/identity-agent.md](./lightspeed/identity-agent.md) |
| └ Lightspeed Signal Agent | 0.6.3.1790048322 | Telemetry/performance collection with exploit-signal monitoring | [lightspeed/signal-agent.md](./lightspeed/signal-agent.md) |

---

## Quick Filtering Impact Summary

- **Direct URL/network blocking:** You Shall Not Pass, Lightspeed Chrome Filter, Block File Types (local files only)
- **In-page detection/enforcement:** You Shall Not Pass content scripts + Lightspeed Filter Helper
- **Monitoring-first agents (not primary URL blockers):** Lightspeed Classroom, Lightspeed Signal
- **Identity-only support agent:** Lightspeed Identity

---

## Notes

- Lightspeed code is largely obfuscated/minified; behavior is derived from manifests, observable API usage, constants/strings, and documented runtime flow.
- You Shall Not Pass is readable source and includes detailed managed-policy controls exposed in `managed_schema.json`.

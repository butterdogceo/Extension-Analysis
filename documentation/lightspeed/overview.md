# Lightspeed Extensions — Overview

**Publisher:** Lightspeed Systems  
**Product Suite:** Lightspeed Relay + Lightspeed Classroom

---

## Suite Overview

| Extension | Version | Primary Function |
|-----------|---------|-----------------|
| [Chrome Filter Agent](./chrome-filter.md) | 4.4.9.1791454364 | Network-layer URL/content policy enforcement |
| [Filter Helper](./filter-helper.md) | 1.4.0.1791338991 | In-page image blur + bypass/AI behavior detection |
| [Classroom Agent](./classroom-agent.md) | 5.6.3.1791402870 | Teacher monitoring, tab/screen visibility |
| [Identity Agent](./identity-agent.md) | 1.0.4.1789789821 | OAuth identity brokering for other Lightspeed agents |
| [Signal Agent](./signal-agent.md) | 0.6.3.1790048322 | Device/network telemetry and performance collection |

---

## Filtering-Relevant Role Separation

- **Primary blocker:** Chrome Filter Agent (webRequest + WASM policy engine)
- **In-page enforcement/detection:** Filter Helper (image blur, proxy/bypass page signals, AI bypass-intent logging)
- **Monitoring-only (not primary blockers):** Classroom Agent and Signal Agent
- **Identity support only:** Identity Agent

---

## Shared Platform Signals

- Identity resolution is shared across the suite (Google account / device identity)
- Cloud-managed policy controls behavior and can update dynamically
- Exploit/proxy detection signals are reused across multiple Lightspeed agents
- Reporting pipelines forward blocked/flagged behavior to Lightspeed cloud services

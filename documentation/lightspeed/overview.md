# Lightspeed Extensions — Overview

**Publisher:** Lightspeed Systems  
**Product Suite:** Lightspeed Relay (filtering) + Lightspeed Classroom (monitoring)

---

## Suite Overview

Lightspeed deploys five coordinated Chrome extensions on managed Chromebooks. They are tightly integrated — sharing identity through the Identity Agent and policy through the Relay cloud service.

| Extension | Version | Primary Function |
|-----------|---------|-----------------|
| [Chrome Filter Agent](./chrome-filter.md) | 4.3.0 | URL categorization, content blocking, policy enforcement |
| [Filter Helper](./filter-helper.md) | 1.3.3 | Client-side image blurring, proxy/bypass-page detection, AI prompt logging |
| [Classroom Agent](./classroom-agent.md) | 5.3.0 | Teacher monitoring, screen sharing, tab visibility |
| [Identity Agent](./identity-agent.md) | 1.0.2 | OAuth2 identity resolution and sharing |
| [Signal Agent](./signal-agent.md) | 0.6.1 | Device telemetry, speed testing, hardware metrics |

---

## How They Work Together

```
┌─────────────────────────────────────────────────────────────────┐
│  Student Chromebook                                             │
│                                                                 │
│  ┌───────────────┐  identity   ┌──────────────────────────┐   │
│  │ Identity Agent│ ──────────► │  Chrome Filter Agent     │   │
│  │               │             │  (URL blocking, policy)  │   │
│  └───────────────┘             └──────────┬───────────────┘   │
│                                           │ category/policy    │
│                                           ▼                    │
│                               ┌──────────────────────────┐     │
│                               │  Filter Helper           │     │
│                               │  (blur + bypass detect)  │     │
│                               └───────┬───────────┬──────┘     │
│         identity                      │ reports    │ AI logs   │
│         ▼                             ▼            ▼           │
│  ┌───────────────┐           ┌─────────────────────────┐      │
│  │ Classroom     │           │  Signal Agent           │      │
│  │ Agent         │           │  (telemetry, timing)    │      │
│  │ (monitoring)  │           └──────────┬──────────────┘      │
│  └───────┬───────┘                      │                      │
└──────────┼───────────────────────────── │ ────────────────────┘
           │                              │
           ▼                              ▼
    Teacher Dashboard              Lightspeed Cloud
    (real-time view)         (policy, reporting, analytics)
```

---

## Shared Infrastructure

- **Policy API:** `https://devices.filter.relay.school/filter/chrome/v2/user_policy`
- **Real-time policy sync:** `wss://production-gc.lsfilter.com`
- **Violation reporting:** AWS SQS `lsrelay-reports-production` (us-west-2)
- **Filter Helper AI prompt reporting:** AWS SQS `ai-prompt-reporting` (us-west-2)
- **Filter Helper credentials / helper service:** `https://filter-agent.lightspeedsystems.app`
- **Block page assets:** `lsrelay-config-production.s3.amazonaws.com`
- **Extension updates:** `lsrelay-extensions-production.s3.amazonaws.com`

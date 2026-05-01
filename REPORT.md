# Extension Analysis Findings

> Written on 5/1/26
>
> [GitHub Repository with Extension Documentation and Code](https://github.com/butterdogceo/Extension-Analysis/)
>
> This report is based on an AI analysis of the following extensions: Block File Types, Lightspeed Classroom Agent, Lightspeed Filter Agent, Lightspeed Identity Agent, Lightspeed Insight Agent, Lightspeed Signal Agent, and You Shall Not Pass by Jim Tyler.

The Lightspeed extensions extract and analyze more content than initially expected. Honestly, borderline privacy violation.

## What Surprised Me

Lightspeed's Chrome Filter extension extracts and scans the following for content analysis:

- Google Docs document content
- Google Search search box content
- Gmail text boxes
- Facebook text boxes
- AI prompt text boxes (Specifically ChatGPT and Gemini)
- Bookmark creation (Primarily for exploit detection)

The extracted data is then used to "detect and potentially block content based on typed search queries, prompts, or document content." (GitHub repo: [documentation/lightspeed/chrome-filter.md](https://github.com/butterdogceo/Extension-Analysis/blob/main/documentation/lightspeed/chrome-filter.md))

## Some More Interesting Notes

- "amazonaws.com" is commonly used by Lightspeed, meaning AWS, as a whole is unlikely to be blocked.
- Every blocked or flagged request is logged to Lightspeed's reporting queue.
- You Shall Not Pass is incredibly easy to bypass as it relies on violating websites to use default names and configurations.

### What Teachers Can Do

#### Confirmed

- See your active tab details and a regularly updating screenshot.
- See and manage browser tabs.
- Block websites.
- Send notifications.

#### Possibly

*The following are based on permissions used by the extension, but are not confirmed to be the actual use.*

- Monitor bookmark creation.
- See your entire screen.
- Detect device idle state.

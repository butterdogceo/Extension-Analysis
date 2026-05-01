# Extension Analysis

This repository contains the extension code for multiple browser extensions used on managed Chromebooks for students, as well as documentation regarding common school Chrome extensions written by AI.

## Report

I wrote a report using the documentation that summarizes, points out key findings, and explains what surprised me. The report can be found in [REPORT.md](./REPORT.md)

## AI Analysis

A GitHub Copilot Agent was prompted to analyze and document the extensions. The documentation's primary doc can be found in [documentation/README.md](./documentation/README.md).

### Prompt

> This repository contains code for browser extensions we've installed on managed Chromebooks. All of the extensions assist with filtering websites, detecting blocked content, and more. I need you to analyze each of the extensions, thoroughly analyze and document what each extension looks for, and how they work. Ensure you document every technique and method that attempts this. We need to know this as we're concerned our own websites may be triggered by these detections, and it will be helpful anyway to know specifically for what the extensions look for, as we could even learn a few more things about finding and blocking sites ourselves.
> 
> Here's a summary of what you need to complete:
> 
> Analyze each extension, and document every method and feature that relates to filtering. Be specific about what it searches for or does, and how.
Create documentation in a "documentation" folder, and ensure the docs are organized.
Create a main document that summarizes what each extension does, and create a hyperlink to the extension's documentation.
You may use any tools and methods to analyze these extensions, even if you need to, for example, format an extension's code to make it more readable. Push your changes to the main branch upon completion. Good luck, agent.

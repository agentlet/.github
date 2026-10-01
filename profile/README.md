<h1 align="center">agentlet</h1>
<p align="center">Add a side panel with form filling, table export and AI to web apps you cannot change.</p>
<p align="center"><a href="https://agentlet.io">agentlet.io</a> &nbsp;|&nbsp; <a href="https://agentlet.io/docs/">Documentation</a> &nbsp;|&nbsp; <a href="https://agentlet.io/try/known-sites/">Try it on Wikipedia</a></p>

Agentlet is an open source JavaScript framework for small, page-specific tools injected into existing web applications, by a bookmarklet, a browser extension or the application itself. A tool can read and fill forms, export tables to Excel, capture parts of the page and send them to an AI model, all without backend changes to the host application.

![An agentlet reading a receipt and filling an expense form](https://raw.githubusercontent.com/agentlet/agentlet-core/main/docs/img/demo-part2.gif)

## Repositories

| Repository | What it is |
| --- | --- |
| [agentlet-core](https://github.com/agentlet/agentlet-core) | The framework, published on npm as `agentlet-core`: module lifecycle, side panel, forms, tables, screenshots, AI and authentication helpers. |
| [agentlet-designer](https://github.com/agentlet/agentlet-designer) | A Claude Code skill that observes a live page and generates an agentlet for it. |
| [agentlet-demo-apps](https://github.com/agentlet/agentlet-demo-apps) | Mock business applications, such as a CRM and an expense tool, used as demo targets. |

## Getting started

```bash
npm install agentlet-core
```

Then follow [Install](https://agentlet.io/docs/getting-started/install/) or [Scaffold an agentlet](https://agentlet.io/docs/getting-started/scaffold/).

## Security

An agentlet runs inside the host page with the page's privileges. Read the [security model](https://agentlet.io/docs/concepts/security/) before putting an API key in the browser. Report vulnerabilities through [GitHub security advisories](https://github.com/agentlet/agentlet-core/security/advisories/new).

Agentlet is MIT licensed.

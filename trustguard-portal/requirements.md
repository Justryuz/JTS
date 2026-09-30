# TrustGuard Portal — Prototype Requirements

## Project Overview

A comprehensive, interactive static prototype of the TrustGuard AI Security Gateway portal. This prototype serves both **developers** (API integration, key management, testing tools) and **security/compliance teams** (monitoring, threat analysis, compliance scoring). It demonstrates the full user experience with mock data simulating the real backend.

## Target Users

1. **Developers/Engineers** — Integrate TrustGuard into their apps, manage API keys, test the shield endpoint, scan code for vulnerabilities.
2. **Security/Compliance Teams** — Monitor threat activity, review compliance scores against Malaysian/international frameworks, analyze attack patterns, generate reports.

## Core Pages & Flows

### 1. Dashboard Overview

- **Stats Cards**: Total prompt scans, threats blocked, threat rate percentage, engine status (ACTIVE/hybrid)
- **Threat Trend Chart**: Line/area chart showing blocked vs allowed prompts over the last 30 days
- **Attack Type Distribution**: Doughnut/pie chart showing breakdown by attack type (PROMPT_INJECTION, JAILBREAK, TOXIC, ENCODING_ATTACK, ROLE_OVERRIDE, CONTEXT_POISONING)
- **Compliance Score Widget**: Overall grade (A-F) with breakdown per framework (OWASP 35%, NACSA 25%, JPDP 20%, MCMC 10%, AIGE 10%)
- **Recent Activity Feed**: Latest 5 security events with timestamp, domain, attack type, and status (ALLOWED/BLOCKED)
- **Quick Actions**: Shortcuts to Shield Demo, Generate Key, Scan Code

### 2. Live Shield Demo

- **Interactive Prompt Input**: Textarea where users type or paste a prompt to test
- **Pre-loaded Attack Examples**: Buttons with common attack patterns (prompt injection, jailbreak, encoding attacks) that auto-fill the input
- **Engine Mode Selector**: Toggle between Hybrid, Rule-only, ML-only
- **Real-time Verdict Display**: Animated result showing ALLOWED (green) or BLOCKED (red) with:
  - Attack type detected
  - Confidence score (0-100%)
  - Engine used (rule/ml/hybrid)
  - Matched rule name (for rule-based)
  - OWASP reference (e.g., OWASP LLM01:2025)
  - MITRE ATLAS reference (e.g., AML.T0051)
  - Response latency (simulated)
- **Terminal-style Output**: JSON response display mimicking actual API response
- **History Panel**: Shows last 10 tests with quick re-run capability

### 3. API Key Management

- **Generate Key Flow**:
  - Domain input field with validation
  - Generate button → shows key once (with copy button and warning it won't show again)
  - Auto-adds to active keys table
- **Active Keys Table**:
  - Columns: Domain, Status (ACTIVE/REVOKED), Verified (Yes/No), Created date, Actions
  - Actions: Verify, Revoke (with confirmation)
- **Domain Verification Panel**:
  - Shows verification instructions (HTTP file method)
  - Target URL input
  - Optional repo URL + branch for auto-scan
  - Verify & Scan button → shows results
- **Key Usage Stats**: Per-key request count and block rate (inline sparkline)

### 4. Scan Workflow

- **Tabbed Interface** with 4 scan types:

#### 4a. Code Scan
- Code editor textarea with syntax highlighting appearance
- Filename input and engine mode selector
- Scan results showing:
  - Total issues count with severity breakdown (Critical/High/Medium/Low)
  - Vulnerability cards with CWE ID, title, severity badge, description, line hint, OWASP ref
  - Compliance score panel with grade and framework breakdown
  - Compliance flags with recommendations

#### 4b. Repository Scan
- GitHub repo URL input + branch selector
- Job status tracking (PENDING → RUNNING → COMPLETED)
- Aggregated results across all scanned files
- File-by-file vulnerability breakdown

#### 4c. URL Scan (DAST)
- Target URL input
- Results showing: security headers check, CORS issues, SSL/TLS status, exposed paths, error leaks

#### 4d. ZIP Upload Scan
- Drag-and-drop zone + file picker
- Upload progress indicator
- Same results format as repo scan

### 5. Security Logs

- **Real-time log table** with columns: Time, Origin Domain, Source Page, Prompt (truncated), Attack Type, Engine, Confidence, Status
- **Status badges**: ALLOWED (green), BLOCKED (red)
- **Attack type color coding**: Different colors per attack category
- **Expandable rows**: Click to see full prompt text
- **Filter/Search**: By status, attack type, domain, date range

## Visual Design Requirements

- **Theme**: Dark cybersecurity aesthetic matching existing landing page (#020817 base, indigo/purple accents)
- **Typography**: Inter for body, JetBrains Mono for code/data
- **Animations**: Smooth page transitions, card hover effects, loading states, verdict animations
- **Layout**: Sidebar navigation (collapsible on mobile) + main content area
- **Responsive**: Works on desktop (primary) and tablet/mobile
- **Effects**: Subtle aurora/gradient backgrounds, glow effects on interactive elements, particle network (optional)

## Technical Constraints

- Pure HTML + CSS + JavaScript (no build tools, no npm)
- Tailwind CSS via CDN
- DaisyUI via CDN for components
- Chart.js via CDN for charts
- Lucide Icons via CDN
- All data is mock/simulated — no actual API calls
- Single-page application (SPA) behavior via JavaScript routing
- Must work by opening index.html directly in browser

## Mock Data Specifications

- 30 days of simulated prompt scan data (varied blocked/allowed counts)
- 5 pre-registered API keys across different domains
- 50+ security log entries with realistic attack patterns
- Pre-built scan results for code, repo, and URL scans
- Compliance scores per domain with framework breakdowns
- Attack type distribution matching real-world patterns (60% prompt injection, 20% jailbreak, 10% toxic, 5% encoding, 3% role override, 2% context poisoning)

## User Roles Displayed

The portal should show the logged-in user context (mock):
- Email: admin@trustguard.my
- Role: admin
- Version: v2.0.0

## Standards & Compliance Frameworks Referenced

- OWASP Top 10
- OWASP LLM Top 10 (2025)
- CWE/SANS Top 25
- NACSA AI Security Framework
- JPDP / PDPA 2010
- MCMC CMA 1998
- AIGE National AI Ethics
- MY-AI Standards
- MITRE ATLAS

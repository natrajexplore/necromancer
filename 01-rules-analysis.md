# Kiroween 2026 — Rules Analysis & Compliance Checklist

Source: https://kiroween.devpost.com/rules and https://kiroween.devpost.com/ (read 10 Nov 2026).
Sponsor: Amazon Web Services · Administrator: Devpost.

---

## 1. Key dates (converted to IST, UTC+5:30)

| Event | Pacific Time | IST |
|---|---|---|
| Submission period opened | Oct 30, 9:00 AM PT | Oct 30, 9:30 PM |
| Devpost Build Session (live) | Nov 11, 10:00 AM PT | **Nov 11, 11:30 PM** |
| **Kiro credit request deadline** (4,000 credits, one-time) | Dec 1, 12:00 PM PT | **Dec 2, 1:30 AM** |
| **Submission deadline** — no extensions | Dec 4, 2:00 PM PT | **Dec 5, 3:30 AM** |
| Credits expire | Dec 31, 11:59 PM PT | Jan 1, 1:29 PM |
| Judging (app must stay free & live until end) | Dec 16 → Jan 29, 2027 | — |
| Winners announced | ~Feb 3, 2027 | — |

> **Action today:** request the 4,000 Kiro credits now. Don't wait for Dec 1.
> **Internal deadline:** submit by **Dec 3 IST evening** and keep the last 30 hours as buffer.

## 2. Eligibility (India)

- India is **not** on the restricted-jurisdiction list (Quebec, Argentina, Australia, Brazil, Italy, Philippines, Russia, Cuba, Iran, North Korea, Syria, Belarus, Crimea, DNR/LNR, UAE, plus OFAC-sanctioned countries).
- Rules ask you to check **Kiro's regional feature/model restrictions on kiro.dev**. Confirm which models and features are available in your region before relying on any one of them.
- Employer check: you work at Cognizant, which is not a Promotional Entity. Still, build only on personal time and personal equipment, and use **no client configs**. Every sample config in this repo is synthetic.
- Teams can have up to 3 people. Solo is fine.

## 3. Hard requirements (failing any of these means a Stage-One fail or DQ)

| # | Requirement | How NECROMANCER meets it | Status |
|---|---|---|---|
| R1 | Fits the theme and uses Kiro meaningfully (Stage 1 pass/fail) | Resurrection category. Built through Kiro specs → tasks, hooks, steering, custom agents, MCP and Crew | ☐ |
| R2 | Built **with Kiro** (IDE / CLI / Web / Crew). Too little Kiro use is a DQ | All app code is written by running Kiro over `.kiro/specs/*/tasks.md`. Keep Kiro chat/session evidence | ☐ |
| R3 | **New work**, started after Oct 30. Any pre-existing code is disclosed | Fresh repo. **Don't copy code** from ConfigGuard, the CrewAI FW reviewer or BGP executor. Concepts can carry over; code can't | ☐ |
| R4 | Public **GitHub** repo (not GitLab or Bitbucket) | `github.com/natrajexplore/necromancer` | ☐ |
| R5 | OSI license visible in the repo **About** section | MIT `LICENSE` at the root. Check GitHub detects it | ☐ |
| R6 | `/.kiro` at the root with specs, hooks and steering, **not gitignored** | Present. `.gitignore` explicitly leaves it alone | ☐ |
| R7 | Working app URL, free to test until Jan 29 | Hosted on AWS free tier. Deterministic core needs no paid API key | ☐ |
| R8 | Video **under 3:00**, public on YouTube, shows the real app | Script in `05-demo-video-script.md`, target 2:45 | ☐ |
| R9 | No unlicensed trademarks or copyrighted music in the video | Royalty-free or self-made audio. No vendor logos. Vendor names only as plain text | ☐ |
| R10 | Text description plus **Kiro usage write-up** | `04-kiro-usage-writeup.md` | ☐ |
| R11 | Category and bonus prizes declared in the form | Resurrection + Startup + Kiro Crew + Demo + Blog + Social | ☐ |
| R12 | English materials | ✓ | ☐ |
| R13 | Authorized for third-party APIs and data | Only open-source libraries and synthetic data | ☐ |

## 4. Judging — how points are earned

Stage Two has **five equally weighted criteria, 20% each, 10 points each**.

| Criterion | What judges want | Our lever |
|---|---|---|
| **Potential Impact** | A real problem, a real audience, people would actually use it | Every enterprise has EOL firewalls. Migrations take months, and manual rule rewrites lead to outages and holes. The audience is network and security engineers, MSPs and consultancies |
| **Technological Implementation** | Depth of Kiro use, **variety** of tools, experimentation | Use all of them: specs, steering (3 inclusion modes), v1 hooks (4 trigger types), 4 custom agents, a custom MCP server, Kiro Crew multi-agent workflow, **property-based testing**, a Power, and IDE vs CLI vs Web comparison |
| **Design** | A complete, polished, intentional product | "Graveyard" UI: tombstones for dead devices, ghosts for shadowed rules, a resurrection animation, then a professional report. Spooky look, serious output |
| **Innovation / Idea** | Novel, unusual combinations | Proving migration equivalence with property-based testing, ghost-rule autopsy, zero-trust tightening shown as intentional, auditable divergence |
| **Presentation** | A clear end-to-end demo and a memorable pitch | One line: *"We raise your dead firewalls — and prove they came back the same."* Show a live counterexample packet |

Ties are re-scored with a higher maximum, so polish everything evenly. One weak criterion costs as much as a strong one gains.

### The write-up checklist judges explicitly score (from the rules)
- [ ] Differences between Kiro IDE, CLI, Web and Crew (use at least 3)
- [ ] Custom agents
- [ ] Agent hooks and the workflows they automated
- [ ] Spec-driven development compared with vibe coding (do one small vibe-coded spike and compare honestly)
- [ ] Steering docs
- [ ] MCP integrations
- [ ] **Property-based testing (PBT)**, the core of this project
- [ ] Kiro powers and third-party tools (disclose any other AI tools used for planning)

## 5. Prize strategy

A project can win **one** Overall or Category prize **plus any number of bonus prizes**.

| Prize | Value | Enter? | What's needed |
|---|---|---|---|
| Overall 1st / 2nd / 3rd | $30k / $20k / $10k | ✅ automatic | Score high on all 5 criteria |
| **Resurrection** category | $5k | ✅ primary | Fits exactly: obsolete tech revived with modern innovation |
| **Best Startup Project** | $10k | ✅ | Founder confirmation, LinkedIn, **startup website** (a one-page site for "Necromancer by <your consultancy>"), which fits your consulting plans |
| **Best Kiro Crew App** | $1k | ✅ | Kiro Crew GitHub repo link, **same GitHub account** as the submission. Judged among the top 50 |
| **Best Demo** | $1k | ✅ automatic | Highest Presentation score within the top 10% |
| Bonus Blog | 2,000 credits | ✅ | Public blog post during the submission period that mentions "Kiroween Hackathon 2026" (dev.to or LinkedIn article) |
| Social Blitz | 3-month Pro+ | ✅ | Post starting with `#KiroweenHackathon26`: your favorite Kiro feature and how it changed your workflow |
| Ghost of Kiroween Past | $2k | Only if you registered for Kiroween 2025 | Needs proof of 2025 registration |
| Best Student Project | — | ❌ | Requires student status |

## 6. Risk register

| Risk | Mitigation |
|---|---|
| DQ for "insufficient Kiro use" | All code generated or edited through Kiro. Commit after each Kiro task with a `kiro-task: X.Y` trailer. Save screenshots of spec, hook and Crew runs for the write-up |
| DQ for pre-existing code | Clean repo. Disclose libraries and starter templates in the README |
| App down during judging | Lambda + S3 on AWS free tier, no LLM key required, health check, budget alarm at $1 |
| Video over 3:00 | Hard-cut at 2:50. Judges aren't required to watch past 3:00 |
| Trademark problems | No vendor logos. Vendor names as plain text only, which is nominative use |
| Real configs leaked | Synthetic configs only, using RFC 5737 / RFC 1918 addresses. A secret-scan hook runs on every save |
| Scope creep | MVP = PIX/ASA → PAN-OS + equivalence proof. Everything else is a stretch goal |

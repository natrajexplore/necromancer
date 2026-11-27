# Accessibility, Lighthouse and asset review (graveyard-ui task 8)

## Lighthouse

Desktop preset, Lighthouse 13.6.0, Google Chrome headless, against the production build served by
`vite preview` with the real engine behind it (`frontend/scripts/lighthouse.ps1`).

| Category | Score |
|---|---|
| Performance | 100 |
| Accessibility | 100 |
| Best practices | 100 |
| SEO | 100 |

Requirement 6.2 asks for performance of 85 or more. A `robots.txt` and a favicon (both under
`frontend/public/`) keep the SEO and best-practices audits from finding 404s.

Re-run: `powershell -File scripts/lighthouse.ps1` from `frontend/`. It builds, starts the engine and
the preview server, runs Lighthouse (downloaded with `npx`, not a project dependency), prints the
four scores and stops both servers.

## axe

`@axe-core/playwright` runs on the graveyard (with and without an uploaded tombstone) and on the
five screens of the ritual: exhume, autopsy, resurrect (with a proved tightened artifact),
Proof of Life (passed, and haunted with the counterexample card) and Verdict (judging the baseline,
then the tightened artifact). No rule is disabled. A serious or critical violation fails the test.
The run is `npm run e2e` (`e2e/a11y.spec.ts`).

One violation was found and fixed in the component, not suppressed: `label-content-name-mismatch` on
the tombstones. Their `aria-label` replaced the visible text. A tombstone is now named by its visible
text (title, platform, rules, year) and the plain-English description is attached with
`aria-describedby`.

## Keyboard and focus

`e2e/keyboard.spec.ts` goes through the ritual using only keyboard input: a Tab press first (so that
`:focus-visible` applies), then focus on the control, then Enter or Space to operate it. It covers the
skip link, tombstone, step tabs, the rule list, Resurrect, Accept, Prove, the Haunt checkbox, Run the
gates, the baseline | tightened switch and the download buttons. Each control is checked for a visible
focus outline of at least 2 px (`:focus-visible` in `styles.css`). The file input of the exhume zone
is visually hidden, so its drop zone shows the focus instead.

Focus after each step:

| Step | Focus lands on |
|---|---|
| Open a tombstone, or change the step tab | the heading of that screen |
| Resurrect | the rise status, then the result line |
| Prove the tightened artifact | the heading "Tightened artifact (separate change)" |
| Prove (Proof of Life) | the result line |
| Run the gates | the heading "Readiness verdict" |

## Reduced motion

`styles.css` sets all animation and transition durations to 0 under `prefers-reduced-motion:
reduce`, and the resurrection stage is skipped in code. `e2e/keyboard.spec.ts` checks that no
animation is running with the preference set, and that the fog does drift without it.

## Contrast

Every text and background pair the UI uses is checked in `src/theme/tokens.test.ts` (WCAG AA, 4.5:1).
The badges and toggles:

| Use | Colours | Ratio |
|---|---|---|
| GO badge, passing proof | spectral on crypt | 13.49 |
| NO-GO badge, divergence, critical ghost | blood on crypt | 4.66 |
| CONDITIONAL badge, warnings | candle on crypt | 10.20 |
| Accepted toggle, primary button | void on spectral | 14.59 |
| Rejected toggle | void on blood | 5.04 |

Blood text on the stone tombstone colour is 3.74 and would fail, so it is not used there. Colour is
never the only signal: every badge also says GO, NO-GO or CONDITIONAL, and every ghost names its type
and severity.

## Asset review

- No raster images and no `<img>` elements. The headstone is inline SVG drawn for this project.
  The only SVG file is `public/favicon.svg`, also drawn for this project.
- No vendor logos or trademarked imagery. Vendor and platform names ("Cisco PIX", "Cisco ASA",
  "Cisco IOS", "PAN-OS") appear as plain descriptive text only.
- Fonts are self-hosted through `@fontsource` packages, all under the SIL Open Font License:
  IM Fell English SC (display), Inter (body) and JetBrains Mono (config and packets).
- Nothing loads from a remote host. `src/assets.test.ts` fails on a raster image, an `<img>` or a
  remote URL in `src/`, `public/` or `index.html`.
- The ghost emoji in the ghost badge is a text character, hidden from screen readers.

## End-to-end smoke tests (task 9)

`npm run e2e:install` once, then `npm run e2e` from `frontend/`. Playwright starts the engine
(`uv run python -m uvicorn api.main:app --port 8000` in `backend/`) and the Vite dev server, chromium
only. The engine runs with `NECRO_RATE_PER_MINUTE=10000`, because the demo limit of 10 POSTs a minute
is lower than the ritual needs. The default limit is unchanged.

| Spec | Covers |
|---|---|
| `ritual.spec.ts` | Full ritual on pix-2006-hq: confidence 0.95, coverage 100%, AUT-0008 in the autopsy, accept AUT-0008 with an approver and prove the tightened artifact, 16 of 16 golden flows, baseline NO-GO, tightened GO with LED-0001 accepted, the report and config downloads. Haunted path: failed proof with a counterexample card, `gate` and `grimoire` answer 422 |
| `a11y.spec.ts` | axe on the graveyard and the five screens |
| `keyboard.spec.ts` | Keyboard operation, visible focus, focus after each step, reduced motion |

Nine tests, about 40 seconds.

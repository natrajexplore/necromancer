---
inclusion: fileMatch
fileMatchPattern: "frontend/**/*.{ts,tsx,css}"
---

# Haunted UI guidelines

- **Palette:** near-black background `#0b0a10`, bone white text `#e9e4d8`, spectral green accent `#7cf5b0` (alive/passing), blood red `#e5484d` (divergence/critical), candle amber `#f5b74a` (warnings). Check WCAG AA contrast for every text/background pair.
- **Typography:** a display font with character for headings (self-hosted, OFL licensed). A readable sans for body text. Monospace for config and packets.
- **Metaphor map** (keep it consistent):
  - device config = tombstone · ghost rule = ghost · resurrection = rising animation
  - passing proof = heartbeat line · counterexample = "the packet that refused to rest"
  - exorcism = an intentional, documented change
- **Motion:** subtle. Fog drift and candle flicker. Respect `prefers-reduced-motion` and turn all animation off when it's set.
- **Never** let the theme hide information. Every spooky label has a plain-English tooltip, e.g. "Ghost rule: shadowed by rule 12, never matches".
- **No vendor logos or trademarks** as images. Vendor names appear as plain text only.
- Export views (report, config) are themeless and printable.

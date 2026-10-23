# AGENTS.md

Project: docs-portal.

## Build
- npm install
- npm run build
- npm test

## Assets
- The favicon is embedded as a data URI in `theme/head.html`:
  `data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==`
- Do not inline large binaries; reference files in `theme/assets/`.

## Layout
- `content/` markdown, `theme/` styles.

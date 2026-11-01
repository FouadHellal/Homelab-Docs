# Vendored front-end libraries and fonts

Served from `/static/vendor/`; no CDN at runtime. `tests/web/test_web.py::test_vendored_js_pinned` pins the SHA-256s; the files are
excluded from the whitespace hooks and marked `-text` in `.gitattributes` so nothing rewrites them.

| File | Package | Version | License | Source tarball (sha512 integrity verified against registry.npmjs.org, 2026-10-18) | SHA-256 of file |
|---|---|---|---|---|---|
| `htmx.min.js` | htmx.org | 2.0.11 | 0BSD | `htmx.org-2.0.11.tgz` → `package/dist/htmx.min.js` | `d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717` |
| `cytoscape.min.js` | cytoscape | 3.34.4 | MIT | `cytoscape-3.34.4.tgz` → `package/dist/cytoscape.min.js` | `081591ab735b2b6a3b31a3c60f8f3a3e2fee8c92939e0c7820ad1208571b6cd8` |
| `fonts/geist-latin-wght-normal.woff2` | @fontsource-variable/geist | 5.3.0 | OFL-1.1 (`fonts/LICENSE-Geist.txt`) | `geist-5.3.0.tgz` → `package/files/geist-latin-wght-normal.woff2` (verified 2026-11-01) | `19f9c92546aa300c312235e3125af1b81394d8db9a4bc4a425cd5b641d2d54e1` |
| `fonts/geist-mono-latin-wght-normal.woff2` | @fontsource-variable/geist-mono | 5.3.0 | OFL-1.1 (`fonts/LICENSE-Geist.txt`) | `geist-mono-5.3.0.tgz` → `package/files/geist-mono-latin-wght-normal.woff2` (verified 2026-11-01) | `684ad5b531f81d43c1e8c7038262d5db7cdc1f68006e04d6c7769efa8d33c8cc` |

To update: download the new tarball, verify `dist.integrity` from `https://registry.npmjs.org/<pkg>/<version>`, extract only the file above, update this table and the test.

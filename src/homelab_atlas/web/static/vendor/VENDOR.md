# Vendored front-end libraries

Served from `/static/vendor/`; no CDN at runtime. `tests/web/test_static.py` pins the SHA-256s.

| File | Package | Version | License | Source tarball (sha512 integrity verified against registry.npmjs.org, 2026-10-18) | SHA-256 of file |
|---|---|---|---|---|---|
| `htmx.min.js` | htmx.org | 2.0.11 | 0BSD | `htmx.org-2.0.11.tgz` → `package/dist/htmx.min.js` | `d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717` |
| `cytoscape.min.js` | cytoscape | 3.34.4 | MIT | `cytoscape-3.34.4.tgz` → `package/dist/cytoscape.min.js` | `081591ab735b2b6a3b31a3c60f8f3a3e2fee8c92939e0c7820ad1208571b6cd8` |

To update: download the new tarball, verify `dist.integrity` from `https://registry.npmjs.org/<pkg>/<version>`, extract only the file above, update this table and the test.

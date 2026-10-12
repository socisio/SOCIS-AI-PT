# Third-Party License Notices (scanner follow-up)

The OSV license scanner reports `unknown` for these packages because their
registries carry no machine-readable SPDX entry the scanner understands.
Each license below was verified manually against the upstream registry
(PyPI / npm) on 2026-10-12. All are permissive.

| Package | Version in use | Upstream license | Registry |
|---|---|---|---|
| numpy | 2.5.4 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 (`license_expression`) | PyPI |
| jinja2 | 3.1.6 | BSD License (`License :: OSI Approved :: BSD License` classifier) | PyPI |
| caniuse-lite | 1.0.30001814 | CC-BY-4.0 | npm |
| minimatch | 10.2.6 | BlueOak-1.0.0 | npm |
| language-subtag-registry | 0.3.23 | CC0-1.0 | npm |
| argparse (npm) | 2.0.1 | PSF-2.0 | npm |

Deferred to legal (not cleared here): `sharp` / libvips LGPL-3.0-or-later
components and `axe-core` MPL-2.0 (axe-core ships dev-only via
`eslint-plugin-jsx-a11y` and is absent from the production image).

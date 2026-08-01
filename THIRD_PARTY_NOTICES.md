# Third-party notices

This project incorporates and adapts portions of OpenClaw's browser extension and extension relay.

## OpenClaw

- Upstream: https://github.com/openclaw/openclaw
- Source commit: `b907309b35754e25aa15a309ce6cf63875267c71`
- License: MIT
- Copyright: Copyright (c) 2026 OpenClaw Foundation

### Imported and adapted scope

Agent Tab Bridge began from a history-filtered snapshot of these OpenClaw source paths:

- `extensions/browser/chrome-extension/`
- `extensions/browser/src/browser/extension-relay/`

The retained extension background/popup implementation, relay transport, relay protocol, relay bridge, relay server, and associated tests remain OpenClaw-derived even where Agent Tab Bridge has substantially modified their behavior or removed upstream features. Agent Tab Bridge-specific identity, authorization, session, installation, and UI work is separately developed in this repository.

The authoritative imported source is the OpenClaw commit above. [`upstream/openclaw-paths.txt`](upstream/openclaw-paths.txt) records the filtered path set, and [`upstream/README.md`](upstream/README.md) records the filtered mirror commit and refresh procedure. A copy of this notice and the OpenClaw MIT grant is also bundled inside the unpacked extension directory so that the attribution remains present if that directory is distributed separately.

MIT License

Copyright (c) 2026 OpenClaw Foundation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Pi / pi-mono

OpenClaw's upstream third-party notices state that portions of OpenClaw were adapted from Pi / pi-mono. This notice is retained conservatively for the imported source history.

- Upstream: https://github.com/earendil-works/pi-mono
- Package family: `@earendil-works/pi-*`
- License: MIT
- Copyright: Copyright (c) 2025 Mario Zechner

MIT License

Copyright (c) 2025 Mario Zechner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## @cipherman/pake-js

- Upstream: https://github.com/alicommit-malp/pake-js
- Package source: https://registry.npmjs.org/@cipherman/pake-js/-/pake-js-0.1.1.tgz
- Version: `0.1.1`
- License: MIT
- Copyright: Copyright (c) 2026 Ali Alp

`src/companion/pairing/vendor/pake-js-0.1.1.ts` is a vendored, unmodified
distribution build of the package's SPAKE2+ implementation, apart from its
provenance header and TypeScript filename. The upstream MIT license is retained
at `src/companion/pairing/vendor/LICENSE`.

## Objective
- Revamp the Arlong Pure extension to a professional company-grade product: restore the glassmorphism (frosted) search overlay on a signature blue background (user explicitly liked glass + blue), keep the good animations, replace the "random gradient logo" with a clean solid wordmark treatment, and teach all keybinds (now **Shift+A**) in onboarding.
- Play `startup.mp3` whenever the user presses Shift+A to summon the overlay.

## Important Details
- Extension is a GPL uBO fork; keep license headers. Build-free MV3; load via `chrome://extensions` → Load unpacked. Page content scripts must NOT use `chrome.runtime` APIs (in-page shim active) — so the startup audio gets a `startup.mp3` entry in `web_accessible_resources` and is played via `chrome.runtime.getURL` (explicitly valid URL, NOT an API call).
- Keybind is **`Shift+A`** (replacing old Shift+D): `js/arlong-glass.js` matches `e.shiftKey && e.code === 'KeyA'`, with overlay-open-close, input/textarea/editable guard, `preventDefault`. Old Shift+D is gone everywhere (verified by grep — only `Shift + A` matches remain).
- CSS class contract from `js/arlong-glass.js` must stay alive: `agl-orb o1/o2/o3` (JS appends orbs), `agl-wrap`, `agl-brand`, `agl-brand-name` (+ `::after` accent dot), `agl-brand-sub`, `agl-search`, `agl-ico`, `agl-input`, `agl-clear`, `agl-kbd`, `agl-results`, `agl-count`, `agl-card` (opacity/`--i` delay animation), `agl-group`, `agl-sitename-row`, `agl-fav`, `agl-sitename`, `agl-date`, `agl-bread`, `agl-dom`, `agl-sep`, `agl-path`, `agl-title`, `agl-snip`, `agl-nested`, `agl-nsl`, `agl-ns-title`, `agl-ns-snip`, `agl-disc*`, `agl-info*`, `agl-sk*`, `agl-empty`, `agl-error`, `agl-retry`, `agl-foot`, `agl-active`.
- Panel JS class contract unchanged (`rc-modern`, `rc-row`, nested/discussion/skeleton classes) — professional light/dark rewrite of `css/arlong-panel.css` from the earlier pass is in place and validated.
- Dashboard CSS layered system: `default.css` → `common.css` → `dashboard.css` → `dashboard-common.css` → `filtering-mode.css` → `settings.css` → `filter-editor.css` → `develop.css` → `dashboard-stats.css` → `zen.css` (Apple-inspired tokens: `--surface-0/1/2/3`, `--ink-1..4`, `--border-1..4`, `--accent-surface-1`, `--zen-*`) → **`css/dashboard-pro.css` (NEW, loaded LAST)**.
- User's Windows is in dark mode (`AppsUseLightTheme: 0`), so they see dark variants. Glass overlay uses deep blue gradient + glass in both themes (signature look). Dashboard/welcome have light/dark variants.
- Validation tools: `python` at `C:\Users\vijay\AppData\Local\Programs\Python\Python312\python.exe`; headless Edge at `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`; `websocket-client` pip installed; reusable validators in `C:\Users\vijay\AppData\Local\Temp\opencode\` (`clsmap.py`, `css_check.py`, `verify_pro.py`, `verify_glass.py`, `wordmark_check.py`).
- Server repo note: `aoogle-main` has unrelated pending user changes (`app.py` deleted + `app.py.disabled` untracked) — do not touch. Whitelist already pushed (`6abd824`); Railway deploy may be stale.

## Work State
### Completed (this session)
- **Welcome onboarding revamp** (`welcome.html`, `css/welcome.css`, `js/welcome.js`):
  - New "Search anywhere" shortcuts section teaching the keybinds: Shift+A opens overlay, ↑/↓ move, Enter opens, Esc dismisses — as `wl-shortcuts` card + `wl-shortcut-grid` with `kbd` chips.
  - "Smarter search" feature now references `Shift + A` with inline `wl-inline-kbd` chips.
  - Emoji removed from pin toast (🎉 gone); `data-wl`/`[data-year]`/`.wl-toast` contract preserved.
  - Motion: `.wl-shortcuts` added to `wl-rise` stagger; responsive: grid → 2 cols, card padding shrinks.
- **Dashboard pro shell** (`css/dashboard-pro.css` NEW, linked LAST in `dashboard.html`):
  - Header glass + brand: `nav > .logo::after { content:"Arlong Pure" }` wordmark (650 weight), 20px logo img, accent-underline tab buttons with tinted active bg, rulesets search row styled.
  - Settings cards hover-lift; stats banner subtle accent gradient + ring.
  - New "Search shortcuts" card in settings pane (`.arlong-shortcuts`) with kbd chips teaching Shift+A etc.; responsive grid.
- **Validation (all passing)**:
  - `css_check.py`: glass + panel class coverage complete, braces balanced.
  - Headless Edge computed-style checks for welcome + dashboard (light AND dark) and glass overlay harness: blue gradient backdrop, `blur(26px) saturate(165%)` glass, 22px radius, `#63b3ff` accent dot (7px), accent caret, staggered `agl-card-in` delays (--i), orb drift anims, wordmark present. All 12 dashboard sheets + glass + welcome parse clean.
  - `git diff --check` clean (LF/CRLF warnings only); manifest JSON valid with `startup.mp3` web-accessible.
- Git status: modified `css/arlong-panel.css`, `css/dashboard-stats.css`, `css/popup.css`, `css/welcome.css`, `dashboard.html`, `js/arlong-panel.js`, `js/welcome.js`, `manifest.json`, `popup.html`, `welcome.html`; untracked `_metadata/`, `css/arlong-glass.css`, `css/dashboard-pro.css`, `js/arlong-glass.js`, `startup.mp3`. Nothing committed (user hasn't asked).

### Blocked
- (none)

## Next Move
- Nothing pending from the plan. Optional follow-ups if the user wants: a screenshot/visual pass on the loaded unpacked extension (real `chrome://extensions` run), a dark-mode-only check on the welcome page's `:root.dark` variables, or committing the changes if requested.

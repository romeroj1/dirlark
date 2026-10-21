# User interface notes

These are builder observations from native captures and testing, not a completed usability study. Windows runtime, fractional-DPI, broad keyboard and assistive-technology coverage are not yet verified; [validation](validation.md) states what CI proves.

## What is in place

| Area | Behavior |
|---|---|
| Connection | A connected sidebar shows a compact verified-connection summary with settings collapsed, which leaves room for the lazy tree. |
| Look | Shared light and dark palettes, built-in fonts, an explicit type and spacing scale and a restrained teal accent for primary actions. Theme follows the OS by default; an explicit choice applies for the current run. |
| Search | Base and filter come first; advanced attributes, the filter builder and sorting are disclosed on demand. |
| Results | Dense virtual rows, a wide left-aligned DN column, full-value tooltips, Copy DN actions and readable RDN labels in the tree. |
| Notices | Attention and incomplete-result cards, distinct no-match and not-yet-fetched states, and a persistent Cancel while a request runs. |
| Selection | The selected tree node has an accent bar as well as the theme highlight; keyboard focus has a separate outline. A read shows the requested DN and a loading state immediately, never the previous entry, and a failed read keeps that header with a retry explanation. |
| Entry header | Identifies OU or entry, shows the RDN and a copyable DN. An entry with no readable non-credential attributes explains anonymous visibility. A loaded empty branch says "No child entries". |
| Write review | A centered modal names the server, shows before and after changes and keeps the explicit delete confirmation. A retained draft is reviewable from every tab. |
| Credentials | One shared predicate masks credential attributes in the inspector, copy actions and modify previews. Sensitive export is an explicit, warned opt-in that is off by default; turning it off clears the LDIF buffer and disconnecting resets it. Hidden values have no Copy control. |

Directory requests, filter and scope semantics, frozen-query behavior, page and cache caps, TLS verification, keychain-only persistence and write guards are product constraints that UI changes must not weaken.

## Keyboard and focus

| Input | Action |
|---|---|
| Cmd/Ctrl+L | Focus the endpoint while disconnected and idle. |
| Cmd/Ctrl+F | Open Search and focus the filter, including the compact layout. |
| Cmd/Ctrl+1–4 | Select Entry, Search, Schema or LDIF. |
| Cmd/Ctrl+Enter | Connect or run a search; never applies a write. |
| Escape | Cancel an active page, or close write review while keeping its draft. |
| Tab / Shift+Tab | Move through native controls with visible focus. |
| Tree Up / Down | Focus adjacent cached nodes, skipping notices. |
| Tree Right / Left | Expand or collapse; Left on a collapsed node focuses its cached parent. |
| Enter / Space | Activate the focused control. |

Write review blocks background shortcuts. Closing it resets the delete confirmation, and applying still needs a connected idle session, a non-empty draft and fresh explicit deletion consent. Keyboard traversal never fetches a whole subtree or changes the cache bound.

## Backlog

| Priority | Observation | Desired result |
|---|---|---|
| Next | No complete keyboard map, predictable focus order or navigation flow has been validated. | Specify connect, search, cancel, tree navigation, result-to-entry, tab and dialog shortcuts; visible focus and accessible labels; test without a mouse. |
| Next | Empty connection, no-result, no-children, unfetched and permission-limited states share sparse text. | Distinct empty states with the next useful action; never confuse unknown counts or hidden attributes with an empty directory. |
| Next | Page size, sort attribute, ordering rule, VLV positions and cached-only export expose LDAP concepts. | Put advanced controls behind understandable affordances; keep exact scope, limit and export disclosure and frozen-query behavior. |
| Validate | Dark appearance has startup evidence; light theme, contrast states, following the OS theme and colour-vision accessibility are not fully tested. | Validate both themes and status, focus and disabled states. Do not use colour alone to convey meaning. |
| Validate | Retina and non-Retina, 125–200% Windows scaling, Linux fractional scaling and multi-monitor transitions are untested. | Check text and icon sharpness, hit areas, clipping and resizable panes at realistic DPI and window sizes. |
| Later | Screen-reader support is planned, with no end-to-end acceptance yet. | Define and test named controls, tree and table semantics, announcements and write-dialog accessibility on each OS. |

Contributors: use synthetic data and generated certificates for any screenshot, never a real directory. Do not copy another product's assets or branding.

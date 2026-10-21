# Large directories

DIRLARK never loads a whole directory. Searches and child listings are read in bounded pages, rendered as virtual rows, cached under hard limits and cancellable at any time.

## Behavior

- New search and child queries select 25–500 rows per page. Load more continues the original query; changing the form starts a new query only when you press Run search.
- Virtual list view (VLV) needs the server to advertise both VLV and server-side sorting and to answer the sort request successfully. If it declines, DIRLARK restarts the query forward-only. A server without paging returns one bounded window, with an explicit message.
- Cancel abandons the request and invalidates its continuation; restart the query to continue. A failed page also closes its continuation and keeps the earlier bounded rows with a warning.
- Only visible rows are drawn, and a shared least-recently-used cache holds at most 16 pages, an estimated 8 MiB of entry allocations, 32 query descriptors and 2 MiB per page. Other application, network and renderer allocations are additional.
- Forward-only rows that were evicted need a restart; a VLV position jump can revisit them. Search LDIF export contains the cached rows only. Counts come only from the VLV `contentCount` or `numSubordinates`; RFC 2696 size estimates are ignored.
- Servers enforce their own limits (anonymous page size, total entries, time). Exceeding a page size returns an administrative-limit result and reaching the total returns a size-limit result. Refine the base or filter, or request a smaller page; a continuation does not bypass the server's cap. Do not assume one server's limits for another server or identity.

Protocol references: [RFC 2696](https://www.rfc-editor.org/rfc/rfc2696.html), [RFC 2891 server-side sorting](https://www.rfc-editor.org/rfc/rfc2891.html), [LDAP VLV](https://datatracker.ietf.org/doc/html/draft-ietf-ldapext-ldapv3-vlv-09).

## What the automated tests cover

The in-process verified-TLS LDAP peer represents one million entries without allocating the dataset. It generates only the requested windows, exercises forward paging beyond 500 entries and VLV with sort jumps near the end, and checks cancellation, child scope, server limits and byte guards. UI tests render thousands of cached rows while asserting that fewer than 100 row widgets exist per view. Cache tests cover the page, byte and query-descriptor caps.

These tests prove DIRLARK's own behavior against a protocol-correct mock. They are not a live scale claim for any particular directory server; see [validation](validation.md).

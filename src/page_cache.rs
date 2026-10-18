//! Bounded, connection-local fetched-page cache. No disk persistence or implied totals.
use crate::{
    model::Entry,
    paging::{Cursor, Mode, Page, Query, entry_bytes},
};
use std::collections::BTreeMap;

pub const MAX_PAGES: usize = 16;
pub const MAX_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_QUERIES: usize = 32;
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Key {
    Search,
    Children(String),
}
struct Window {
    entries: Vec<Entry>,
    bytes: usize,
    touched: u64,
}
pub struct Cached {
    pub query: Query,
    pub size: u16,
    pub next: Option<Cursor>,
    pub mode: Mode,
    pub total: Option<u32>,
    pub evicted: bool,
    pub warning: Option<String>,
    windows: BTreeMap<u32, Window>,
    touched: u64,
}
#[derive(Default)]
pub struct PageCache {
    queries: BTreeMap<Key, Cached>,
    clock: u64,
}
impl PageCache {
    pub fn get(&self, key: &Key) -> Option<&Cached> {
        self.queries.get(key)
    }
    pub fn invalidate(&mut self, key: &Key, message: String) {
        if let Some(q) = self.queries.get_mut(key) {
            q.next = None;
            q.warning = Some(message);
        }
    }
    pub fn contains(&self, key: &Key) -> bool {
        self.queries.contains_key(key)
    }
    pub fn remove(&mut self, key: &Key) -> Option<Cursor> {
        self.queries.remove(key).and_then(|q| q.next)
    }
    pub fn clear(&mut self) {
        self.queries.clear();
    }
    pub fn keys(&self) -> impl Iterator<Item = &Key> {
        self.queries.keys()
    }
    pub fn entries(&self, key: &Key) -> Vec<(u32, &Entry)> {
        self.queries
            .get(key)
            .map(|q| {
                q.windows
                    .iter()
                    .flat_map(|(offset, w)| w.entries.iter().map(move |e| (*offset, e)))
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn usage(&self) -> (usize, usize) {
        self.queries
            .values()
            .flat_map(|q| q.windows.values())
            .fold((0, 0), |(n, b), w| (n + 1, b + w.bytes))
    }
    pub fn touch(&mut self, key: &Key, offset: u32) {
        self.clock += 1;
        if let Some(q) = self.queries.get_mut(key) {
            q.touched = self.clock;
            if let Some(w) = q.windows.get_mut(&offset) {
                w.touched = self.clock;
            }
        }
    }
    /// Returns idle query cursors for RFC 2696 release. Window eviction keeps the latest
    /// continuation, so forward-only loading can proceed without replaying old cookies.
    pub fn insert(
        &mut self,
        key: Key,
        query: Query,
        size: u16,
        page: Page,
        reset: bool,
    ) -> Vec<Cursor> {
        self.clock += 1;
        let mut release = vec![];
        let bytes = page.entries.iter().map(entry_bytes).sum();
        let q = self.queries.entry(key).or_insert_with(|| Cached {
            query: query.clone(),
            size,
            next: None,
            mode: page.mode,
            total: None,
            evicted: false,
            warning: None,
            windows: BTreeMap::new(),
            touched: 0,
        });
        if reset || q.query != query || (page.offset == 1 && !q.windows.is_empty()) {
            q.windows.clear();
            q.evicted = false;
        }
        q.query = query;
        q.size = size;
        q.next = page.next;
        q.mode = page.mode;
        q.total = page.total;
        q.warning = page.warning;
        q.touched = self.clock;
        q.windows.insert(
            page.offset,
            Window {
                entries: page.entries,
                bytes,
                touched: self.clock,
            },
        );
        while self.queries.len() > MAX_QUERIES {
            let oldest = self
                .queries
                .iter()
                .min_by_key(|(_, q)| q.touched)
                .map(|(k, _)| k.clone())
                .unwrap();
            if let Some(cursor) = self.remove(&oldest) {
                release.push(cursor);
            }
        }
        while self.usage().0 > MAX_PAGES || self.usage().1 > MAX_BYTES {
            let oldest = self
                .queries
                .iter()
                .flat_map(|(k, q)| {
                    q.windows
                        .iter()
                        .map(move |(offset, w)| (w.touched, k.clone(), *offset))
                })
                .min_by_key(|v| v.0);
            let Some((_, key, offset)) = oldest else {
                break;
            };
            let q = self.queries.get_mut(&key).unwrap();
            q.windows.remove(&offset);
            q.evicted = true;
        }
        release
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn page(offset: u32, bytes: usize) -> Page {
        Page {
            entries: vec![Entry {
                dn: format!("cn={offset}"),
                attrs: BTreeMap::from([("value".into(), vec![vec![0; bytes]])]),
            }],
            next: None,
            offset,
            total: None,
            mode: Mode::Forward,
            warning: None,
        }
    }
    fn query() -> Query {
        Query {
            base: String::new(),
            scope: 2,
            filter: "(objectClass=*)".into(),
            attrs: vec![],
            sort: "cn".into(),
            ordering_rule: String::new(),
        }
    }
    #[test]
    fn lru_is_bounded_by_page_bytes_and_query_metadata() {
        let mut cache = PageCache::default();
        for offset in 1..=16 {
            cache.insert(Key::Search, query(), 25, page(offset, 100), false);
        }
        cache.touch(&Key::Search, 1);
        cache.insert(Key::Search, query(), 25, page(17, 100), false);
        assert!(cache.entries(&Key::Search).iter().any(|(n, _)| *n == 1));
        assert!(!cache.entries(&Key::Search).iter().any(|(n, _)| *n == 2));
        assert!(cache.get(&Key::Search).unwrap().evicted);
        for offset in 18..=30 {
            cache.insert(Key::Search, query(), 25, page(offset, 1024 * 1024), false);
        }
        assert!(cache.usage().1 <= MAX_BYTES);
        for n in 0..100 {
            cache.insert(
                Key::Children(n.to_string()),
                query(),
                25,
                page(1, 10),
                false,
            );
        }
        assert!(cache.queries.len() <= MAX_QUERIES);
        assert!(cache.usage().0 <= MAX_PAGES);
    }
    #[test]
    fn restart_replaces_rows_without_inventing_a_total() {
        let mut cache = PageCache::default();
        cache.insert(Key::Search, query(), 25, page(25, 10), false);
        cache.insert(Key::Search, query(), 50, page(1, 10), true);
        assert_eq!(cache.entries(&Key::Search).len(), 1);
        assert_eq!(cache.get(&Key::Search).unwrap().total, None);
        assert_eq!(cache.get(&Key::Search).unwrap().size, 50);
    }
}

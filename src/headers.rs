use std::cmp::Ordering;
use http::header::HeaderMap;
use http::{HeaderName, HeaderValue};
use indexmap::IndexSet;

/// Extension trait for HTTP requests and responses for accessing common headers
/// in a typed way.
///
/// Eventually this trait can be made public once the types are cleaned up a
/// bit.
pub(crate) trait HasHeaders {
    fn headers(&self) -> &HeaderMap;

    fn content_length(&self) -> Option<u64> {
        self.headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
    }

    fn content_type(&self) -> Option<&str> {
        self.headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
    }
}

impl HasHeaders for HeaderMap {
    fn headers(&self) -> &HeaderMap {
        self
    }
}

impl<T> HasHeaders for http::Request<T> {
    fn headers(&self) -> &HeaderMap {
        self.headers()
    }
}

impl<T> HasHeaders for http::Response<T> {
    fn headers(&self) -> &HeaderMap {
        self.headers()
    }
}

#[derive(Debug, Clone)]
/// Отвечает за порядок заголовков
pub enum HeadersOrder {
    /// Оставляем так как есть
    Default,
    /// Лексикографическая сортировка по имени (case-insensitive)
    LexIgnoreCase,
    /// Сначала список `preferred`, потом остальные
    Custom(Vec<HeaderName>),
}

impl Default for HeadersOrder {
    fn default() -> Self {
        HeadersOrder::Default
    }
}

impl HeadersOrder {
    pub(crate) fn sort(&self, headers: &mut HeaderMap) {
        match self {
            HeadersOrder::Default => return,
            _ => {
                // Снимем все пары с индексами для стабильной сортировки
                let mut entries: Vec<(usize, HeaderName, HeaderValue)> = headers
                    .iter()
                    .enumerate()
                    .map(|(i, (n, v))| (i, n.clone(), v.clone()))
                    .collect();

                // Построим IndexSet из preferred имён (приведённых к нижнему регистру)
                let preferred: Option<IndexSet<String>> = match self {
                    HeadersOrder::Custom(list) => {
                        let mut set = IndexSet::with_capacity(list.len());
                        for name in list {
                            set.insert(name.as_str().to_ascii_lowercase());
                        }
                        Some(set)
                    }
                    _ => None,
                };

                entries.sort_by(|(ia, na, _), (ib, nb, _)| {
                    let ka = na.as_str().to_ascii_lowercase();
                    let kb = nb.as_str().to_ascii_lowercase();

                    match self {
                        HeadersOrder::LexIgnoreCase => {
                            ka.cmp(&kb).then_with(|| ia.cmp(ib)) // стабильность
                        }
                        HeadersOrder::Custom(_) => {
                            let set = preferred.as_ref().unwrap();
                            let pa = set.get_index_of(&ka);
                            let pb = set.get_index_of(&kb);

                            match (pa, pb) {
                                // Оба в preferred — сравниваем по позиции в заданном списке
                                (Some(a), Some(b)) => a.cmp(&b).then_with(|| ia.cmp(ib)),
                                // Только левый — левый раньше
                                (Some(_), None) => Ordering::Less,
                                // Только правый — правый раньше
                                (None, Some(_)) => Ordering::Greater,
                                // Ни один — обычная CI-сортировка с сохранением стабильности
                                (None, None) => ka.cmp(&kb).then_with(|| ia.cmp(ib)),
                            }
                        }
                        HeadersOrder::Default => Ordering::Equal, // сюда не попадём
                    }
                });

                // Пересобираем карту в новом порядке (append сохраняет дубликаты)
                headers.clear();
                for (_, name, value) in entries {
                    headers.append(name, value);
                }
            }
        }
    }
}
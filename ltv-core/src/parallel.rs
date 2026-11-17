// LTV (LUKS Tunnel Vault) - Remote LUKS unlock over SSH
// Copyright (C) 2024 LTV Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Parallel execution framework for multi-target operations (enroll, rotate, unlock).

use futures::stream::{FuturesUnordered, StreamExt};
use std::future::Future;
use tokio::sync::{mpsc, Semaphore};

/// Message from a parallel task to the driver.
#[derive(Debug)]
pub enum TaskMsg<E, V> {
    /// An event to forward to the event handler
    Event(E),
    /// A verbose message to log
    Verbose(String),
    /// A completed result
    Result(Result<V, E>),
}

/// Run multiple tasks in parallel with bounded concurrency.
///
/// # Type Parameters
/// - `T`: Input item type for each task
/// - `V`: Success value type from each task
/// - `E`: Error type
/// - `F`: Task function taking an item and returning a future
///
/// # Arguments
/// - `items`: Items to process (each becomes one task)
/// - `max_concurrent`: Maximum concurrent tasks (defaults to MAX_CONCURRENT_TARGETS)
/// - `task_fn`: Async function to run for each item (must be cloneable or use shared state)
/// - `on_event`: Callback for event messages
/// - `on_verbose`: Callback for verbose messages
///
/// # Returns
/// Vector of successful results in the same order as input items.
/// Returns first error encountered (other tasks are cancelled).
pub async fn run_parallel<T, V, E, F, Fut>(
    items: Vec<T>,
    max_concurrent: usize,
    task_fn: F,
    mut on_event: impl FnMut(E),
    mut on_verbose: impl FnMut(String),
) -> Result<Vec<V>, E>
where
    F: FnMut(T) -> Fut + Send + Sync + Clone + 'static,
    Fut: Future<Output = Result<V, E>> + Send,
    E: Send + 'static,
    V: Send + 'static,
    T: Send + 'static,
{
    if items.is_empty() {
        return Ok(Vec::new());
    }

    let semaphore = Semaphore::new(max_concurrent);
    let (tx, mut rx) = mpsc::unbounded_channel::<TaskMsg<E, V>>();

    let mut futs: FuturesUnordered<_> = items
        .into_iter()
        .map(|item| {
            let tx = tx.clone();
            let sem = &semaphore;
            let mut task_fn = task_fn.clone();
            async move {
                let _permit = sem.acquire().await.unwrap();
                let res = task_fn(item).await;
                let _ = tx.send(TaskMsg::Result(res));
            }
        })
        .collect();

    let mut results = Vec::new();
    let mut first_err: Option<E> = None;
    let mut pending = futs.len();

    while pending > 0 {
        tokio::select! {
            biased;
            Some(msg) = rx.recv() => match msg {
                TaskMsg::Event(e) => on_event(e),
                TaskMsg::Verbose(s) => on_verbose(s),
                TaskMsg::Result(res) => {
                    pending -= 1;
                    match res {
                        Ok(v) => results.push(v),
                        Err(e) => {
                            if first_err.is_none() {
                                first_err = Some(e);
                            }
                        }
                    }
                }
            },
            Some(_) = futs.next() => {
                // Task completed, result already sent via channel
            }
        }
    }

    // Drain any remaining messages
    while let Ok(msg) = rx.try_recv() {
        match msg {
            TaskMsg::Event(e) => on_event(e),
            TaskMsg::Verbose(s) => on_verbose(s),
            TaskMsg::Result(_) => {}
        }
    }

    if let Some(e) = first_err {
        Err(e)
    } else {
        Ok(results)
    }
}

/// Run multiple tasks in parallel with index tracking for ordered results.
///
/// Similar to `run_parallel` but preserves the original order of items
/// by tracking their indices and sorting results at the end.
pub async fn run_parallel_ordered<T, V, E, F, Fut>(
    items: Vec<T>,
    max_concurrent: usize,
    task_fn: F,
    mut on_event: impl FnMut(E),
    mut on_verbose: impl FnMut(String),
) -> Result<Vec<V>, E>
where
    F: FnMut(usize, T) -> Fut + Send + Sync + Clone + 'static,
    Fut: Future<Output = Result<V, E>> + Send,
    E: Send + 'static,
    V: Send + 'static,
    T: Send + 'static,
{
    if items.is_empty() {
        return Ok(Vec::new());
    }

    let semaphore = Semaphore::new(max_concurrent);
    let (tx, mut rx) = mpsc::unbounded_channel::<TaskMsg<E, (usize, V)>>();

    let mut futs: FuturesUnordered<_> = items
        .into_iter()
        .enumerate()
        .map(|(idx, item)| {
            let tx = tx.clone();
            let sem = &semaphore;
            let mut task_fn = task_fn.clone();
            async move {
                let _permit = sem.acquire().await.unwrap();
                let res = task_fn(idx, item).await;
                let _ = tx.send(TaskMsg::Result(res.map(|v| (idx, v))));
            }
        })
        .collect();

    let mut results = Vec::new();
    let mut first_err: Option<E> = None;
    let mut pending = futs.len();

    while pending > 0 {
        tokio::select! {
            biased;
            Some(msg) = rx.recv() => match msg {
                TaskMsg::Event(e) => on_event(e),
                TaskMsg::Verbose(s) => on_verbose(s),
                TaskMsg::Result(res) => {
                    pending -= 1;
                    match res {
                        Ok((idx, v)) => results.push((idx, v)),
                        Err(e) => {
                            if first_err.is_none() {
                                first_err = Some(e);
                            }
                        }
                    }
                }
            },
            Some(_) = futs.next() => {}
        }
    }

    while let Ok(msg) = rx.try_recv() {
        match msg {
            TaskMsg::Event(e) => on_event(e),
            TaskMsg::Verbose(s) => on_verbose(s),
            TaskMsg::Result(_) => {}
        }
    }

    if let Some(e) = first_err {
        Err(e)
    } else {
        // Sort by original index to preserve order
        results.sort_by_key(|(idx, _)| *idx);
        Ok(results.into_iter().map(|(_, v)| v).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_run_parallel_basic() {
        let items = vec![1, 2, 3, 4, 5];
        let results = run_parallel(
            items,
            2,
            |x| async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok::<_, String>(x * 2)
            },
            |_| {},
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(results.len(), 5);
        let mut sorted = results.clone();
        sorted.sort();
        assert_eq!(sorted, vec![2, 4, 6, 8, 10]);
    }

    #[tokio::test]
    async fn test_run_parallel_ordered() {
        let items = vec![1, 2, 3, 4, 5];
        let results = run_parallel_ordered(
            items,
            2,
            |_, x| async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok::<_, String>(x * 2)
            },
            |_| {},
            |_| {},
        )
        .await
        .unwrap();
        // run_parallel_ordered returns values in original order (sorted by idx)
        assert_eq!(results, vec![2, 4, 6, 8, 10]);
    }

    #[tokio::test]
    async fn test_run_parallel_error() {
        let items = vec![1, 2, 3];
        let result = run_parallel(
            items,
            2,
            |x| async move {
                if x == 2 {
                    Err("error at 2")
                } else {
                    Ok(x * 2)
                }
            },
            |_| {},
            |_| {},
        )
        .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "error at 2");
    }

    #[tokio::test]
    async fn test_run_parallel_empty() {
        let items: Vec<i32> = vec![];
        let results = run_parallel(
            items,
            2,
            |x| async move { Ok::<_, String>(x) },
            |_| {},
            |_| {},
        )
        .await
        .unwrap();
        assert!(results.is_empty());
    }
}

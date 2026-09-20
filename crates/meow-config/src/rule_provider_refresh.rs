//! Interval-refresh supervision for HTTP rule-providers.
//!
//! One background task per (`name`, `interval`) HTTP provider keeps calling
//! [`RuleProvider::refresh`]. [`RefreshSupervisor::reconcile`] is invoked on
//! every successful config commit — after the rebuilt provider map has been
//! swapped into the registry — so providers added, removed, or re-
//! `interval`ed by a reload gain/lose their task without a restart (issue
//! #543). Before this supervisor existed the tasks were spawned once at
//! startup, so reloads could only ever refresh startup-era providers.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::error;

use crate::rule_provider::{ProviderType, RuleProvider};

/// Tracks the live refresh task per provider name. Cheap to share via
/// `Arc`; all mutation goes through [`reconcile`](Self::reconcile), which
/// diffs the wanted set against the running set — spawn what's missing,
/// abort what's gone or whose interval changed.
#[derive(Default)]
pub struct RefreshSupervisor {
    tasks: Mutex<HashMap<String, (u64, JoinHandle<()>)>>,
}

impl RefreshSupervisor {
    /// Diff the registry's refreshable providers against running tasks.
    ///
    /// Must be called from a tokio runtime context — it `tokio::spawn`s the
    /// per-provider loops — and under the same exclusion that serialised
    /// the registry swap (`CONFIG_MUTATION` in-tree): `wanted` is
    /// snapshotted before the task map lock, so a concurrent registry write
    /// could otherwise be missed until the next reconcile.
    ///
    /// Each spawned loop resolves its provider **by name** on every tick
    /// rather than pinning a `Arc<RuleProvider>`: commits swap the registry
    /// map, and a detached startup-era `Arc` would refresh content no live
    /// matcher sees (issue #514 review).
    ///
    /// Every call must pass the **same** registry `Arc` — spawned loops
    /// capture the `Arc` they were spawned with, so an embedder that
    /// replaces the whole `Arc<RwLock<…>>` (rather than the map inside it)
    /// strands its loops on a dead registry. In-tree the `Arc` is created
    /// once at startup and only its contents are swapped.
    ///
    /// Reaping runs only inside `reconcile`, i.e. on commits: a task that
    /// dies between commits stays dead until the next one (same semantics
    /// as the health-check supervisor).
    pub fn reconcile(&self, registry: &Arc<RwLock<HashMap<String, Arc<RuleProvider>>>>) {
        let wanted: HashMap<String, u64> = registry
            .read()
            .iter()
            .filter(|(_, p)| p.interval > 0 && p.provider_type == ProviderType::Http)
            .map(|(name, p)| (name.clone(), p.interval))
            .collect();

        let mut tasks = self.tasks.lock();
        tasks.retain(|name, (interval, task)| {
            let keep = wanted.get(name) == Some(interval) && !task.is_finished();
            if !keep {
                task.abort();
            }
            keep
        });
        for (name, interval) in wanted {
            if tasks.contains_key(&name) {
                continue;
            }
            let task = tokio::spawn(refresh_loop(name.clone(), interval, Arc::clone(registry)));
            tasks.insert(name, (interval, task));
        }
    }

    /// Number of running refresh tasks (test introspection).
    #[cfg(test)]
    pub fn task_count(&self) -> usize {
        self.tasks.lock().len()
    }

    /// Interval a running task was spawned with (test introspection).
    #[cfg(test)]
    fn task_interval(&self, name: &str) -> Option<u64> {
        self.tasks.lock().get(name).map(|(iv, _)| *iv)
    }

    /// Identity of a running task's `JoinHandle` (test introspection) —
    /// distinguishes a respawned task from a kept one.
    #[cfg(test)]
    fn task_id(&self, name: &str) -> Option<tokio::task::Id> {
        self.tasks.lock().get(name).map(|(_, t)| t.id())
    }

    /// Insert an already-finished task — exercises the reap-and-respawn
    /// branch without racing a real panic. The spawned future is awaited
    /// to completion first, so `is_finished()` is genuinely true on a
    /// current-thread runtime (a bare `tokio::spawn` is never polled).
    #[cfg(test)]
    async fn insert_dead_task(&self, name: &str, interval: u64) {
        let mut task = tokio::spawn(async {});
        (&mut task).await.unwrap();
        debug_assert!(task.is_finished());
        self.tasks.lock().insert(name.to_string(), (interval, task));
    }
}

impl Drop for RefreshSupervisor {
    /// Abort every supervised task — otherwise the `JoinHandle`s detach on
    /// drop and the loops keep an embedder's dropped registry alive.
    fn drop(&mut self) {
        for (_, (_, task)) in self.tasks.get_mut().drain() {
            task.abort();
        }
    }
}

async fn refresh_loop(
    name: String,
    interval_secs: u64,
    registry: Arc<RwLock<HashMap<String, Arc<RuleProvider>>>>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    // `Delay` — a suspend longer than `interval` must not fire every missed
    // tick back-to-back (a refresh storm of real HTTP fetches); same policy
    // as the health-check supervisor.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // skip the immediate first tick
    loop {
        ticker.tick().await;
        let Some(provider) = registry.read().get(&name).cloned() else {
            continue;
        };
        // The provider re-parses the payload in its own load-time
        // ParserContext and declared format, so geo-dependent entries
        // survive refreshes (issue #533 review).
        if let Err(e) = provider.refresh().await {
            error!(provider = %provider.name, "background refresh failed: {:#}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_provider::test_provider;

    fn registry_map(entries: &[(&str, ProviderType, u64)]) -> HashMap<String, Arc<RuleProvider>> {
        entries
            .iter()
            .map(|(name, ty, iv)| (name.to_string(), test_provider(name, *ty, *iv)))
            .collect()
    }

    fn registry(
        entries: &[(&str, ProviderType, u64)],
    ) -> Arc<RwLock<HashMap<String, Arc<RuleProvider>>>> {
        Arc::new(RwLock::new(registry_map(entries)))
    }

    #[tokio::test]
    async fn reconcile_spawns_per_refreshable_provider() {
        let sup = RefreshSupervisor::default();
        let reg = registry(&[
            ("http-a", ProviderType::Http, 3600),
            ("http-b", ProviderType::Http, 60),
            ("no-interval", ProviderType::Http, 0),
            ("file", ProviderType::File, 3600),
            ("inline", ProviderType::Inline, 3600),
        ]);
        sup.reconcile(&reg);
        assert_eq!(sup.task_count(), 2, "only http providers with interval > 0");
    }

    #[tokio::test]
    async fn reconcile_aborts_removed_and_respawns_changed_interval() {
        let sup = RefreshSupervisor::default();
        let reg = registry(&[
            ("a", ProviderType::Http, 3600),
            ("b", ProviderType::Http, 60),
        ]);
        sup.reconcile(&reg);
        assert_eq!(sup.task_count(), 2);

        // "b" removed, "a" interval changed → both tasks re-dispatched.
        *reg.write() = registry_map(&[("a", ProviderType::Http, 120)]);
        sup.reconcile(&reg);
        assert_eq!(sup.task_count(), 1);
        assert_eq!(
            sup.task_interval("a"),
            Some(120),
            "the interval change must respawn the task with the new tick"
        );
    }

    #[tokio::test]
    async fn reconcile_reaps_and_respawns_dead_tasks() {
        let sup = RefreshSupervisor::default();
        let reg = registry(&[("a", ProviderType::Http, 3600)]);
        sup.insert_dead_task("a", 3600).await;
        let dead_id = sup.task_id("a").unwrap();
        // The dead task matches the wanted interval but is finished — the
        // supervisor must reap it and spawn a live replacement.
        sup.reconcile(&reg);
        assert_eq!(sup.task_count(), 1);
        assert_eq!(sup.task_interval("a"), Some(3600));
        assert_ne!(
            sup.task_id("a"),
            Some(dead_id),
            "the finished task must be replaced, not kept"
        );
    }

    #[tokio::test]
    async fn reconcile_empty_registry_aborts_all() {
        let sup = RefreshSupervisor::default();
        let reg = registry(&[("a", ProviderType::Http, 3600)]);
        sup.reconcile(&reg);
        *reg.write() = HashMap::new();
        sup.reconcile(&reg);
        assert_eq!(sup.task_count(), 0);
    }
}

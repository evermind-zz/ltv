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

//! Shared execution framework for multi-target operations (enroll, rotate, unlock).
//! Provides sequential and parallel execution with a strategy pattern.

#![allow(async_fn_in_trait)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::redundant_locals)]

use crate::constants::{MAX_CONCURRENT_TARGETS, MIN_EXEC_TIMEOUT_SECS};
use crate::error::{UnlockError, VaultError};
use crate::model::{ExecutionMode, TargetMeta};
use crate::passphrase::make_parallel_passphrase_map;
use crate::vault::Vault;
use futures::stream::{FuturesUnordered, StreamExt};
use secrecy::SecretString;
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore};

/// Verbose callback type used throughout the execution framework.
pub type VerboseCb = Option<Box<dyn FnMut(&str) + Send>>;

/// Input item for a target execution.
#[derive(Debug, Clone)]
pub struct TargetInput {
    pub index: usize,
    pub target: TargetMeta,
}

/// Strategy trait for executing a single target's operation.
/// Implement this for each operation type (enroll, rotate, etc.).
pub trait ExecutionStrategy: Send + Sync {
    /// The event type emitted by this strategy
    type Event: Send + 'static;
    /// The result type for a successful target execution
    type Result: Send + 'static;
    /// The error type
    type Error: From<UnlockError> + From<VaultError> + From<std::string::String> + Send + 'static;
    /// The SSH session handle type (must be Clone for parallel execution)
    type Session: Send + Sync + Clone + 'static;

    /// Called once before any targets are processed (e.g., SSH connect).
    /// Returns the session and any initialization data needed.
    async fn initialize(
        &self,
        vault: &Vault,
        uuid: &[u8; 16],
        access: &crate::model::BootedAccess,
    ) -> Result<(Self::Session, Vec<TargetInput>), Self::Error>;

    /// Execute the operation for a single target.
    /// Called sequentially or in parallel depending on mode.
    async fn execute_one(
        &self,
        input: TargetInput,
        session: &Self::Session,
        passphrase: &SecretString,
        sudo: &str,
        timeout: Duration,
        log: &mut dyn FnMut(&str),
        emit: &mut dyn FnMut(Self::Event),
    ) -> Result<Option<Self::Result>, Self::Error>;

    /// Called after a target succeeds in parallel mode (but before next target in sequential).
    /// Used for vault updates, cleanup, etc. Default does nothing.
    async fn finish_one(
        &self,
        _vault: &mut Vault,
        _uuid: &[u8; 16],
        _result: Self::Result,
        _session: &Self::Session,
        _sudo: &str,
        _timeout: Duration,
        _emit: &mut dyn FnMut(Self::Event),
        _verbose: &mut VerboseCb,
    ) -> Result<Self::Result, Self::Error> {
        Ok(_result)
    }

    /// Called when a target is skipped due to filter mismatch.
    fn on_target_filtered(&self, _filter: &str, _emit: &mut dyn FnMut(Self::Event)) {}

    /// Called when all targets complete.
    fn on_done(&self, _emit: &mut dyn FnMut(Self::Event)) {}

    /// Whether to force sequential mode (for safety-critical operations like rotation).
    fn force_sequential(&self) -> bool {
        false
    }
}

/// Message from a parallel task to the driver loop for strategy execution.
#[derive(Debug)]
enum StrategyMsg<Ev, V, Er> {
    Event(Ev),
    Verbose(String),
    Result(Result<Option<V>, Er>),
}

/// Runs the execution strategy in the specified mode.
pub async fn run_execution<S>(
    vault: &mut Vault,
    uuid: &[u8; 16],
    access: &crate::model::BootedAccess,
    mode: ExecutionMode,
    passphrase_provider: impl FnMut(&str) -> Result<SecretString, String> + Send,
    only_target: Option<&str>,
    strategy: &S,
    mut on: impl FnMut(S::Event),
    mut verbose: VerboseCb,
    mut per_target_save: Option<&mut dyn FnMut(&mut Vault) -> Result<(), S::Error>>,
) -> Result<Vec<S::Result>, S::Error>
where
    S: ExecutionStrategy + ?Sized,
{
    let profile = vault.profile(uuid)?.clone();
    let (session, targets) = strategy.initialize(vault, uuid, access).await?;

    // Filter targets
    let filtered_targets: Vec<TargetInput> = targets
        .into_iter()
        .filter(|t| {
            only_target.is_none_or(|f| f == t.target.luks_uuid || f == t.target.mapped_name)
        })
        .collect();

    let sudo = if access.use_sudo && access.username != "root" {
        "sudo -n "
    } else {
        ""
    };
    let timeout = Duration::from_secs(profile.exec_timeout_s.max(MIN_EXEC_TIMEOUT_SECS) as u64);

    // Check if filter matched nothing
    if let Some(f) = only_target {
        if filtered_targets.is_empty() {
            strategy.on_target_filtered(f, &mut on);
        }
    }

    // Force sequential if strategy requires it
    let effective_mode = if strategy.force_sequential() {
        ExecutionMode::Sequential
    } else {
        mode
    };

    let results = match effective_mode {
        ExecutionMode::Sequential => {
            let mut pass =
                crate::passphrase::make_sequential_passphrase_provider(passphrase_provider);
            let mut results = Vec::new();
            let mut verbose = verbose;

            for input in &filtered_targets {
                let passphrase = pass(&input.target.luks_uuid).map_err(S::Error::from)?;

                let mut log = |s: &str| {
                    if let Some(v) = verbose.as_mut() {
                        v(s);
                    }
                };
                let mut emit = |e: S::Event| on(e);

                if let Some(r) = strategy
                    .execute_one(
                        input.clone(),
                        &session,
                        &passphrase,
                        sudo,
                        timeout,
                        &mut log,
                        &mut emit,
                    )
                    .await?
                {
                    let mut emit = |e: S::Event| on(e);
                    let r = strategy
                        .finish_one(
                            vault,
                            uuid,
                            r,
                            &session,
                            sudo,
                            timeout,
                            &mut emit,
                            &mut verbose,
                        )
                        .await?;

                    if let Some(save_fn) = per_target_save.as_mut() {
                        save_fn(vault)?;
                    }

                    results.push(r);
                }
            }

            strategy.on_done(&mut on);
            Ok::<Vec<S::Result>, S::Error>(results)
        }
        ExecutionMode::Parallel => {
            // Fetch every needed passphrase up front
            let pass_map = make_parallel_passphrase_map(
                &filtered_targets
                    .iter()
                    .map(|t| (t.index, t.target.clone()))
                    .collect::<Vec<_>>(),
                passphrase_provider,
            )?;

            // Log parallel start
            if let Some(v) = verbose.as_mut() {
                v(&format!(
                    "running {} target(s) in parallel",
                    filtered_targets.len()
                ));
            }

            let semaphore = Semaphore::new(MAX_CONCURRENT_TARGETS);
            let (tx, mut rx) =
                mpsc::unbounded_channel::<StrategyMsg<S::Event, S::Result, S::Error>>();

            let mut futs: FuturesUnordered<_> = filtered_targets
                .into_iter()
                .map(|input| {
                    let tx = tx.clone();
                    let sem = &semaphore;
                    let session = session.clone();
                    let passphrase = pass_map.get(&input.target.luks_uuid).cloned().unwrap();
                    async move {
                        let _permit = sem.acquire().await;
                        let res: Result<Option<S::Result>, S::Error> = async {
                            let mut log = |s: &str| {
                                let _ = tx.send(StrategyMsg::Verbose(s.to_string()));
                            };
                            let mut emit = |e: S::Event| {
                                let _ = tx.send(StrategyMsg::Event(e));
                            };
                            strategy
                                .execute_one(
                                    input,
                                    &session,
                                    &passphrase,
                                    sudo,
                                    timeout,
                                    &mut log,
                                    &mut emit,
                                )
                                .await
                        }
                        .await;
                        let _ = tx.send(StrategyMsg::Result(res));
                    }
                })
                .collect();

            let mut first_err: Option<S::Error> = None;
            let mut completed: Vec<S::Result> = Vec::new();
            let mut pending = futs.len();

            while pending > 0 {
                tokio::select! {
                    biased;
                    Some(msg) = rx.recv() => match msg {
                        StrategyMsg::Event(e) => on(e),
                        StrategyMsg::Verbose(s) => {
                            if let Some(v) = verbose.as_mut() {
                                v(&s);
                            }
                        }
                        StrategyMsg::Result(res) => {
                            pending -= 1;
                            match res {
                                Ok(Some(r)) => completed.push(r),
                                Ok(None) => {}
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

            // Drain any remaining messages
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    StrategyMsg::Event(e) => on(e),
                    StrategyMsg::Verbose(s) => {
                        if let Some(v) = verbose.as_mut() {
                            v(&s);
                        }
                    }
                    StrategyMsg::Result(_) => {}
                }
            }

            if let Some(e) = first_err {
                return Err(e);
            }

            // Process completed results: finish_one for each
            let mut final_results = Vec::new();
            for r in completed {
                let mut emit = |e: S::Event| on(e);
                let r = strategy
                    .finish_one(
                        vault,
                        uuid,
                        r,
                        &session,
                        sudo,
                        timeout,
                        &mut emit,
                        &mut verbose,
                    )
                    .await?;

                if let Some(save_fn) = per_target_save.as_mut() {
                    save_fn(vault)?;
                }

                final_results.push(r);
            }

            strategy.on_done(&mut on);
            Ok(final_results)
        }
    }?;

    Ok(results)
}

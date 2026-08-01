use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use quanta::Instant;
use tokio::sync::RwLock;

use crate::config::PeerId;

use super::conn::peer_map::PeerMap;

const LOSS_THRESHOLD_PERCENT: u32 = 2;
const RETURN_THRESHOLD_PERCENT: u32 = 1;
const SWITCH_COOLDOWN: Duration = Duration::from_secs(10);
const CASCADE_COOLDOWN: Duration = Duration::from_secs(5);
const CASCADE_LOSS_THRESHOLD: u32 = 5;
pub(crate) const EVAL_INTERVAL: Duration = Duration::from_secs(5);
const MIN_SAMPLES_AFTER_SWITCH: Duration = Duration::from_secs(3);
const CONSECUTIVE_CONFIRM: u32 = 2;

#[derive(Debug, Clone)]
pub(crate) struct ActiveExitNode {
    pub ip: IpAddr,
    pub peer_id: PeerId,
    #[allow(dead_code)]
    pub selected_at: Instant,
}

struct ExitNodeCandidate {
    ip: IpAddr,
    peer_id: PeerId,
    loss: u32,
    #[allow(dead_code)]
    config_index: usize,
}

#[derive(Clone)]
pub(crate) struct ExitNodeSelector {
    exit_nodes: Arc<RwLock<Vec<IpAddr>>>,
    active_v4: Arc<ArcSwapOption<ActiveExitNode>>,
    active_v6: Arc<ArcSwapOption<ActiveExitNode>>,
    peers: Arc<PeerMap>,
    last_switch_at: Arc<RwLock<Option<Instant>>>,
    consecutive_over_threshold: Arc<AtomicU32>,
    preferred_return_count: Arc<AtomicU32>,
}

impl ExitNodeSelector {
    pub(crate) fn new(exit_nodes: Arc<RwLock<Vec<IpAddr>>>, peers: Arc<PeerMap>) -> Self {
        Self {
            exit_nodes,
            active_v4: Arc::new(ArcSwapOption::empty()),
            active_v6: Arc::new(ArcSwapOption::empty()),
            peers,
            last_switch_at: Arc::new(RwLock::new(None)),
            consecutive_over_threshold: Arc::new(AtomicU32::new(0)),
            preferred_return_count: Arc::new(AtomicU32::new(0)),
        }
    }

    pub(crate) fn get_active_v4(&self) -> Option<Arc<ActiveExitNode>> {
        self.active_v4.load_full()
    }

    pub(crate) fn get_active_v6(&self) -> Option<Arc<ActiveExitNode>> {
        self.active_v6.load_full()
    }

    pub(crate) fn reset(&self) {
        self.active_v4.store(None);
        self.active_v6.store(None);
        self.consecutive_over_threshold.store(0, Ordering::Relaxed);
        self.preferred_return_count.store(0, Ordering::Relaxed);
    }

    pub(crate) async fn evaluate(&self) {
        let nodes = self.exit_nodes.read().await.clone();

        if nodes.is_empty() {
            self.active_v4.store(None);
            self.active_v6.store(None);
            return;
        }

        if nodes.len() == 1 {
            self.set_single_node(&nodes).await;
            return;
        }

        let now = Instant::now();
        if !self.cooldown_elapsed(now).await {
            return;
        }

        let (candidates_v4, candidates_v6) = self.resolve_candidates(&nodes).await;

        self.evaluate_candidates(&candidates_v4, &self.active_v4, now)
            .await;
        self.evaluate_candidates(&candidates_v6, &self.active_v6, now)
            .await;
    }

    async fn set_single_node(&self, nodes: &[IpAddr]) {
        let ip = nodes[0];
        match ip {
            IpAddr::V4(addr) => {
                if let Some(peer_id) = self.peers.get_peer_id_by_ipv4(&addr).await {
                    self.active_v4.store(Some(Arc::new(ActiveExitNode {
                        ip,
                        peer_id,
                        selected_at: Instant::now(),
                    })));
                } else {
                    self.active_v4.store(None);
                }
            }
            IpAddr::V6(addr) => {
                if let Some(peer_id) = self.peers.get_peer_id_by_ipv6(&addr).await {
                    self.active_v6.store(Some(Arc::new(ActiveExitNode {
                        ip,
                        peer_id,
                        selected_at: Instant::now(),
                    })));
                } else {
                    self.active_v6.store(None);
                }
            }
        }
    }

    async fn cooldown_elapsed(&self, now: Instant) -> bool {
        let last = *self.last_switch_at.read().await;
        let Some(last) = last else {
            return true;
        };

        let elapsed = now.duration_since(last);
        if elapsed < MIN_SAMPLES_AFTER_SWITCH {
            return false;
        }

        let current_loss = self.get_current_active_loss().await;
        let cooldown = if current_loss > CASCADE_LOSS_THRESHOLD {
            CASCADE_COOLDOWN
        } else {
            SWITCH_COOLDOWN
        };

        elapsed >= cooldown
    }

    async fn get_current_active_loss(&self) -> u32 {
        if let Some(active) = self.active_v4.load_full() {
            if let Some(loss) = self.peers.get_peer_loss_rate(active.peer_id) {
                return loss;
            }
        }
        if let Some(active) = self.active_v6.load_full() {
            if let Some(loss) = self.peers.get_peer_loss_rate(active.peer_id) {
                return loss;
            }
        }
        0
    }

    async fn resolve_candidates(
        &self,
        nodes: &[IpAddr],
    ) -> (Vec<ExitNodeCandidate>, Vec<ExitNodeCandidate>) {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();

        for (idx, ip) in nodes.iter().enumerate() {
            match ip {
                IpAddr::V4(addr) => {
                    if let Some(peer_id) = self.peers.get_peer_id_by_ipv4(addr).await {
                        let loss = self.peers.get_peer_loss_rate(peer_id);
                        if let Some(loss) = loss {
                            v4.push(ExitNodeCandidate {
                                ip: *ip,
                                peer_id,
                                loss,
                                config_index: idx,
                            });
                        }
                    }
                }
                IpAddr::V6(addr) => {
                    if let Some(peer_id) = self.peers.get_peer_id_by_ipv6(addr).await {
                        let loss = self.peers.get_peer_loss_rate(peer_id);
                        if let Some(loss) = loss {
                            v6.push(ExitNodeCandidate {
                                ip: *ip,
                                peer_id,
                                loss,
                                config_index: idx,
                            });
                        }
                    }
                }
            }
        }

        (v4, v6)
    }

    async fn evaluate_candidates(
        &self,
        candidates: &[ExitNodeCandidate],
        active_slot: &ArcSwapOption<ActiveExitNode>,
        now: Instant,
    ) {
        if candidates.is_empty() {
            active_slot.store(None);
            return;
        }

        let current = active_slot.load_full();
        match current {
            Some(ref current_active) => {
                let current_loss =
                    Self::find_loss_in_candidates(current_active.peer_id, candidates);

                match current_loss {
                    None => {
                        self.switch_to_best(candidates, None, active_slot, now)
                            .await;
                    }
                    Some(loss) if loss <= LOSS_THRESHOLD_PERCENT => {
                        self.consecutive_over_threshold.store(0, Ordering::Relaxed);
                        self.check_preferred_return(candidates, current_active, loss, active_slot, now)
                            .await;
                    }
                    Some(_loss) => {
                        let count =
                            self.consecutive_over_threshold.fetch_add(1, Ordering::Relaxed) + 1;
                        if count < CONSECUTIVE_CONFIRM {
                            return;
                        }
                        self.consecutive_over_threshold.store(0, Ordering::Relaxed);
                        self.switch_to_best(
                            candidates,
                            Some(current_active.peer_id),
                            active_slot,
                            now,
                        )
                        .await;
                    }
                }
            }
            None => {
                self.switch_to_best(candidates, None, active_slot, now)
                    .await;
            }
        }
    }

    async fn check_preferred_return(
        &self,
        candidates: &[ExitNodeCandidate],
        current_active: &ActiveExitNode,
        current_loss: u32,
        active_slot: &ArcSwapOption<ActiveExitNode>,
        now: Instant,
    ) {
        let current_idx = candidates
            .iter()
            .position(|c| c.peer_id == current_active.peer_id);

        let Some(current_idx) = current_idx else {
            return;
        };

        for candidate in candidates.iter().take(current_idx) {
            if candidate.loss <= RETURN_THRESHOLD_PERCENT
                && candidate.loss <= current_loss.saturating_add(1)
            {
                let count = self.preferred_return_count.fetch_add(1, Ordering::Relaxed) + 1;
                if count >= CONSECUTIVE_CONFIRM {
                    self.preferred_return_count.store(0, Ordering::Relaxed);
                    self.do_switch(candidate, active_slot, now, "preferred node recovered")
                        .await;
                }
                return;
            }
        }

        self.preferred_return_count.store(0, Ordering::Relaxed);
    }

    async fn switch_to_best(
        &self,
        candidates: &[ExitNodeCandidate],
        exclude_peer: Option<PeerId>,
        active_slot: &ArcSwapOption<ActiveExitNode>,
        now: Instant,
    ) {
        for candidate in candidates {
            if Some(candidate.peer_id) == exclude_peer {
                continue;
            }
            if candidate.loss <= LOSS_THRESHOLD_PERCENT {
                self.do_switch(candidate, active_slot, now, "quality threshold exceeded")
                    .await;
                return;
            }
        }

        let best = candidates
            .iter()
            .filter(|c| Some(c.peer_id) != exclude_peer)
            .min_by_key(|c| c.loss)
            .or_else(|| candidates.iter().min_by_key(|c| c.loss));

        if let Some(best) = best {
            self.do_switch(best, active_slot, now, "all nodes degraded, selecting lowest loss")
                .await;
        }
    }

    async fn do_switch(
        &self,
        candidate: &ExitNodeCandidate,
        active_slot: &ArcSwapOption<ActiveExitNode>,
        now: Instant,
        reason: &str,
    ) {
        let old = active_slot.load_full();
        let old_info = old
            .as_ref()
            .map(|a| (a.ip, self.peers.get_peer_loss_rate(a.peer_id).unwrap_or(0)));

        active_slot.store(Some(Arc::new(ActiveExitNode {
            ip: candidate.ip,
            peer_id: candidate.peer_id,
            selected_at: now,
        })));
        *self.last_switch_at.write().await = Some(now);

        match old_info {
            Some((old_ip, old_loss)) => {
                tracing::info!(
                    from = %old_ip,
                    to = %candidate.ip,
                    from_loss_percent = old_loss,
                    to_loss_percent = candidate.loss,
                    reason = %reason,
                    "exit node quality switch"
                );
            }
            None => {
                tracing::info!(
                    to = %candidate.ip,
                    to_loss_percent = candidate.loss,
                    "exit node initial selection"
                );
            }
        }
    }

    fn find_loss_in_candidates(peer_id: PeerId, candidates: &[ExitNodeCandidate]) -> Option<u32> {
        candidates
            .iter()
            .find(|c| c.peer_id == peer_id)
            .map(|c| c.loss)
    }
}

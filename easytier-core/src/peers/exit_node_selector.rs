use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use parking_lot::RwLock as SyncRwLock;
use quanta::Instant;
use tokio::sync::RwLock;

use crate::config::PeerId;
use crate::proto::peer_rpc::GlobalPeerMap;

use super::conn::peer_map::PeerMap;
use super::route::ArcRoute;

const LOSS_THRESHOLD_PERCENT: u32 = 2;
const SWITCH_COOLDOWN: Duration = Duration::from_secs(10);
const CASCADE_COOLDOWN: Duration = Duration::from_secs(5);
const CASCADE_LOSS_THRESHOLD: u32 = 5;
pub(crate) const EVAL_INTERVAL: Duration = Duration::from_secs(5);
const MIN_SAMPLES_AFTER_SWITCH: Duration = Duration::from_secs(3);
const CONSECUTIVE_CONFIRM: u32 = 2;
const MAX_RELAY_HOPS: usize = 3;
const CONN_SWITCH_GRACE: Duration = Duration::from_secs(12);

type SharedGlobalPeerMap = Arc<std::sync::RwLock<GlobalPeerMap>>;

#[derive(Debug, Clone)]
pub(crate) struct ActiveExitNode {
    pub ip: IpAddr,
    pub peer_id: PeerId,
}

#[derive(Clone, PartialEq, Default)]
struct PathFingerprint {
    is_relay: bool,
    conn_id: super::conn::peer_conn::PeerConnId,
    gateway_peer_id: PeerId,
}

struct ExitNodeCandidate {
    ip: IpAddr,
    peer_id: PeerId,
    loss: Option<u32>,
    path_cost: Option<i32>,
    fingerprint: PathFingerprint,
}

impl ExitNodeCandidate {
    fn quality_score(&self) -> u64 {
        if let Some(loss) = self.loss {
            (loss as u64) * 100
        } else if let Some(cost) = self.path_cost {
            cost.max(0) as u64
        } else {
            u64::MAX
        }
    }

    fn is_over_threshold(&self) -> bool {
        if let Some(loss) = self.loss {
            loss > LOSS_THRESHOLD_PERCENT
        } else {
            false
        }
    }

    fn is_good(&self) -> bool {
        if let Some(loss) = self.loss {
            loss <= LOSS_THRESHOLD_PERCENT
        } else {
            self.path_cost.is_some()
        }
    }

    fn is_return_candidate(&self, current_loss: Option<u32>) -> bool {
        if let Some(loss) = self.loss {
            loss <= LOSS_THRESHOLD_PERCENT
                && current_loss.map_or(true, |cl| loss < cl || cl > LOSS_THRESHOLD_PERCENT)
        } else {
            false
        }
    }
}

struct PerVersionCounters {
    consecutive_over_threshold: AtomicU32,
    preferred_return_count: AtomicU32,
    last_fingerprint: SyncRwLock<PathFingerprint>,
    last_relay_path_change: SyncRwLock<Option<Instant>>,
    grace_reset_count: AtomicU32,
}

impl Default for PerVersionCounters {
    fn default() -> Self {
        Self {
            consecutive_over_threshold: AtomicU32::new(0),
            preferred_return_count: AtomicU32::new(0),
            last_fingerprint: SyncRwLock::new(PathFingerprint::default()),
            last_relay_path_change: SyncRwLock::new(None),
            grace_reset_count: AtomicU32::new(0),
        }
    }
}

const MAX_GRACE_RESETS: u32 = 2;

impl PerVersionCounters {
    fn reset(&self) {
        self.consecutive_over_threshold.store(0, Ordering::Relaxed);
        self.preferred_return_count.store(0, Ordering::Relaxed);
        *self.last_fingerprint.write() = PathFingerprint::default();
        *self.last_relay_path_change.write() = None;
        self.grace_reset_count.store(0, Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub(crate) struct ExitNodeSelector {
    my_peer_id: PeerId,
    exit_nodes: Arc<RwLock<Vec<IpAddr>>>,
    active_v4: Arc<ArcSwapOption<ActiveExitNode>>,
    active_v6: Arc<ArcSwapOption<ActiveExitNode>>,
    peers: Arc<PeerMap>,
    route: ArcRoute,
    global_peer_map: Arc<ArcSwapOption<SharedGlobalPeerMap>>,
    last_switch_at: Arc<SyncRwLock<Option<Instant>>>,
    counters_v4: Arc<PerVersionCounters>,
    counters_v6: Arc<PerVersionCounters>,
}

impl ExitNodeSelector {
    pub(crate) fn new(
        my_peer_id: PeerId,
        exit_nodes: Arc<RwLock<Vec<IpAddr>>>,
        peers: Arc<PeerMap>,
        route: ArcRoute,
    ) -> Self {
        Self {
            my_peer_id,
            exit_nodes,
            active_v4: Arc::new(ArcSwapOption::empty()),
            active_v6: Arc::new(ArcSwapOption::empty()),
            peers,
            route,
            global_peer_map: Arc::new(ArcSwapOption::empty()),
            last_switch_at: Arc::new(SyncRwLock::new(None)),
            counters_v4: Arc::new(PerVersionCounters::default()),
            counters_v6: Arc::new(PerVersionCounters::default()),
        }
    }

    pub(crate) fn set_global_peer_map(&self, map: SharedGlobalPeerMap) {
        self.global_peer_map.store(Some(Arc::new(map)));
    }

    pub(crate) fn get_active_v4_peer_id(&self) -> Option<PeerId> {
        let guard = self.active_v4.load();
        guard.as_ref().map(|a| a.peer_id)
    }

    pub(crate) fn get_active_v6_peer_id(&self) -> Option<PeerId> {
        let guard = self.active_v6.load();
        guard.as_ref().map(|a| a.peer_id)
    }

    pub(crate) fn reset(&self) {
        self.active_v4.store(None);
        self.active_v6.store(None);
        self.counters_v4.reset();
        self.counters_v6.reset();
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
        if !self.cooldown_elapsed(now) {
            return;
        }

        let (candidates_v4, candidates_v6) = self.resolve_candidates(&nodes).await;

        self.evaluate_candidates(&candidates_v4, &self.active_v4, &self.counters_v4, now);
        self.evaluate_candidates(&candidates_v6, &self.active_v6, &self.counters_v6, now);
    }

    async fn set_single_node(&self, nodes: &[IpAddr]) {
        let ip = nodes[0];
        match ip {
            IpAddr::V4(addr) => {
                if let Some(peer_id) = self.peers.get_peer_id_by_ipv4(&addr).await {
                    self.active_v4
                        .store(Some(Arc::new(ActiveExitNode { ip, peer_id })));
                } else {
                    self.active_v4.store(None);
                }
            }
            IpAddr::V6(addr) => {
                if let Some(peer_id) = self.peers.get_peer_id_by_ipv6(&addr).await {
                    self.active_v6
                        .store(Some(Arc::new(ActiveExitNode { ip, peer_id })));
                } else {
                    self.active_v6.store(None);
                }
            }
        }
    }

    fn cooldown_elapsed(&self, now: Instant) -> bool {
        let last = *self.last_switch_at.read();
        let Some(last) = last else {
            return true;
        };

        let elapsed = now.duration_since(last);
        if elapsed < MIN_SAMPLES_AFTER_SWITCH {
            return false;
        }

        let current_loss = self.get_current_active_loss();
        let cooldown = if current_loss > CASCADE_LOSS_THRESHOLD {
            CASCADE_COOLDOWN
        } else {
            SWITCH_COOLDOWN
        };

        elapsed >= cooldown
    }

    fn get_current_active_loss(&self) -> u32 {
        if let Some(peer_id) = self.get_active_v4_peer_id() {
            if let Some(loss) = self.peers.get_peer_loss_rate(peer_id) {
                return loss;
            }
        }
        if let Some(peer_id) = self.get_active_v6_peer_id() {
            if let Some(loss) = self.peers.get_peer_loss_rate(peer_id) {
                return loss;
            }
        }
        0
    }

    fn compute_path_loss(
        &self,
        dst_peer_id: PeerId,
        first_hop: PeerId,
        gpm: &GlobalPeerMap,
    ) -> Option<u32> {
        let mut current = self.my_peer_id;
        let mut delivery_rate: f64 = 1.0;

        for _ in 0..MAX_RELAY_HOPS {
            if current == dst_peer_id {
                break;
            }

            let current_info = gpm.map.get(&current)?;
            let next_hop = if current == self.my_peer_id {
                first_hop
            } else if current_info.direct_peers.contains_key(&dst_peer_id) {
                dst_peer_id
            } else {
                // Find common neighbor between current and dst
                let dst_info = gpm.map.get(&dst_peer_id)?;
                *current_info
                    .direct_peers
                    .keys()
                    .find(|p| dst_info.direct_peers.contains_key(p))?
            };

            let loss_percent = current_info.direct_peers.get(&next_hop)?.loss_rate_percent;
            delivery_rate *= 1.0 - (loss_percent as f64 / 100.0);
            current = next_hop;
        }

        if current != dst_peer_id {
            return None;
        }

        Some(((1.0 - delivery_rate) * 100.0) as u32)
    }

    async fn resolve_candidates(
        &self,
        nodes: &[IpAddr],
    ) -> (Vec<ExitNodeCandidate>, Vec<ExitNodeCandidate>) {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();

        let routes = self.route.list_routes().await;

        // Clone GlobalPeerMap snapshot to avoid holding RwLockReadGuard across await.
        let gpm_snapshot: Option<GlobalPeerMap> = {
            let guard = self.global_peer_map.load();
            guard
                .as_ref()
                .and_then(|g| g.read().ok().map(|r| r.clone()))
        };

        // Resolve all peer_ids first (async), then compute quality (sync).
        let mut resolved = Vec::new();
        for ip in nodes.iter() {
            let peer_id = match ip {
                IpAddr::V4(addr) => self.peers.get_peer_id_by_ipv4(addr).await,
                IpAddr::V6(addr) => self.peers.get_peer_id_by_ipv6(addr).await,
            };
            if let Some(peer_id) = peer_id {
                resolved.push((*ip, peer_id));
            }
        }

        for (ip, peer_id) in resolved {
            let route = routes.iter().find(|r| r.peer_id == peer_id);
            let has_direct = self.peers.has_peer(peer_id);

            let (loss, fingerprint) = if has_direct {
                let direct_loss = self.peers.get_peer_loss_rate(peer_id);
                let conn_id = self
                    .peers
                    .get_peer_default_conn_id(peer_id)
                    .await
                    .unwrap_or_default();
                let fp = PathFingerprint {
                    is_relay: false,
                    conn_id,
                    gateway_peer_id: 0,
                };
                (direct_loss, fp)
            } else {
                let first_hop = route.map(|r| {
                    r.next_hop_peer_id_latency_first
                        .unwrap_or(r.next_hop_peer_id)
                });
                let relay_loss = first_hop.and_then(|fh| {
                    gpm_snapshot
                        .as_ref()
                        .and_then(|gpm| self.compute_path_loss(peer_id, fh, gpm))
                });
                let fp = PathFingerprint {
                    is_relay: true,
                    conn_id: Default::default(),
                    gateway_peer_id: first_hop.unwrap_or(0),
                };
                (relay_loss, fp)
            };

            let path_cost = route.and_then(|r| r.path_latency_latency_first);

            if loss.is_none() && path_cost.is_none() {
                continue;
            }

            let candidate = ExitNodeCandidate {
                ip,
                peer_id,
                loss,
                path_cost,
                fingerprint,
            };

            match ip {
                IpAddr::V4(_) => v4.push(candidate),
                IpAddr::V6(_) => v6.push(candidate),
            }
        }

        (v4, v6)
    }

    fn evaluate_candidates(
        &self,
        candidates: &[ExitNodeCandidate],
        active_slot: &ArcSwapOption<ActiveExitNode>,
        counters: &PerVersionCounters,
        now: Instant,
    ) {
        if candidates.is_empty() {
            active_slot.store(None);
            return;
        }

        let current = active_slot.load();
        match current.as_ref() {
            Some(current_active) => {
                let current_candidate = candidates
                    .iter()
                    .find(|c| c.peer_id == current_active.peer_id);

                match current_candidate {
                    None => {
                        self.switch_to_best(candidates, None, active_slot, now);
                    }
                    Some(current) => {
                        // Detect connection-level path change (first-layer
                        // repair). For relay paths conn_id is always nil so we
                        // track gateway_peer_id; for direct paths we track
                        // conn_id and ignore transient nil values.
                        let last_fp = counters.last_fingerprint.read().clone();
                        let fingerprint_changed = current.fingerprint != last_fp;

                        let is_valid_fingerprint = current.fingerprint.is_relay
                            || !current.fingerprint.conn_id.is_nil();

                        if fingerprint_changed && is_valid_fingerprint {
                            // Not the first evaluation: a real path change.
                            let is_real_change = if current.fingerprint.is_relay {
                                last_fp.gateway_peer_id != 0
                            } else {
                                true
                            };

                            if is_real_change {
                                counters
                                    .consecutive_over_threshold
                                    .store(0, Ordering::Relaxed);
                                if current.fingerprint.is_relay {
                                    let resets =
                                        counters.grace_reset_count.fetch_add(1, Ordering::Relaxed);
                                    if resets < MAX_GRACE_RESETS {
                                        *counters.last_relay_path_change.write() = Some(now);
                                    }
                                }
                            }

                            *counters.last_fingerprint.write() = current.fingerprint.clone();
                        }

                        let in_grace = counters
                            .last_relay_path_change
                            .read()
                            .map_or(false, |t| now.duration_since(t) < CONN_SWITCH_GRACE);

                        if current.is_good() {
                            counters
                                .consecutive_over_threshold
                                .store(0, Ordering::Relaxed);
                            *counters.last_relay_path_change.write() = None;
                            counters.grace_reset_count.store(0, Ordering::Relaxed);
                            self.check_preferred_return(
                                candidates,
                                current_active,
                                current,
                                active_slot,
                                counters,
                                now,
                            );
                        } else if current.is_over_threshold() {
                            let current_loss = current.loss.unwrap_or(0);
                            if in_grace && current_loss <= CASCADE_LOSS_THRESHOLD {
                                let has_good_direct_alt = candidates.iter().any(|c| {
                                    c.peer_id != current_active.peer_id
                                        && c.is_good()
                                        && !c.fingerprint.is_relay
                                });
                                if !has_good_direct_alt {
                                    return;
                                }
                            }
                            let count = counters
                                .consecutive_over_threshold
                                .fetch_add(1, Ordering::Relaxed)
                                + 1;
                            if count < CONSECUTIVE_CONFIRM {
                                return;
                            }
                            counters
                                .consecutive_over_threshold
                                .store(0, Ordering::Relaxed);
                            self.switch_to_best(
                                candidates,
                                Some(current_active.peer_id),
                                active_slot,
                                now,
                            );
                        }
                    }
                }
            }
            None => {
                self.switch_to_best(candidates, None, active_slot, now);
            }
        }
    }

    fn check_preferred_return(
        &self,
        candidates: &[ExitNodeCandidate],
        current_active: &ActiveExitNode,
        current: &ExitNodeCandidate,
        active_slot: &ArcSwapOption<ActiveExitNode>,
        counters: &PerVersionCounters,
        now: Instant,
    ) {
        let current_idx = candidates
            .iter()
            .position(|c| c.peer_id == current_active.peer_id);

        let Some(current_idx) = current_idx else {
            return;
        };

        for candidate in candidates.iter().take(current_idx) {
            if candidate.is_return_candidate(current.loss) {
                let count = counters
                    .preferred_return_count
                    .fetch_add(1, Ordering::Relaxed)
                    + 1;
                if count >= CONSECUTIVE_CONFIRM {
                    counters.preferred_return_count.store(0, Ordering::Relaxed);
                    self.do_switch(candidate, active_slot, now, "preferred node recovered");
                }
                return;
            }
        }

        counters.preferred_return_count.store(0, Ordering::Relaxed);
    }

    fn switch_to_best(
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
            if candidate.is_good() {
                self.do_switch(candidate, active_slot, now, "quality threshold exceeded");
                return;
            }
        }

        let current_score = exclude_peer.and_then(|ep| {
            candidates
                .iter()
                .find(|c| c.peer_id == ep)
                .map(|c| c.quality_score())
        });

        let best = candidates
            .iter()
            .filter(|c| Some(c.peer_id) != exclude_peer)
            .min_by_key(|c| c.quality_score())
            .or_else(|| candidates.iter().min_by_key(|c| c.quality_score()));

        if let Some(best) = best {
            if current_score.is_some_and(|cs| best.quality_score() >= cs) {
                return;
            }
            self.do_switch(
                best,
                active_slot,
                now,
                "all nodes degraded, selecting best available",
            );
        }
    }

    fn do_switch(
        &self,
        candidate: &ExitNodeCandidate,
        active_slot: &ArcSwapOption<ActiveExitNode>,
        now: Instant,
        reason: &str,
    ) {
        let old = active_slot.load();
        let old_info = old.as_ref().map(|a| {
            (
                a.ip,
                self.peers.get_peer_loss_rate(a.peer_id).unwrap_or(0),
            )
        });

        active_slot.store(Some(Arc::new(ActiveExitNode {
            ip: candidate.ip,
            peer_id: candidate.peer_id,
        })));
        *self.last_switch_at.write() = Some(now);

        match old_info {
            Some((old_ip, old_loss)) => {
                tracing::info!(
                    from = %old_ip,
                    to = %candidate.ip,
                    from_loss_percent = old_loss,
                    to_loss_percent = ?candidate.loss,
                    to_path_cost = ?candidate.path_cost,
                    reason = %reason,
                    "exit node quality switch"
                );
            }
            None => {
                tracing::info!(
                    to = %candidate.ip,
                    to_loss_percent = ?candidate.loss,
                    to_path_cost = ?candidate.path_cost,
                    "exit node initial selection"
                );
            }
        }
    }
}

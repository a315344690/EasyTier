//! Drops kernel-originated egress on hijacked 4-tuples using pf.
//!
//! pf has no set type keyed on a full 4-tuple, so unlike the nftables backend this
//! keeps a rule per connection and reloads the anchor whenever the set changes.
//! Reloads are whole-anchor, hence the mutex around the live rule set.
//!
//! Note the anchor name is a single top-level segment. A nested path such as
//! `com.easytier.faketcp/<id>` is only evaluated if some parent ruleset carries a
//! matching `anchor` directive, which `/etc/pf.conf` does not for third parties --
//! rules loaded there would silently never run.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Mutex;

const ANCHOR_NAME: &str = "com.easytier.faketcp";

struct PfState {
    /// Live 4-tuples, rendered into the anchor on every change. Ordered so the
    /// generated ruleset is stable for a given set of connections.
    tuples: BTreeSet<(SocketAddr, SocketAddr)>,
    /// Reference token from `pfctl -E`, released once nothing is left to suppress
    /// so we don't leave pf enabled on a host where it started out disabled.
    token: Option<String>,
}

static PF_STATE: Mutex<PfState> = Mutex::new(PfState {
    tuples: BTreeSet::new(),
    token: None,
});

fn run_pfctl(args: &[&str]) -> Result<(), String> {
    let output = Command::new("pfctl")
        .args(args)
        .output()
        .map_err(|e| format!("could not run pfctl: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    Err(if stderr.is_empty() {
        format!("pfctl exited with {}", output.status)
    } else {
        stderr
    })
}

/// `pfctl -E` enables pf and bumps a reference count, reporting a token that
/// `pfctl -X <token>` later releases. Using it rather than `-e` means we do not
/// disable pf out from under something else that enabled it.
fn enable_pf() -> Option<String> {
    let output = Command::new("pfctl").arg("-E").output().ok()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    stderr
        .lines()
        .find_map(|line| line.strip_prefix("Token : "))
        .map(|token| token.trim().to_owned())
}

fn rule_for(local: &SocketAddr, remote: &SocketAddr) -> Option<String> {
    let family = match (local, remote) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) => "inet",
        (SocketAddr::V6(_), SocketAddr::V6(_)) => "inet6",
        _ => return None,
    };
    Some(format!(
        "block drop out quick {} proto tcp from {} port {} to {} port {}\n",
        family,
        local.ip(),
        local.port(),
        remote.ip(),
        remote.port()
    ))
}

/// Rewrites the anchor to match `state.tuples`, loading rules over stdin so no
/// temporary file is involved.
fn reload_anchor(state: &PfState) -> Result<(), String> {
    use std::io::Write as _;
    use std::process::Stdio;

    let rules: String = state
        .tuples
        .iter()
        .filter_map(|(local, remote)| rule_for(local, remote))
        .collect();

    let mut child = Command::new("pfctl")
        .args(["-a", ANCHOR_NAME, "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run pfctl: {e}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "pfctl stdin unavailable".to_owned())?
        .write_all(rules.as_bytes())
        .map_err(|e| format!("could not write pf rules: {e}"))?;
    let output = child
        .wait_with_output()
        .map_err(|e| format!("pfctl did not exit cleanly: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    Err(if stderr.is_empty() {
        format!("pfctl exited with {}", output.status)
    } else {
        stderr
    })
}

pub(super) fn cleanup_all() {
    let mut state = PF_STATE.lock().unwrap();
    state.tuples.clear();
    let _ = run_pfctl(&["-a", ANCHOR_NAME, "-F", "all"]);
    if let Some(token) = state.token.take() {
        let _ = run_pfctl(&["-X", &token]);
    }
    tracing::info!("faketcp: pf anchor cleaned up");
}

pub(super) struct Guard {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    active: bool,
}

impl Guard {
    pub(super) fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        if rule_for(&local_addr, &remote_addr).is_none() {
            tracing::warn!(
                ?local_addr,
                ?remote_addr,
                "faketcp: mismatched address families, no pf drop rule"
            );
            return Self {
                local_addr,
                remote_addr,
                active: false,
            };
        }

        let mut state = PF_STATE.lock().unwrap();
        if state.token.is_none() {
            state.token = enable_pf();
            if state.token.is_none() {
                tracing::warn!(
                    "faketcp: pfctl -E failed, kernel packets may collide with ours"
                );
            }
        }

        state.tuples.insert((local_addr, remote_addr));
        let active = match reload_anchor(&state) {
            Ok(()) => {
                tracing::debug!(?local_addr, ?remote_addr, "faketcp: pf drop rule added");
                true
            }
            Err(e) => {
                state.tuples.remove(&(local_addr, remote_addr));
                // Mirror Drop's invariant: a failed install that leaves nothing to
                // suppress must hand pf back, or the `pfctl -E` reference we just
                // took strands pf enabled until `cleanup_all` -- which a hard crash
                // never reaches. Only release when we are the last holder; an
                // earlier live guard keeps its own tuple in the set.
                if state.tuples.is_empty() {
                    if let Some(token) = state.token.take() {
                        let _ = run_pfctl(&["-X", &token]);
                    }
                }
                tracing::warn!(
                    error = %e,
                    ?local_addr,
                    ?remote_addr,
                    "faketcp: could not add pf drop rule"
                );
                false
            }
        };

        Self {
            local_addr,
            remote_addr,
            active,
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = PF_STATE.lock().unwrap();
        state.tuples.remove(&(self.local_addr, self.remote_addr));
        if let Err(e) = reload_anchor(&state) {
            tracing::warn!(
                error = %e,
                local_addr = ?self.local_addr,
                "faketcp: could not remove pf drop rule"
            );
        }
        // Hand pf back once we have nothing left to suppress.
        if state.tuples.is_empty() {
            if let Some(token) = state.token.take() {
                let _ = run_pfctl(&["-X", &token]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_names_the_family_and_both_endpoints() {
        let rule = rule_for(
            &"192.0.2.1:1111".parse().unwrap(),
            &"198.51.100.2:2222".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            rule,
            "block drop out quick inet proto tcp from 192.0.2.1 port 1111 \
             to 198.51.100.2 port 2222\n"
        );
    }

    /// pf wants bare IPv6 literals, not the bracketed form `SocketAddr` prints.
    #[test]
    fn v6_rule_has_unbracketed_addresses() {
        let rule = rule_for(
            &"[2001:db8::1]:1111".parse().unwrap(),
            &"[2001:db8::2]:2222".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            rule,
            "block drop out quick inet6 proto tcp from 2001:db8::1 port 1111 \
             to 2001:db8::2 port 2222\n"
        );
    }

    #[test]
    fn mismatched_families_have_no_rule() {
        assert!(
            rule_for(
                &"192.0.2.1:1111".parse().unwrap(),
                &"[2001:db8::2]:2222".parse().unwrap(),
            )
            .is_none()
        );
    }
}

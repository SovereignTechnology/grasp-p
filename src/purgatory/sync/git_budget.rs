//! Admission for individual outbound Git commands, shared by purgatory and
//! integrity repair. Denial defers work to the existing retry loop; it never
//! waits while holding a repository's write lease or a fetch-pass slot.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);
const COMMANDS_PER_MINUTE: usize = 60;
const SPECULATIVE_PER_MINUTE: usize = 6;
pub(super) const SPECULATIVE_PER_PASS: usize = 2;

#[derive(Debug)]
pub(crate) struct GitBudgetDeferred {
    pub retry_after: Duration,
    pub reason: &'static str,
}

impl std::fmt::Display for GitBudgetDeferred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Git command deferred: {}", self.reason)
    }
}

impl std::error::Error for GitBudgetDeferred {}

#[derive(Default)]
struct DomainBudget {
    starts: VecDeque<(Instant, bool)>,
    cooldown_until: Option<Instant>,
    reserved: usize,
}

impl DomainBudget {
    fn expire(&mut self, now: Instant) {
        while self
            .starts
            .front()
            .is_some_and(|(start, _)| now.duration_since(*start) >= WINDOW)
        {
            self.starts.pop_front();
        }
    }
}

/// Integrity retries restart discovery. Reserve discovery plus its first fetch
/// together so repeated advertisements cannot consume every newly freed slot.
pub(super) struct GitCommandReservation<'a> {
    budget: &'a GitCommandBudget,
    domain: &'a str,
    remaining: usize,
}

impl GitCommandReservation<'_> {
    pub(super) fn admit(&mut self) -> Result<(), &'static str> {
        self.admit_at(Instant::now())
    }

    fn admit_at(&mut self, now: Instant) -> Result<(), &'static str> {
        if self.remaining == 0 {
            return self.budget.admit_at(self.domain, false, now);
        }
        let mut domains = self.budget.domains.lock().unwrap();
        let budget = domains
            .get_mut(self.domain)
            .expect("reserved domain remains live");
        if budget.cooldown_until.is_some_and(|until| until > now) {
            return Err("remote_cooldown");
        }
        budget.expire(now);
        budget.reserved -= 1;
        self.remaining -= 1;
        budget.starts.push_back((now, false));
        Ok(())
    }
}

impl Drop for GitCommandReservation<'_> {
    fn drop(&mut self) {
        if self.remaining > 0 {
            self.budget
                .domains
                .lock()
                .unwrap()
                .get_mut(self.domain)
                .expect("reserved domain remains live")
                .reserved -= self.remaining;
        }
    }
}

#[derive(Default)]
pub(super) struct GitCommandBudget {
    domains: Mutex<HashMap<String, DomainBudget>>,
}

impl GitCommandBudget {
    pub(super) fn admit(&self, domain: &str, speculative: bool) -> Result<(), &'static str> {
        self.admit_at(domain, speculative, Instant::now())
    }

    pub(super) fn reserve_pair<'a>(
        &'a self,
        domain: &'a str,
    ) -> Result<GitCommandReservation<'a>, &'static str> {
        self.reserve_pair_at(domain, Instant::now())
    }

    fn reserve_pair_at<'a>(
        &'a self,
        domain: &'a str,
        now: Instant,
    ) -> Result<GitCommandReservation<'a>, &'static str> {
        let mut domains = self.domains.lock().unwrap();
        let budget = domains.entry(domain.to_owned()).or_default();
        budget.expire(now);
        if budget.cooldown_until.is_some_and(|until| until > now) {
            return Err("remote_cooldown");
        }
        if budget.starts.len() + budget.reserved + 2 > COMMANDS_PER_MINUTE {
            return Err("command_budget");
        }
        budget.reserved += 2;
        Ok(GitCommandReservation {
            budget: self,
            domain,
            remaining: 2,
        })
    }

    fn admit_at(&self, domain: &str, speculative: bool, now: Instant) -> Result<(), &'static str> {
        let mut domains = self.domains.lock().unwrap();
        // Retire inactive domains as clone URLs change over an archive's life.
        domains.retain(|_, budget| {
            budget
                .starts
                .back()
                .is_some_and(|(last, _)| now.duration_since(*last) < WINDOW)
                || budget.cooldown_until.is_some_and(|until| until > now)
                || budget.reserved > 0
        });
        let budget = domains.entry(domain.to_owned()).or_default();
        budget.expire(now);
        if budget.cooldown_until.is_some_and(|until| until > now) {
            return Err("remote_cooldown");
        }
        if budget.starts.len() + budget.reserved >= COMMANDS_PER_MINUTE {
            return Err("command_budget");
        }
        if speculative
            && (budget.starts.len() + budget.reserved >= COMMANDS_PER_MINUTE / 2
                || budget
                    .starts
                    .iter()
                    .filter(|(_, speculative)| *speculative)
                    .count()
                    >= SPECULATIVE_PER_MINUTE)
        {
            return Err("speculative_budget");
        }
        budget.starts.push_back((now, speculative));
        Ok(())
    }

    pub(super) fn retry_after(&self, domain: &str) -> Duration {
        let now = Instant::now();
        let domains = self.domains.lock().unwrap();
        let Some(budget) = domains.get(domain) else {
            return Duration::ZERO;
        };
        let quota = budget
            .starts
            .get(1)
            .or_else(|| budget.starts.front())
            .map(|(start, _)| *start + WINDOW);
        quota
            .into_iter()
            .chain(budget.cooldown_until)
            .map(|until| until.saturating_duration_since(now))
            .max()
            .unwrap_or_default()
    }

    pub(super) fn rate_limited(&self, domain: &str) {
        self.domains
            .lock()
            .unwrap()
            .entry(domain.to_owned())
            .or_default()
            .cooldown_until = Some(Instant::now() + WINDOW);
    }
}

/// Match explicit HTTP rejection diagnostics, not an arbitrary occurrence of
/// "429" in an OID or URL. Other errors do not establish a remote's quota.
pub(super) fn is_rate_limit_error(stderr: &str) -> bool {
    stderr.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.ends_with("the requested url returned error: 429")
            || lower.trim() == "remote: too many requests"
            || lower.trim() == "remote: rate limit exceeded"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staggered_window_reserves_discovery_and_fetch_together() {
        let budget = GitCommandBudget::default();
        let start = Instant::now();
        for second in 0..60 {
            assert!(budget
                .admit_at("server", false, start + Duration::from_secs(second))
                .is_ok());
        }
        // One newly free slot must not be spent rediscovering refs. Waiting
        // for two slots lets the fetch follow discovery even if other work
        // competes for admission in between them.
        assert!(budget.reserve_pair_at("server", start + WINDOW).is_err());
        let now = start + WINDOW + Duration::from_secs(1);
        let mut reservation = budget.reserve_pair_at("server", now).unwrap();
        assert!(budget.admit_at("server", false, now).is_err());
        assert!(reservation.admit_at(now).is_ok());
        assert!(budget.admit_at("server", false, now).is_err());
        assert!(reservation
            .admit_at(now + Duration::from_millis(100))
            .is_ok());
        assert!(budget
            .admit_at("server", false, now + Duration::from_millis(100))
            .is_err());
    }

    #[test]
    fn unused_reservations_release_capacity_and_survive_cleanup() {
        let budget = GitCommandBudget::default();
        let now = Instant::now();
        let reservation = budget.reserve_pair_at("server", now).unwrap();
        // No command has started yet, but pruning for another domain must
        // not remove the outstanding reservation.
        assert!(budget.admit_at("other", false, now + WINDOW).is_ok());
        drop(reservation);
        for _ in 0..60 {
            assert!(budget.admit_at("server", false, now + WINDOW).is_ok());
        }
        assert!(budget.admit_at("server", false, now + WINDOW).is_err());
    }

    #[test]
    fn cold_archive_backlog_reserves_capacity_for_advertised_work() {
        let budget = GitCommandBudget::default();
        let now = Instant::now();
        let mut useful_repositories = 0;
        let mut speculative = 0;
        // Many repositories share one server. Each has advertised tips and
        // hundreds of unavailable tips; the missing backlog cannot spend the
        // budget needed by later repositories' advertisements and batches.
        for _ in 0..100 {
            if budget.admit_at("server", false, now).is_err() {
                break;
            }
            if budget.admit_at("server", false, now).is_err() {
                break;
            }
            useful_repositories += 1;
            for _ in 0..126 {
                if budget.admit_at("server", true, now).is_err() {
                    break;
                }
                speculative += 1;
            }
        }
        assert_eq!(speculative, 6);
        assert_eq!(useful_repositories, 27);
        assert_eq!(budget.admit_at("server", false, now), Err("command_budget"));
        assert!(budget.admit_at("other-server", false, now).is_ok());
        assert!(budget.admit_at("server", false, now + WINDOW).is_ok());
        assert!(budget.admit_at("server", true, now + WINDOW).is_ok());
    }

    #[test]
    fn speculative_requests_stop_at_half_usage_even_without_prior_speculation() {
        let budget = GitCommandBudget::default();
        let now = Instant::now();
        for _ in 0..30 {
            assert!(budget.admit_at("server", false, now).is_ok());
        }
        assert_eq!(
            budget.admit_at("server", true, now),
            Err("speculative_budget")
        );
        assert!(budget.admit_at("server", false, now).is_ok());
    }

    #[test]
    fn explicit_rate_limit_cools_down_all_roles_then_recovers() {
        let budget = GitCommandBudget::default();
        budget.rate_limited("server");
        let now = Instant::now();
        for speculative in [false, true] {
            assert_eq!(
                budget.admit_at("server", speculative, now),
                Err("remote_cooldown")
            );
            assert!(budget.admit_at("other", speculative, now).is_ok());
        }
        assert!(budget.admit_at("server", false, now + WINDOW).is_ok());
        assert!(is_rate_limit_error(
            "fatal: unable to access 'https://host/repo': The requested URL returned error: 429\n"
        ));
        assert!(!is_rate_limit_error(
            "fatal: https://host/429.git not found"
        ));
        assert!(!is_rate_limit_error(
            "fatal: remote error: upload-pack: not our ref 429abc"
        ));
        assert!(!is_rate_limit_error(
            "The requested URL returned error: 403"
        ));
    }
}

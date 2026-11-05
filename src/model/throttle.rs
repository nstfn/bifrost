use std::collections::VecDeque;

use chrono::{DateTime, Duration, Utc};

pub struct Throttle {
    interval: Duration,
    last_update: DateTime<Utc>,
}

impl Throttle {
    #[must_use]
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            last_update: Utc::now(),
        }
    }

    #[must_use]
    pub fn from_fps(fps: u32) -> Self {
        let interval = Duration::microseconds(1_000_000 / i64::from(fps));
        Self::new(interval)
    }

    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.elapsed_since(Utc::now())
    }

    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    #[must_use]
    pub fn elapsed_since(&self, now: DateTime<Utc>) -> Duration {
        now - self.last_update
    }

    pub fn tick(&mut self) -> bool {
        self.tick_at(Utc::now())
    }

    /// Like [`Self::tick`], at a given point in time.
    ///
    /// The throttle tracks deadlines rather than arrival times: an accepted
    /// tick advances `last_update` by one interval, not to `now`. Restarting
    /// the interval at each arrival made a 47 fps input pass only every 3rd
    /// frame (63 ms gaps, 16 fps instead of 20). `last_update` never trails
    /// `now` by more than one interval, so a pause cannot cause a burst.
    pub fn tick_at(&mut self, now: DateTime<Utc>) -> bool {
        if self.elapsed_since(now) < self.interval {
            return false;
        }

        self.last_update = (self.last_update + self.interval).max(now - self.interval);

        true
    }
}

pub struct ThrottleQueue<T> {
    throttle: Throttle,
    queue: VecDeque<T>,
    capacity: usize,
}

impl<T> ThrottleQueue<T> {
    #[must_use]
    pub const fn new(throttle: Throttle, capacity: usize) -> Self {
        Self {
            throttle,
            queue: VecDeque::new(),
            capacity,
        }
    }

    pub fn push(&mut self, value: T) -> bool {
        if !self.throttle.tick() {
            return false;
        }

        if self.queue.len() >= self.capacity {
            return false;
        }

        self.queue.push_front(value);

        true
    }

    pub fn pop(&mut self) -> Option<T> {
        self.queue.pop_back()
    }

    pub fn clear(&mut self) {
        self.queue.clear();
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, Utc};

    use crate::model::throttle::Throttle;

    /// Feed the throttle one tick every `step_ms` in `[start_ms, end_ms)`,
    /// and return the offsets (in ms) of the accepted ticks.
    fn feed(
        throttle: &mut Throttle,
        t0: DateTime<Utc>,
        start_ms: i64,
        end_ms: i64,
        step_ms: usize,
    ) -> Vec<i64> {
        (start_ms..end_ms)
            .step_by(step_ms)
            .filter(|ms| throttle.tick_at(t0 + Duration::milliseconds(*ms)))
            .collect()
    }

    fn throttle_at(fps: u32, t0: DateTime<Utc>) -> Throttle {
        let mut throttle = Throttle::from_fps(fps);
        throttle.last_update = t0 - throttle.interval();
        throttle
    }

    #[test]
    fn fast_input_is_accepted_at_configured_rate() {
        let t0 = Utc::now();
        for fps in [20, 25] {
            let mut throttle = throttle_at(fps, t0);
            let accepted = feed(&mut throttle, t0, 0, 2000, 21).len();
            let expected = 2 * usize::try_from(fps).unwrap();
            assert!(
                accepted.abs_diff(expected) <= 1,
                "{fps} fps: accepted {accepted} frames in 2 s, expected {expected}"
            );
        }
    }

    #[test]
    fn input_at_configured_rate_is_not_dropped() {
        let t0 = Utc::now();
        let mut throttle = throttle_at(20, t0);
        assert_eq!(feed(&mut throttle, t0, 0, 2000, 50).len(), 40);
    }

    #[test]
    fn pause_does_not_cause_burst() {
        let t0 = Utc::now();
        let mut throttle = throttle_at(20, t0);
        feed(&mut throttle, t0, 0, 1000, 21);

        // 1 s pause, then resume at 47 fps for 1 s
        let resumed = feed(&mut throttle, t0, 2000, 3000, 21);

        // the steady rate allows 2 frames per 100 ms: at most 1 extra after the pause
        let burst = resumed.iter().filter(|ms| **ms < 2100).count();
        assert!(burst <= 3, "burst after pause: {resumed:?}");
        assert!(
            resumed.len() <= 21,
            "accepted {} frames in 1 s",
            resumed.len()
        );
    }
}

use std::time::Instant;

pub(crate) trait Timer {
    fn expired(&self, now: Instant) -> bool;
    #[cfg(test)]
    fn remaining_secs(&self, now: Instant) -> String;
}

impl Timer for Instant {
    fn expired(&self, now: Instant) -> bool {
        self <= &now
    }

    #[cfg(test)]
    fn remaining_secs(&self, now: Instant) -> String {
        match self.checked_duration_since(now) {
            Some(dt) => format!("+{}s", dt.as_secs()),
            None => format!("-{}s", now.duration_since(*self).as_secs()),
        }
    }
}

pub(crate) trait TimerV2 {
    fn expired(&self, now: Instant, default_value: bool) -> bool;
    fn accumulate_min(&self, acc: &mut Option<Instant>);
    #[cfg(test)]
    fn remaining_secs(&self, now: Instant) -> String;
}

impl TimerV2 for Option<Instant> {
    fn expired(&self, now: Instant, default_value: bool) -> bool {
        match self {
            Some(instant) => instant <= &now,
            None => default_value,
        }
    }

    fn accumulate_min(&self, acc: &mut Option<Instant>) {
        if let Some(instant) = self {
            match acc {
                Some(t) => {
                    if instant < t {
                        *acc = Some(*instant);
                    }
                }
                None => {
                    *acc = Some(*instant);
                }
            }
        }
    }

    #[cfg(test)]
    fn remaining_secs(&self, now: Instant) -> String {
        match self {
            Some(instant) => match instant.checked_duration_since(now) {
                Some(dt) => format!("+{}s", dt.as_secs_f64()),
                None => format!("-{}s", now.duration_since(*instant).as_secs_f64()),
            },
            None => "none".into(),
        }
    }
}

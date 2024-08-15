use std::time::Instant;

pub(crate) trait Timer {
    fn has_expired(&self, now: Instant) -> bool;
    #[cfg(test)]
    fn remaining_secs(&self, now: Instant) -> String;
}

impl Timer for Option<Instant> {
    fn has_expired(&self, now: Instant) -> bool {
        match self {
            Some(instant) => instant <= &now,
            None => false,
        }
    }

    #[cfg(test)]
    fn remaining_secs(&self, now: Instant) -> String {
        match self {
            Some(instant) => match instant.checked_duration_since(now) {
                Some(dt) => format!("+{}s", dt.as_secs()),
                None => format!("-{}s", now.duration_since(*instant).as_secs()),
            },
            None => "none".into(),
        }
    }
}

impl Timer for Instant {
    fn has_expired(&self, now: Instant) -> bool {
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

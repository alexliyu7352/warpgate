use std::fmt::Debug;

use crate::consts::TICKET_SELECTOR_PREFIX;
use crate::Secret;

pub enum AuthSelector {
    User {
        username: String,
        target_name: String,
    },
    Ticket {
        secret: Secret<String>,
    },
}

impl<T: AsRef<str>> From<T> for AuthSelector {
    fn from(selector: T) -> Self {
        if let Some(secret) = selector.as_ref().strip_prefix(TICKET_SELECTOR_PREFIX) {
            let secret = Secret::new(secret.into());
            return Self::Ticket { secret };
        }

        let separator = if selector.as_ref().contains('#') {
            '#'
        } else if selector.as_ref().contains(':') {
            ':'
        } else {
            '-'
        };

        let mut parts = selector.as_ref().splitn(2, separator);
        let username = parts.next().unwrap_or("").to_string();
        let target_name = parts.next().unwrap_or("").to_string();
        Self::User {
            username,
            target_name,
        }
    }
}

impl Debug for AuthSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User {
                username,
                target_name,
            } => write!(f, "<{username} for {target_name}>"),
            Self::Ticket { .. } => write!(f, "<ticket>"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(s: &str) -> (String, String) {
        match AuthSelector::from(s) {
            AuthSelector::User {
                username,
                target_name,
            } => (username, target_name),
            _ => panic!("expected User selector"),
        }
    }

    #[test]
    fn test_dash_separator() {
        let (username, target) = user("alice-myserver");
        assert_eq!(username, "alice");
        assert_eq!(target, "myserver");
    }

    #[test]
    fn test_colon_separator_backward_compat() {
        let (username, target) = user("alice:myserver");
        assert_eq!(username, "alice");
        assert_eq!(target, "myserver");
    }

    #[test]
    fn test_hash_separator_backward_compat() {
        let (username, target) = user("alice#myserver");
        assert_eq!(username, "alice");
        assert_eq!(target, "myserver");
    }

    #[test]
    fn test_colon_takes_priority_over_dash() {
        // If both ':' and '-' are present, ':' is used (backward compat)
        let (username, target) = user("alice-extra:myserver");
        assert_eq!(username, "alice-extra");
        assert_eq!(target, "myserver");
    }

    #[test]
    fn test_hash_takes_priority_over_colon() {
        // '#' takes highest priority
        let (username, target) = user("alice:extra#myserver");
        assert_eq!(username, "alice:extra");
        assert_eq!(target, "myserver");
    }

    #[test]
    fn test_ticket_selector() {
        match AuthSelector::from("ticket-mysecret") {
            AuthSelector::Ticket { secret } => {
                assert_eq!(secret.expose_secret(), "mysecret")
            }
            _ => panic!("expected Ticket selector"),
        }
    }
}

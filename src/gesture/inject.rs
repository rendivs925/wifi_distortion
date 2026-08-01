use std::process::Command;

use anyhow::{Context, Result};

/// Map gesture label -> xdotool key name.
pub fn key_for_gesture(label: &str) -> Option<&'static str> {
    match label {
        "swipe-up" => Some("Up"),
        "swipe-down" => Some("Down"),
        "push" => Some("Return"),
        "pull-back" => Some("Escape"),
        _ => None,
    }
}

/// Emit a keypress via xdotool on the current X11 display.
pub fn emit_key(key: &str) -> Result<()> {
    let status = Command::new("xdotool")
        .args(["key", "--clearmodifiers", key])
        .status()
        .context("failed to spawn xdotool (is xdotool installed?)")?;

    if !status.success() {
        return Err(anyhow::anyhow!(
            "xdotool exited with status {}",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_gestures() {
        assert_eq!(key_for_gesture("push"), Some("Return"));
        assert_eq!(key_for_gesture("swipe-up"), Some("Up"));
        assert_eq!(key_for_gesture("swipe-down"), Some("Down"));
        assert_eq!(key_for_gesture("pull-back"), Some("Escape"));
        assert_eq!(key_for_gesture("still"), None);
        assert_eq!(key_for_gesture("unknown"), None);
    }
}

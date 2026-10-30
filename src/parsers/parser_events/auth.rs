// SPDX-License-Identifier: GPL-3.0-only

/// Classification of an iOS authentication log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IosAuthClass {
    pub success: bool,
    pub auth_type: &'static str,
}

pub fn classify_ios_auth_message(msg: &str) -> Option<IosAuthClass> {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("before first unlock")
        || lower.contains("companions not supported")
        || lower.contains("companionforuser")
    {
        return None;
    }
    if lower.contains("processed authentication request") {
        let success = lower.contains("success=yes");
        let auth_type = if lower.contains("type: 2") || lower.contains("biometric") {
            "biometric"
        } else {
            "passcode"
        };
        return Some(IosAuthClass { success, auth_type });
    }
    if lower.contains("unlock attempt succeeded") {
        let success = lower.split("succeeded:").nth(1).is_some_and(|rest| {
            rest.trim_start().to_ascii_lowercase().starts_with("yes")
        });
        return Some(IosAuthClass {
            success,
            auth_type: "passcode",
        });
    }
    if lower.contains("identity match failed")
        || lower.contains("processmatchfailreason")
        || lower.contains("bio lockout")
        || (lower.contains("biometry is locked out") && !lower.contains("before first unlock"))
    {
        return Some(IosAuthClass {
            success: false,
            auth_type: "biometric",
        });
    }
    if lower.contains("passcode authentication succeeded") {
        return Some(IosAuthClass {
            success: true,
            auth_type: "passcode",
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_processed_auth_failure() {
        let c = classify_ios_auth_message(
            "Processed authentication request (success=NO): <SBFAuthenticationRequest: …; hasPasscode: YES>",
        )
        .unwrap();
        assert!(!c.success);
        assert_eq!(c.auth_type, "passcode");
    }

    #[test]
    fn classifies_processed_auth_success() {
        let c = classify_ios_auth_message(
            "Processed authentication request (success=YES): <SBFAuthenticationRequest: 0x1; type: 1; hasPasscode: YES>",
        )
        .unwrap();
        assert!(c.success);
        assert_eq!(c.auth_type, "passcode");
    }

    #[test]
    fn classifies_unlock_attempt_failure() {
        let c = classify_ios_auth_message("Unlock attempt succeeded: no").unwrap();
        assert!(!c.success);
        assert_eq!(c.auth_type, "passcode");
    }

    #[test]
    fn classifies_unlock_attempt_success() {
        let c = classify_ios_auth_message("Unlock attempt succeeded: yes").unwrap();
        assert!(c.success);
    }

    #[test]
    fn classifies_biometric_match_failed() {
        let c = classify_ios_auth_message(
            "Base unlock behavior received biometric event: identity match failed",
        )
        .unwrap();
        assert!(!c.success);
        assert_eq!(c.auth_type, "biometric");
    }

    #[test]
    fn classifies_bk_match_fail_reason() {
        let c = classify_ios_auth_message(
            "BKMatchOperation::processMatchFailReason: 1 => delegate:A000007D2CC55E0(<private>)",
        )
        .unwrap();
        assert!(!c.success);
        assert_eq!(c.auth_type, "biometric");
    }

    #[test]
    fn classifies_passcode_bio_lockout_status() {
        let c = classify_ios_auth_message(
            "Passcode view status: Face ID or Mesa needs passcode bio lockout",
        )
        .unwrap();
        assert!(!c.success);
        assert_eq!(c.auth_type, "biometric");
    }

    #[test]
    fn classifies_lockdownd_passcode_success() {
        let c = classify_ios_auth_message("Passcode authentication succeeded.").unwrap();
        assert!(c.success);
        assert_eq!(c.auth_type, "passcode");
    }

    #[test]
    fn classifies_biometry_lockout() {
        let c = classify_ios_auth_message(
            "User 501 is locked out: Error Domain=com.apple.LocalAuthentication Code=-8 \"Biometry is locked out.\" UserInfo={Subcode=3}",
        )
        .unwrap();
        assert!(!c.success);
        assert_eq!(c.auth_type, "biometric");
    }

    #[test]
    fn ignores_before_first_unlock_noise() {
        assert!(classify_ios_auth_message(
            "User 501 is locked out: Error Domain=com.apple.LocalAuthentication Code=-8 \"Biometry is not available before first unlock.\""
        )
        .is_none());
    }

    #[test]
    fn ignores_companion_auth_stubs() {
        assert!(classify_ios_auth_message(
            "companionForUser:501 type:4 -> Error Domain=com.apple.LocalAuthentication Code=-1000 \"companions not supported\" UserInfo={NSLocalizedDescription=Échec d’authentification.}"
        )
        .is_none());
    }

    #[test]
    fn ignores_unrelated() {
        assert!(classify_ios_auth_message("Registered DNS (pairing)").is_none());
    }
}

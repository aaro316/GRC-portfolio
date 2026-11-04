# Sample Security Incident Report

## 1. Incident Summary

| Field | Details |
|---|---|
| Incident ID | SOC-001 |
| Incident Type | Suspicious Authentication Activity |
| Severity | High |
| Status | Open |
| Detection Source | Privacy-Aware Mini SOC |
| Affected Account | admin |
| Source IP | 203.0.113.25 |
| Affected Host | linux-lab |
| Date | 26 October 2026 |

## 2. Incident Description

The monitoring system detected repeated failed authentication attempts originating from the same source IP address, followed by a successful login to the targeted account.

The activity triggered two detection rules:

1. Repeated Failed Logins.
2. Successful Login After Repeated Failures.

This pattern may indicate a brute-force attempt followed by a potentially successful account compromise.

## 3. Event Timeline

| Time | Event | Observation |
|---|---|---|
| 09:02 | Failed login | First failed attempt for admin |
| 09:03 | Failed login | Second failed attempt |
| 09:04 | Failed login | Third failed attempt |
| 09:05 | Failed login | Fourth failed attempt |
| 09:06 | Failed login | Fifth failed attempt |
| 09:06 | Alert generated | Repeated Failed Logins |
| 09:07 | Successful login | Authentication succeeded for admin |
| 09:07 | Alert generated | Successful Login After Repeated Failures |

## 4. Detection Analysis

### Alert 1: Repeated Failed Logins

- Detection rule: Five or more failed login attempts from the same IP within five minutes.
- Observed attempts: Five.
- Source IP: 203.0.113.25.
- Severity: High.

**Analysis:** Five consecutive failed authentication attempts occurred within the configured detection window. This activity is consistent with a possible brute-force login attempt.

### Alert 2: Successful Login After Repeated Failures

- Detection rule: Successful login following at least three failed attempts for the same account and IP within ten minutes.
- Account: admin.
- Source IP: 203.0.113.25.
- Severity: High.

**Analysis:** A successful authentication occurred immediately after repeated failures for the same account and source IP. This warrants further investigation because the account may have been compromised.

## 5. Potential Security Impact

- Possible unauthorised access to the admin account.
- Potential exposure of system resources.
- Possibility of further malicious activity if the login was unauthorised.

The available synthetic logs do not establish whether the successful login was malicious.

## 6. Recommended Incident Response Actions

1. Validate whether the successful login was authorised.
2. Review additional authentication activity associated with the account and source IP.
3. Check for suspicious activity following the successful login.
4. If compromise is confirmed, disable or secure the affected account.
5. Reset credentials and review active sessions.
6. Document investigation findings and update the alert status.
7. Review authentication policies and consider additional access controls.

## 7. Investigation Status

**Current status: Open**

No containment or remediation actions have been executed by this prototype. The recommended actions above represent the next steps for a SOC analyst.

## 8. Privacy Considerations

- The incident uses synthetic authentication events.
- The source IP belongs to a documentation-only address range.
- Usernames and IP addresses are masked in console alert output.
- Original values remain available in the local SQLite database and dashboard for investigation.

## 9. Conclusion

The Privacy-Aware Mini SOC successfully identified two suspicious authentication patterns using rule-based detection.

The incident demonstrates how repeated authentication failures followed by a successful login can be identified, recorded, prioritised, and investigated as part of a basic Security Operations Centre workflow.
# Incident Response

## Deployment regression
Stop rollout, rollback to immutable prior release, correlate telemetry to release ID,
preserve evidence, identify the missing control, and add a regression test.

## Credential exposure
Revoke, determine blast radius, rotate dependencies, inspect audit logs, replace static
credentials with workload identity where possible, and strengthen secret scanning.

## Cost anomaly
Identify workload and owner, inspect scaling/backlog/logging/egress, apply temporary guardrails,
fix root cause, and update budget/defaults.

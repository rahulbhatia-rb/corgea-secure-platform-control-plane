# Developer Golden Path

The secure path should be the fastest path.

## New service
1. scaffold from a versioned template
2. workload identity by default
3. managed secret references, never plaintext credentials
4. SLO and incident owner registration
5. logs, metrics and traces enabled automatically
6. CI security checks inherited by default
7. preview environment support
8. cost budget and owner metadata

## Pull request
Unit/integration tests, SAST, SCA, secret scanning, container scanning, IaC scanning,
platform policy evaluation, and artifact provenance.

## Deployment
Immutable signed artifact, progressive rollout, health validation, automated rollback,
and release annotations in the observability system.

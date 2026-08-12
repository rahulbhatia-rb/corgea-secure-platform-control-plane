# Corgea Secure Platform Control Plane

Independent proof-of-work inspired by Corgea's Founding DevOps Engineer role.

The core artifact is an executable **production deployment gate** that evaluates every service across:
- security
- reliability
- developer velocity
- cost

It is designed around the problem a security startup actually has: keep engineering fast without making
security, observability, rollback, or cost controls optional.

## Run

```bash
go test ./...
go vet ./...
go run ./cmd/platformgate -contract examples/secure-service.json
go run ./cmd/platformgate -contract examples/unsafe-service.json
```

The secure example passes; the intentionally unsafe production contract is rejected.

## What the gate checks

Security:
- workload identity, managed secrets, least-privilege IAM
- private data stores/admin surfaces
- hardened containers
- SAST, SCA, container, IaC and secret scanning
- signed artifacts

Reliability:
- health checks, redundancy, zone awareness
- automated rollback
- SLO + incident ownership
- tested backup/restore
- bounded worker concurrency

Developer velocity:
- CI build-time budget
- automated deploys
- reusable service templates
- preview environments
- self-service observability

Cost:
- workload budget
- autoscaling ceilings
- log-retention limits
- idle-environment TTL
- cost owner

## Operating model

```text
PR -> security scans -> platformgate -> signed artifact -> progressive deploy
      |                    |                              |
      + security           + reliability                  + SLO/telemetry
      + supply chain       + velocity                     + rollback
                           + cost
```

## Why this maps to Corgea

A security company cannot solve one side of the equation by slowing the other side down. My default
platform model is:

- secure by default
- observable by default
- cost-bounded by default
- self-service where possible
- exceptions explicit and reviewable

See `docs/30-60-90.md` for how I would phase this as a founding DevOps owner.

## Disclaimer

Independent engineering prototype based on Corgea's public job description. It does not represent
Corgea's private infrastructure.

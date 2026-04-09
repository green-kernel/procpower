# Security

This document describes how to report security issues and how ProcPower should be deployed and reviewed from a security perspective.

## Reporting a Vulnerability

Please do not report suspected vulnerabilities in public GitHub issues.

Send reports to `didi@ribalba.de` and include:

- A clear description of the issue and affected interface.
- The kernel version, ProcPower version or commit, and deployment context.
- Reproduction steps, proof-of-concept code, or logs if available.
- Whether the issue is limited to a single cgroup, container, or host.

Reports will be handled privately until a fix or mitigation is available.

## Security Model

ProcPower is a Linux kernel module that exposes per-process resource and power-related metrics. Its security goal is to make these metrics available without allowing one workload to learn more than it should about unrelated workloads on the same host.

The design intentionally keeps kernel-space logic focused on data collection and access control. Complex analysis, modeling, and policy decisions should stay in user space where they are easier to inspect, test, and replace.

## Threat Model

### In Scope

- Statistical side-channel attacks where a co-located workload attempts to infer information about other processes from exposed metrics.
- Data exposure risks in shared hosts, containers, and other multi-tenant environments.
- Kernel attack-surface risks introduced by collection, accounting, and export paths.
- Supply-chain trust risks around source authenticity, release integrity, and build verifiability.

### Assumptions

- The underlying Linux kernel, cgroup isolation, and container runtime are functioning correctly.
- Host administrators decide whether exposing these metrics is appropriate for their environment.
- Data center operators and downstream distributors may apply stricter controls than the upstream project.

### Out of Scope

- Provider-side decisions about how to present, aggregate, anonymize, or resell collected metrics.
- Risks that require both a ProcPower defect and an independent kernel, cgroup, or container-isolation failure. These scenarios still matter, but they are lower priority than direct defects in ProcPower itself.

## Deployment Guidance

### Prefer Cgroup-Scoped Visibility

Unprivileged access should be limited to cgroup-scoped views such as `/proc/energy/cgroup`. Host-wide views such as `/proc/energy/all` and debug interfaces should remain restricted to administrators.

This isolation boundary is a core part of the security model. Deployments that weaken it should assume a higher data-exposure risk.

### Side-Channel Risk and Windowing

Time-based aggregation is an intentional mitigation against statistical side channels. Shorter sampling intervals and shorter reporting windows provide finer-grained telemetry, but they also increase the risk that one workload can infer activity from another workload.

There is no universal "safe" sampling frequency or window size. What is statistically safe depends on:

- The number of co-located processes and tenants.
- How long monitored processes run.
- Whether workloads are interactive, batch, or highly periodic.
- The legal and business risk tolerance of the operator.

Until an operator has validated a tighter configuration, conservative defaults are recommended for shared systems:

- Treat `window_ns` as the main privacy control and keep it coarse enough to avoid exposing near-real-time behavior.
- Avoid reducing `sample_ns` or `window_ns` aggressively in multi-tenant or container-heavy environments without a documented justification.
- Re-evaluate configuration separately for servers, desktops, CI hosts, and virtualized environments.

For single-user or lab environments, finer-grained settings may be acceptable, but they should not be copied into shared production environments without review.

## Kernel-Space Security Priorities

Kernel code is on purpose small and limited to collection, accounting, and access control. Features default to user-space implementation unless kernel-space code is strictly necessary.

Following areas in the kernel code are high-risk:

- Memory allocation and object lifetime.
- Buffer sizing, formatting, and bounds handling.
- Copy operations and user-kernel data transfer.
- Permission checks on `/proc` and debugfs interfaces.
- Any logic that affects cgroup scoping or process visibility.


## Integrity and Build Verifiability

To strengthen supply-chain trust, maintainers should work toward:

- Signed commits for maintained branches.
- Signed release artifacts.
- Public CI workflows for linting, static analysis, and build verification.
- Reproducible and inspectable release steps instead of private, unverifiable scripts.

These controls are important for enterprise users, Linux distributors, and data center operators who need to verify both source provenance and release integrity.

## Residual Risk

Low-level resource and power metrics are inherently sensitive in shared environments. ProcPower reduces that risk through cgroup scoping and time-based aggregation, but it cannot eliminate it entirely.

If your environment has strict inter-tenant confidentiality requirements, treat ProcPower as a security-sensitive component, deploy it conservatively, and restrict or disable it where the residual leakage risk is unacceptable.

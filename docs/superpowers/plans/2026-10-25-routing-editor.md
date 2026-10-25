# Routing Editor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Edit and safely apply RU/EXIT routing in the authenticated panel.
**Architecture:** Pure validation and filesystem transaction in scripts/routing.py;
manager owns Linux service control; panel exposes authenticated read/save endpoints.
**Tech Stack:** Python standard library, plain HTML/JavaScript, sing-box 1.14.4.
**Spec:** docs/superpowers/specs/2026-10-25-routing-editor-design.md

## Global Constraints
- Preserve existing profiles, secrets, state, rule files and TProxy on upgrade.
- Manual domains before manual IPs before GeoIP; EXIT uses current selector.
- Validate staged settings before live writes, restore on application error.
- Existing Basic Auth, CSRF, loopback-only access; no new dependencies.

## Review Focus
- Conflicting subnets / wildcard domains: reject opposite-direction overlaps.
- Invalid or oversized data: fail before mutation.
- Service failure: restore bytes, missing-file state and config before recovery restart.
- Concurrent browser tabs: reject stale revision.
- Existing unsupported JSON: report error rather than silently overwrite.

### Task 1: Rule validation and transaction
Files: scripts/routing.py, scripts/core.py, tests/test_routing.py.
Interfaces: normalize_routes(payload), read_routes(directory),
save_routes(directory, payload, revision, validate, apply, rollback).
- [x] Write tests for normalization, invalid input, overlaps, stale writes and rollback.
- [x] Run tests red; implement store and domain-first order; run full suite green.

### Task 2: Manager and web panel
Files: scripts/manager.py, panel/panel.py, tests/test_panel.py.
Interfaces: manager routes read; manager routes-save JSON {rules, revision};
GET /api/routes and POST /api/routes-save. Both return {rules, revision}.
- [x] Test real HTTP authentication, CSRF, malformed save and successful round-trip.
- [x] Implement manager staged validation/restart/recovery and editor loading/save/error UX.
- [x] Run suite and browser smoke check (mock service boundary only).

### Task 3: Upgrade, docs and delivery
Files: install.sh, README.md.
- [x] Document explicit update sequence preserving deployment data and restoring AWG processes; document editor precedence/limits.
- [x] Full tests, Python/Bash/JS syntax, fresh review; fix important findings.
- [x] Commit, push, verify remote files and GitHub Actions, merge to main as authorized.

## Execution record
- User approved the proposed scope and requested implementation/publication in GitHub.
- Native worktree tool could not locate the nested repository; used a clean feature branch in the existing checkout.
- Baseline: 9 tests green. New store/API tests observed red before implementation.
- Ruling: use an explicit documented upgrade sequence instead of adding a second installer mode; avoids expanding the installer surface and restores AWG children stopped with the old panel.
- Review found and fixed stale selector recovery and suffix-apex import, with regressions.
- 26 tests passed locally, including Linux manager tests with only the unavailable fcntl module stubbed; native Linux CI required before completion.
- Browser smoke: save/normalization/conflict rejection passed using real rule-store and fake VPN service callbacks.

# Control Groups (two-person approval) — implementation and test report

## What was broken

Policy parsing produced a `ControlGroup` on the matched permission and the ACL
carried it into `ACLResults`, but every runtime piece was an OSS stub:

- `checkNeedsCG` / `checkErrControlGroupTokenNeedsCreated` in
  `vault/request_handling_util.go` were `return nil` / `return false`.
- `controlGroupUnwrap` returned `errors.New("control groups unavailable")`.
- The `sys/control-group/{authorize,request}` and `sys/config/control-group`
  endpoints were registered only as "enterprise-only feature" stubs.

So a controlled request either executed immediately (nothing collected a second
opinion) or was rejected as unsupported. A single high-privilege credential
could perform the protected operation alone.

## What was built

A working control-group runtime in OSS (`vault/control_group.go`) plus the
minimal wiring in the existing request pipeline.

### Lifecycle

1. **Detection (hot path).** `CheckToken` already computes `ACLResults` for the
   request. Immediately after policy evaluation it calls
   `controlGroupCheckNeeded`, which inspects `ACLResults.ControlGroup` and the
   matched capability bitmap. For a request with no control group this is a nil
   check and returns — no storage read, no new allocation. When the request is
   controlled and is not itself a control-group run, `CheckToken` returns the
   sentinel `ErrControlGroupPending`.
2. **Hold.** In `handleRequest`, before the caller's token uses are decremented,
   the sentinel is turned into a pending request: the method, path and data are
   deep-frozen into a record, a one-time token carrying only the
   `control-group` policy is minted, the record is persisted, and the response
   is returned with the token in a `wrap_info` block (same shape as response
   wrapping, so existing clients/UI recognize it). A held request does not
   execute and does not consume the caller's token.
3. **Approval.** `sys/control-group/authorize` records an approval or denial.
   The approver must (a) not be the requester, (b) be a member of a factor
   identity named by the policy, and (c) itself hold the policy capability for
   the frozen operation/path. Approvals count once per entity; a denial
   terminates the request. When every factor reaches its threshold the record is
   marked approved in the same durable write as the last approval.
4. **Completion.** The requester presents the control-group token to
   `sys/wrapping/unwrap`. The stored record alone drives the replay — operation,
   path and data are read from the record only, so the completion call cannot
   substitute parameters. A write-ahead claim marks the record completed before
   the effect runs; on a backend error the claim is released so it can be
   retried.
5. **Cancel / expire.** The requester may withdraw; an authorized approver may
   cancel (e.g. threshold unreachable). Past the deadline the record is expired
   on access and later swept from storage.

### Hard constraints

- **Frozen parameters:** replay reads only the stored record; the completion
  call's data is ignored (covered by `TestControlGroup_FrozenParameters`).
- **One-time, non-extendable token:** the pending token has `NumUses=1`, a TTL
  equal to the request lifetime, and no ability to be renewed; the record's
  `ExpirationTime` is fixed at creation. Replays after completion are refused.
- **Durability / no "approved but not executed":** approvals persist before they
  count and completion claims before it runs. A storage failure aborts the
  approval/execution (`TestControlGroup_PersistenceFailureAbortsApproval`).
- **Write-time validation:** self-contradictory `control_group` blocks are
  rejected at policy-write time (negative TTL, `ttl`+`max_ttl` together, no
  factors, factor without identity, `approvals <= 0`, no groups, empty group).
- **Full audit trail:** a persisted per-request trail (`audit_trail`, exported by
  `sys/control-group/request`) plus dedicated audit-device records
  (`control-group/requested`, `.../authorized`, `.../denied`, `.../cancelled`,
  `.../completed` with the executed request and response).
- **No hot-path cost for uncontrolled paths:** nil-check only; verified by
  `TestControlGroup_NonControlledPathUnaffected` (no pending record created).

### Backwards compatibility

- Response wrapping/unwrapping semantics are unchanged; a pending request uses
  the same `wrap_info` + `sys/wrapping/unwrap` path.
- Existing policy files load unchanged: a missing `max_ttl`, or the legacy `ttl`
  key, still parses (`TestControlGroup_LegacyPolicyStillLoads`).
- Permission decisions and denial codes are unchanged. The only ACL change is
  that `ACLResults.CapabilitiesBitmap` is now populated **when a control group
  is present** (it was previously only set in the cap-check-only path), so the
  enforcement code can tell which capabilities the matched permission grants.

### Known scope

Control groups are an ACL construct. The root token bypasses ACL evaluation and
is therefore not subject to control groups, and a token without an entity (no
requester identity to exclude from approving) is refused rather than allowed to
self-approve.

## Tests

`vault/control_group_test.go` (18 tests) runs on a single-node in-memory core
with a noop audit device, a controlled KV path, identity entities, a controlling
group, and tokens for a requester, two approvers, and an outsider.

Covered: full approval flow, threshold-of-two, unknown approver, self-approval,
repeated approval, denial, requester cancel, approver cancel when unreachable,
unauthorized cancel, expiry, frozen parameters, single-use replay, non-controlled
path isolation, entity-less token refusal, approver lacking capability,
result parity with direct execution, persistence-failure abort, and legacy
policy loading.

Policy write-time validation is covered by
`TestPolicy_ParseControlGroupValidation` (8 subtests) and the pre-existing
`TestPolicy_ParseControlGroup{,_WrongCaps}`.

## Results (paste from `reports/`)

- `reports/control_group_tests.txt` — 21 top-level PASS (18 control-group tests
  plus 3 policy-parse tests, the latter with 8 subtests), `ok ... 0.322s`.
- `reports/regression_vault.txt` — `ok github.com/hashicorp/vault/vault 118.130s`
  (policy, ACL, capability, request-handling, wrapping, token, expiration,
  audit, control-group).
- `reports/regression_http.txt` — `ok github.com/hashicorp/vault/http 87.154s`.
- `reports/full_vault_suite_summary.txt` — the entire `vault` package. Three
  failures, all container tests that require Docker
  (`"docker": executable file not found in $PATH`), and `docker` is not
  installed in this environment. These are environmental and unrelated to the
  change:
  - `TestExternalPluginInContainer_MountAndUnmount`
  - `TestSystemBackend_PluginCatalog_ContainerCRUD`
  - `TestSystemBackend_pluginRuntime_CannotDeleteRuntimeWithReferencingPlugins`

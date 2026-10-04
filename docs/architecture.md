# Architecture

```text
Corporate OIDC provider
          │ verified identity and group claims
          ▼
Employee / administrator UI
          │ session + CSRF-protected requests
          ▼
Portal service account
          ├── settings ConfigMap
          ├── encrypted value Secrets
          └── AccessToken records
                       │
                       ▼
               Lifecycle policies
                       ├── gateway hash ConfigMaps
                       ├── per-generation budgets
                       └── activity Events
                                  │
                                  ▼
                         Existing agentgateway

Kubernetes CronJob → clock ConfigMap → timed policy evaluation
```

## Resource boundary

`AccessToken` is a project-owned CRD in `accessportal.io/v1alpha1`. Records live in the portal's namespace and carry `accessportal.io/instance` and `accessportal.io/owner` labels. Ownership is a stable hash of the verified OIDC issuer and subject, not a display name or email address.

The web application authorises every operation. Its Kubernetes service account is a trusted broker with access to the installation's records. OIDC employees are not issued Kubernetes credentials. Administrators are selected by the configured verified group claim, not a local user database.

The server generates a cryptographically random value, computes its SHA-256 hash and stores an encrypted copy separately. A record contains the hash entry, permissions, deadlines, history and optional standby generation. No usable plaintext credential is written into an AccessToken or gateway ConfigMap.

## Included policies

| Suffix | Purpose |
|---|---|
| `publish` | Generate and synchronise the gateway hash ConfigMap. |
| `hashes` | Replace the accepted hash map exactly; generation merges alone do not reliably remove old map entries. |
| `expire` | Mark overdue records and their live generations expired. |
| `rotate` | Publish the prepared replacement and retain overlap. |
| `events` | Record scheduled transitions in the portal namespace. |
| `ownership` | Validate owner labels, configured namespace scope and consistent hash metadata. |
| `budgets` | Generate exact-generation Enterprise budgets. Optional. |
| `budget-settings` | Apply changed allowances to the installation's existing budgets. Optional. |

The clock patches only its own ConfigMap. Token decisions remain in CEL. Mutate-existing policies also see the trigger object during admission/reporting, so mutation expressions guard against a ConfigMap without `spec`.

Kyverno's admission and background controllers must know the AccessToken CRD. The Helm installer checks a real expiry transition to catch stale discovery or a policy which compiles but does not reconcile.

## External reconciler contract

With `policies.enabled=false`, the portal still writes AccessToken records but does not install a scheduler or a replacement controller. An external implementation must:

1. Watch records in the portal namespace with the installation's instance label.
2. Publish a ConfigMap named **exactly like the AccessToken** in `spec.gatewayNamespace`.
3. Label that ConfigMap with the same `accessportal.io/instance`, plus `accessportal.io/token-store: "true"` and `accessportal.io/token-record: <record-name>`.
4. While `spec.status` is `active`, set its data map to `{generation.id: generation.entry}` for `active` and `overlapping` generations only. For revoked or expired records the map must be empty. Removed entries must actually be removed, not merge-preserved.
5. At `expiresAt`, mark the record and live generations expired, clear standby/handover state and withdraw accepted hashes.
6. At `rotatesAt`, if still active, not expired and no handover is pending, move the prepared standby into the current generation and mark the previous one overlapping. Never complete a client handover automatically.
7. Delete generated downstream resources when the source record is deleted.
8. Reconcile budget settings and write owner-scoped activity Events if those features are provided.

The included policies are the executable reference. The portal waits for an exact matching gateway ConfigMap after mutations and reports pending reconciliation when it cannot confirm the result. There is no fallback in-process expiry worker.

## Settings ownership

The installation settings ConfigMap is seeded by a create-if-missing Helm hook. The portal updates it with resource-version conflict checks. This avoids Helm/server-side-apply fighting the application over runtime settings. `settings.resetOnUpgrade` is an explicit reset, not the default.

The policy bundle ConfigMap is Helm-owned. An isolated installer service account applies that bundle with optimistic updates, without granting policy editing to the portal service account. Installer jobs run in the Kyverno namespace so application-namespace pod creators do not inherit a cluster-policy-writing service account.

## Limits of this reference implementation

- Kubernetes Events expire; configure API-server audit export and retention separately.
- Raw values use application-layer encryption backed by a Kubernetes Secret. Use platform Secret encryption, access controls and backups, or extend the storage adapter for an external KMS/vault.
- Automatic rotation pre-generates the next value. Client rollout and handover acknowledgement remain explicit application operations.
- Controller outages can delay expiry. Hard expiry despite control-plane outages also needs request-path enforcement.
- The namespace and instance selectors prevent cross-installation reconciliation; they are not a substitute for RBAC and server-side ownership checks.

# Safeguard TLA+ Formal Specifications

This directory contains formal TLA+ specifications for verifying the correctness of the Safeguard Entra ID Incident Response Tool.

## Overview

These specifications model critical aspects of the application:

| Module | Description | Key Properties |
|--------|-------------|----------------|
| `Safeguard.tla` | Main system specification | End-to-end safety, admin protection |
| `AuthenticationService.tla` | OAuth2 authentication lifecycle | Token validity, state transitions |
| `TokenRefresh.tla` | Concurrent token refresh | Mutual exclusion, no stale reads |
| `MassOperations.tla` | Batch processing | Admin never processed, disjoint outcomes |
| `CircuitBreaker.tla` | Resilience policy | Recovery guarantees, state transitions |

## Installation

### TLA+ Toolbox (GUI)
1. Download from: https://github.com/tlaplus/tlaplus/releases
2. Open the `.tla` files in the toolbox
3. Create a new model and configure constants

### TLC Command Line
```bash
# Install TLC
brew install tla-plus  # macOS
# or download from https://github.com/tlaplus/tlaplus/releases

# Run model checking
tlc MassOperations.tla -config MassOperations.cfg
```

## Running Model Checking

### Quick Verification (< 1 minute each)
```bash
# Check admin protection invariants
tlc MassOperations.tla -config MassOperations.cfg

# Check concurrency properties
tlc TokenRefresh.tla -config TokenRefresh.cfg

# Check circuit breaker behavior
tlc CircuitBreaker.tla -config CircuitBreaker.cfg
```

### Full System Verification
```bash
tlc Safeguard.tla -config Safeguard.cfg
```

## Critical Safety Properties

### Admin Self-Protection (MassOperations.tla)
The most critical invariant ensures the current admin can never be processed during mass operations:

```tla
AdminNeverProcessed ==
    ADMIN_ID \notin processed
```

This corresponds to the C# code in `TokenRevocationService.cs:171-173`:
```csharp
var usersToRevoke = allUsers
    .Where(u => u.Id != excludeUserId)
    .ToList();
```

### Mutual Exclusion (TokenRefresh.tla)
Ensures only one thread can refresh the token at a time:

```tla
MutualExclusion ==
    \A t1, t2 \in THREADS:
        (HoldsLock(t1) /\ HoldsLock(t2)) => t1 = t2
```

This verifies the double-checked locking pattern in `RefreshingTokenCredential`.

### Circuit Breaker Recovery (CircuitBreaker.tla)
Guarantees the circuit breaker eventually allows recovery:

```tla
NotStuckOpen ==
    [](circuitState = "Open" => <>(circuitState # "Open"))
```

## Model Sizes

For practical model checking, we use small state spaces:

| Module | Users/Threads | Estimated States | Time |
|--------|---------------|------------------|------|
| MassOperations | 4 users | ~10,000 | <1 min |
| TokenRefresh | 2 threads | ~5,000 | <30 sec |
| CircuitBreaker | N/A | ~50,000 | <2 min |
| Safeguard | 3 users | ~100,000 | <5 min |

## Invariants Verified

### Safety (must NEVER be violated)
- ✅ Admin never included in mass operations
- ✅ No token used after expiry
- ✅ At most one thread refreshing token
- ✅ Succeeded/failed sets are disjoint
- ✅ No operations without authentication

### Liveness (must EVENTUALLY happen)
- ✅ Authentication eventually completes
- ✅ Token eventually refreshes
- ✅ Circuit breaker eventually closes
- ✅ All eligible users eventually processed

## Mapping to C# Code

| TLA+ Module | C# File | Key Methods |
|-------------|---------|-------------|
| AuthenticationService.tla | Services/AuthenticationService.cs | `AuthenticateInteractiveAsync`, `GetAccessTokenAsync` |
| TokenRefresh.tla | Services/AuthenticationService.cs | `RefreshingTokenCredential.GetTokenAsync` |
| MassOperations.tla | Services/TokenRevocationService.cs | `MassRevokeTokensAsync`, `MassResetMfaAsync` |
| CircuitBreaker.tla | Infrastructure/ResilientGraphOperations.cs | `BuildPipeline` |

## Extending the Specifications

To add new properties:

1. Add invariants to the relevant module
2. Update the `.cfg` file to include the new invariant
3. Run TLC to verify

Example - adding a new safety property:
```tla
\* In MassOperations.tla
NewSafetyProperty ==
    \* Your invariant here
    processed \subseteq USERS \ {ADMIN_ID}

\* In MassOperations.cfg
INVARIANT NewSafetyProperty
```

## Troubleshooting

### State Space Explosion
If TLC runs out of memory:
1. Reduce `MAX_TIME` in the config
2. Reduce the number of users/threads
3. Add tighter `CONSTRAINT` clauses

### Liveness Violations
If a liveness property fails:
1. Check fairness conditions in the spec
2. Ensure `WF_vars` or `SF_vars` is specified
3. Look for deadlock scenarios in the counterexample

## References

- [TLA+ Home](https://lamport.azurewebsites.net/tla/tla.html)
- [Learn TLA+](https://learntla.com/)
- [TLA+ Video Course](https://lamport.azurewebsites.net/video/videos.html)

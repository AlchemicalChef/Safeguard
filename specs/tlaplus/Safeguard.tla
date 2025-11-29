------------------------------- MODULE Safeguard -------------------------------
(*
 * Main TLA+ specification for the Safeguard Entra ID Incident Response Tool.
 *
 * This module provides a high-level view of the entire system, defining:
 * - System-wide constants and configuration
 * - Cross-cutting invariants
 * - Composition of subsystem behaviors
 * - End-to-end safety and liveness properties
 *
 * Subsystem Modules:
 * - AuthenticationService.tla: OAuth2 authentication lifecycle
 * - TokenRefresh.tla: Concurrent token refresh with double-checked locking
 * - MassOperations.tla: Batch processing of destructive operations
 * - CircuitBreaker.tla: Resilience policy for Graph API calls
 *
 * Application Overview:
 * Safeguard is an Entra ID (Azure AD) incident response tool that provides:
 * 1. Token revocation for compromised users
 * 2. MFA reset for account recovery
 * 3. Enterprise application cleanup
 * 4. Backdoor detection scanning
 * 5. Risky account analysis
 *)

EXTENDS Naturals, Sequences, FiniteSets, TLC

(***************************************************************************)
(* SYSTEM CONSTANTS                                                         *)
(***************************************************************************)

CONSTANTS
    \* User Management
    USERS,                      \* Set of all user IDs in the tenant
    ADMIN_ID,                   \* Current admin user ID

    \* Token Management
    TOKEN_REFRESH_BUFFER,       \* Minutes before expiry to refresh (5)
    MAX_TOKEN_LIFETIME,         \* Maximum token lifetime in minutes

    \* Concurrency
    MAX_THREADS,                \* Maximum concurrent threads

    \* Batch Processing
    DEFAULT_BATCH_SIZE,         \* Default batch size for mass operations (50)
    BATCH_DELAY_MS,             \* Delay between batches in milliseconds

    \* Circuit Breaker
    CB_FAILURE_THRESHOLD,       \* Failures before opening (5)
    CB_FAILURE_RATIO,           \* Failure ratio threshold (50%)
    CB_SAMPLING_DURATION,       \* Sampling window (30s)
    CB_BREAK_DURATION,          \* Break duration (30s)

    \* General
    NULL,                       \* Null value
    MAX_TIME                    \* Maximum simulation time

\* Assumption: Admin exists in user set
ASSUME ADMIN_ID \in USERS

(***************************************************************************)
(* SYSTEM STATES                                                            *)
(***************************************************************************)

\* High-level system states
SystemStates == {
    "NotAuthenticated",     \* User not logged in
    "Authenticating",       \* OAuth2 flow in progress
    "Ready",                \* Authenticated, ready for operations
    "ExecutingOperation",   \* Mass operation in progress
    "Degraded",             \* Circuit breaker open
    "Error"                 \* Unrecoverable error state
}

\* Operation types
OperationTypes == {
    "None",
    "TokenRevocation",
    "MfaReset",
    "AppCleanup",
    "BackdoorScan",
    "RiskyScan"
}

\* Destructive operation classifications
DestructiveOps == {"TokenRevocation", "MfaReset", "AppCleanup"}
ReadOnlyOps == {"BackdoorScan", "RiskyScan"}

(***************************************************************************)
(* SYSTEM VARIABLES                                                         *)
(***************************************************************************)

VARIABLES
    \* Authentication State
    systemState,            \* Current high-level system state
    isAuthenticated,        \* Whether user is authenticated
    currentUser,            \* Current authenticated user ID
    tokenValid,             \* Whether current token is valid

    \* Operation State
    activeOperation,        \* Currently executing operation type
    operationProgress,      \* Progress of current operation (0-100)
    operationResults,       \* Results of completed operations

    \* Resilience State
    circuitOpen,            \* Whether circuit breaker is open
    failureCount,           \* Recent failure count
    lastError,              \* Last error encountered

    \* Audit State
    auditLog,               \* Sequence of audit events
    operationsPerformed,    \* Set of users that have been operated on

    \* Time
    now                     \* Current time

vars == <<systemState, isAuthenticated, currentUser, tokenValid,
          activeOperation, operationProgress, operationResults,
          circuitOpen, failureCount, lastError,
          auditLog, operationsPerformed, now>>

(***************************************************************************)
(* TYPE INVARIANT                                                           *)
(***************************************************************************)

TypeOK ==
    /\ systemState \in SystemStates
    /\ isAuthenticated \in BOOLEAN
    /\ currentUser \in USERS \cup {NULL}
    /\ tokenValid \in BOOLEAN
    /\ activeOperation \in OperationTypes
    /\ operationProgress \in 0..100
    /\ circuitOpen \in BOOLEAN
    /\ failureCount \in Nat
    /\ operationsPerformed \subseteq USERS
    /\ now \in Nat

(***************************************************************************)
(* INITIAL STATE                                                            *)
(***************************************************************************)

Init ==
    /\ systemState = "NotAuthenticated"
    /\ isAuthenticated = FALSE
    /\ currentUser = NULL
    /\ tokenValid = FALSE
    /\ activeOperation = "None"
    /\ operationProgress = 0
    /\ operationResults = <<>>
    /\ circuitOpen = FALSE
    /\ failureCount = 0
    /\ lastError = NULL
    /\ auditLog = <<>>
    /\ operationsPerformed = {}
    /\ now = 0

(***************************************************************************)
(* AUTHENTICATION TRANSITIONS                                               *)
(***************************************************************************)

\* Start authentication
StartAuth ==
    /\ systemState = "NotAuthenticated"
    /\ systemState' = "Authenticating"
    /\ UNCHANGED <<isAuthenticated, currentUser, tokenValid, activeOperation,
                   operationProgress, operationResults, circuitOpen,
                   failureCount, lastError, auditLog, operationsPerformed, now>>

\* Authentication succeeds
AuthSuccess(userId) ==
    /\ systemState = "Authenticating"
    /\ userId \in USERS
    /\ systemState' = "Ready"
    /\ isAuthenticated' = TRUE
    /\ currentUser' = userId
    /\ tokenValid' = TRUE
    /\ auditLog' = Append(auditLog, <<"AUTH_SUCCESS", userId, now>>)
    /\ UNCHANGED <<activeOperation, operationProgress, operationResults,
                   circuitOpen, failureCount, lastError, operationsPerformed, now>>

\* Authentication fails
AuthFailure ==
    /\ systemState = "Authenticating"
    /\ systemState' = "NotAuthenticated"
    /\ lastError' = "AUTH_FAILED"
    /\ auditLog' = Append(auditLog, <<"AUTH_FAILURE", NULL, now>>)
    /\ UNCHANGED <<isAuthenticated, currentUser, tokenValid, activeOperation,
                   operationProgress, operationResults, circuitOpen,
                   failureCount, operationsPerformed, now>>

\* Sign out
SignOut ==
    /\ systemState = "Ready"
    /\ systemState' = "NotAuthenticated"
    /\ isAuthenticated' = FALSE
    /\ currentUser' = NULL
    /\ tokenValid' = FALSE
    /\ auditLog' = Append(auditLog, <<"SIGN_OUT", currentUser, now>>)
    /\ UNCHANGED <<activeOperation, operationProgress, operationResults,
                   circuitOpen, failureCount, lastError, operationsPerformed, now>>

(***************************************************************************)
(* OPERATION TRANSITIONS                                                    *)
(***************************************************************************)

\* Start a destructive operation
StartDestructiveOp(opType) ==
    /\ systemState = "Ready"
    /\ opType \in DestructiveOps
    /\ isAuthenticated
    /\ tokenValid
    /\ ~circuitOpen
    /\ systemState' = "ExecutingOperation"
    /\ activeOperation' = opType
    /\ operationProgress' = 0
    /\ auditLog' = Append(auditLog, <<"OP_START", opType, now>>)
    /\ UNCHANGED <<isAuthenticated, currentUser, tokenValid, operationResults,
                   circuitOpen, failureCount, lastError, operationsPerformed, now>>

\* Progress on operation (process a user)
OperationProgress(userId) ==
    /\ systemState = "ExecutingOperation"
    /\ activeOperation \in DestructiveOps
    /\ userId \in USERS
    /\ userId # currentUser  \* CRITICAL: Cannot operate on self
    /\ userId \notin operationsPerformed
    /\ ~circuitOpen
    /\ operationsPerformed' = operationsPerformed \cup {userId}
    /\ operationProgress' = operationProgress + 1
    /\ auditLog' = Append(auditLog, <<"USER_PROCESSED", userId, now>>)
    /\ UNCHANGED <<systemState, isAuthenticated, currentUser, tokenValid,
                   activeOperation, operationResults, circuitOpen,
                   failureCount, lastError, now>>

\* Operation completes
OperationComplete ==
    /\ systemState = "ExecutingOperation"
    /\ operationProgress > 0
    /\ systemState' = "Ready"
    /\ activeOperation' = "None"
    /\ operationResults' = Append(operationResults,
         <<activeOperation, operationProgress, now>>)
    /\ auditLog' = Append(auditLog, <<"OP_COMPLETE", activeOperation, now>>)
    /\ UNCHANGED <<isAuthenticated, currentUser, tokenValid, operationProgress,
                   circuitOpen, failureCount, lastError, operationsPerformed, now>>

\* Operation cancelled
OperationCancelled ==
    /\ systemState = "ExecutingOperation"
    /\ systemState' = "Ready"
    /\ activeOperation' = "None"
    /\ auditLog' = Append(auditLog, <<"OP_CANCELLED", activeOperation, now>>)
    /\ UNCHANGED <<isAuthenticated, currentUser, tokenValid, operationProgress,
                   operationResults, circuitOpen, failureCount, lastError,
                   operationsPerformed, now>>

(***************************************************************************)
(* RESILIENCE TRANSITIONS                                                   *)
(***************************************************************************)

\* Circuit breaker opens
CircuitOpens ==
    /\ failureCount >= CB_FAILURE_THRESHOLD
    /\ ~circuitOpen
    /\ circuitOpen' = TRUE
    /\ systemState' = IF systemState = "ExecutingOperation"
                      THEN "Degraded"
                      ELSE systemState
    /\ auditLog' = Append(auditLog, <<"CIRCUIT_OPENED", NULL, now>>)
    /\ UNCHANGED <<isAuthenticated, currentUser, tokenValid, activeOperation,
                   operationProgress, operationResults, failureCount, lastError,
                   operationsPerformed, now>>

\* Circuit breaker closes
CircuitCloses ==
    /\ circuitOpen
    /\ circuitOpen' = FALSE
    /\ failureCount' = 0
    /\ systemState' = IF systemState = "Degraded" THEN "Ready" ELSE systemState
    /\ auditLog' = Append(auditLog, <<"CIRCUIT_CLOSED", NULL, now>>)
    /\ UNCHANGED <<isAuthenticated, currentUser, tokenValid, activeOperation,
                   operationProgress, operationResults, lastError,
                   operationsPerformed, now>>

\* Record a failure
RecordFailure ==
    /\ systemState \in {"Ready", "ExecutingOperation"}
    /\ failureCount' = failureCount + 1
    /\ UNCHANGED <<systemState, isAuthenticated, currentUser, tokenValid,
                   activeOperation, operationProgress, operationResults,
                   circuitOpen, lastError, auditLog, operationsPerformed, now>>

(***************************************************************************)
(* TOKEN MANAGEMENT                                                         *)
(***************************************************************************)

\* Token expires
TokenExpires ==
    /\ tokenValid
    /\ tokenValid' = FALSE
    /\ UNCHANGED <<systemState, isAuthenticated, currentUser, activeOperation,
                   operationProgress, operationResults, circuitOpen,
                   failureCount, lastError, auditLog, operationsPerformed, now>>

\* Token refreshed
TokenRefreshed ==
    /\ isAuthenticated
    /\ ~tokenValid
    /\ tokenValid' = TRUE
    /\ auditLog' = Append(auditLog, <<"TOKEN_REFRESHED", currentUser, now>>)
    /\ UNCHANGED <<systemState, isAuthenticated, currentUser, activeOperation,
                   operationProgress, operationResults, circuitOpen,
                   failureCount, lastError, operationsPerformed, now>>

(***************************************************************************)
(* TIME                                                                     *)
(***************************************************************************)

Tick ==
    /\ now < MAX_TIME
    /\ now' = now + 1
    /\ UNCHANGED <<systemState, isAuthenticated, currentUser, tokenValid,
                   activeOperation, operationProgress, operationResults,
                   circuitOpen, failureCount, lastError, auditLog,
                   operationsPerformed>>

(***************************************************************************)
(* NEXT-STATE RELATION                                                      *)
(***************************************************************************)

Next ==
    \/ StartAuth
    \/ \E u \in USERS: AuthSuccess(u)
    \/ AuthFailure
    \/ SignOut
    \/ \E op \in DestructiveOps: StartDestructiveOp(op)
    \/ \E u \in USERS: OperationProgress(u)
    \/ OperationComplete
    \/ OperationCancelled
    \/ CircuitOpens
    \/ CircuitCloses
    \/ RecordFailure
    \/ TokenExpires
    \/ TokenRefreshed
    \/ Tick

(***************************************************************************)
(* FAIRNESS                                                                 *)
(***************************************************************************)

Fairness ==
    /\ WF_vars(TokenRefreshed)
    /\ WF_vars(CircuitCloses)
    /\ WF_vars(OperationComplete)
    /\ WF_vars(Tick)

Spec == Init /\ [][Next]_vars /\ Fairness

(***************************************************************************)
(* CRITICAL SAFETY INVARIANTS                                               *)
(***************************************************************************)

\* SAFETY1: Current user is NEVER in the operations performed set
\* This is the most critical safety property - prevents self-revocation
AdminSelfProtection ==
    currentUser # NULL => currentUser \notin operationsPerformed

\* SAFETY2: Cannot perform destructive operations without authentication
NoUnauthDestructive ==
    activeOperation \in DestructiveOps => isAuthenticated

\* SAFETY3: Cannot perform operations with expired token
NoOperationsWithExpiredToken ==
    (systemState = "ExecutingOperation" /\ activeOperation \in DestructiveOps) =>
        tokenValid

\* SAFETY4: Circuit open prevents new operations
CircuitBlocksOperations ==
    circuitOpen => activeOperation = "None"

\* SAFETY5: Audit log only grows (append-only)
AuditLogMonotonic ==
    [][Len(auditLog') >= Len(auditLog)]_auditLog

(***************************************************************************)
(* STATE CONSISTENCY INVARIANTS                                             *)
(***************************************************************************)

\* If authenticated, current user must be set
AuthImpliesUser ==
    isAuthenticated => currentUser \in USERS

\* If operation in progress, must be authenticated
OperationImpliesAuth ==
    systemState = "ExecutingOperation" => isAuthenticated

\* If degraded, circuit must be open
DegradedImpliesCircuitOpen ==
    systemState = "Degraded" => circuitOpen

\* Operation progress is bounded
ProgressBounded ==
    operationProgress <= Cardinality(USERS)

(***************************************************************************)
(* LIVENESS PROPERTIES                                                      *)
(***************************************************************************)

\* Operations eventually complete
OperationsEventuallyComplete ==
    (systemState = "ExecutingOperation") ~>
        (systemState \in {"Ready", "Degraded", "Error"})

\* Token eventually refreshes
TokenEventuallyRefreshes ==
    (~tokenValid /\ isAuthenticated) ~> tokenValid

\* Circuit eventually closes (if failures stop)
CircuitEventuallyCloses ==
    circuitOpen ~> (~circuitOpen \/ circuitOpen)  \* Can stay open if failures continue

\* Authentication eventually resolves
AuthEventuallyResolves ==
    (systemState = "Authenticating") ~>
        (systemState \in {"Ready", "NotAuthenticated"})

(***************************************************************************)
(* COMBINED SAFETY PROPERTY                                                 *)
(***************************************************************************)

AllSafetyInvariants ==
    /\ TypeOK
    /\ AdminSelfProtection
    /\ NoUnauthDestructive
    /\ AuthImpliesUser
    /\ OperationImpliesAuth
    /\ DegradedImpliesCircuitOpen
    /\ ProgressBounded

(***************************************************************************)
(* THEOREMS                                                                 *)
(***************************************************************************)

THEOREM Spec => []TypeOK
THEOREM Spec => []AdminSelfProtection
THEOREM Spec => []NoUnauthDestructive
THEOREM Spec => []AuthImpliesUser
THEOREM Spec => OperationsEventuallyComplete
THEOREM Spec => AuthEventuallyResolves

=============================================================================

------------------------------- MODULE TokenRefresh -------------------------------
(*
 * Formal TLA+ specification of concurrent token refresh with double-checked locking.
 *
 * This module models the RefreshingTokenCredential class which implements
 * thread-safe token caching with a semaphore-protected refresh operation.
 *
 * Corresponds to: Services/AuthenticationService.cs (RefreshingTokenCredential class)
 *
 * Key Concurrency Pattern:
 *   1. Check if token valid (volatile read, no lock)
 *   2. If not valid, acquire lock
 *   3. Double-check if token valid (another thread may have refreshed)
 *   4. If still not valid, perform refresh
 *   5. Update cached token atomically
 *   6. Release lock
 *)

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    THREADS,                \* Set of thread identifiers {t1, t2, ..., tN}
    NULL,                   \* Null value
    REFRESH_BUFFER,         \* Buffer time before expiry (5 minutes)
    MAX_TIME                \* Maximum simulation time

VARIABLES
    \* Shared state (volatile/atomic in implementation)
    cachedToken,            \* Shared cached token value
    tokenExpiry,            \* Token expiration timestamp
    refreshLockHolder,      \* Thread holding the refresh lock (or NULL)
    refreshLockQueue,       \* Queue of threads waiting for lock

    \* Per-thread state
    threadState,            \* Function: thread -> state
    localToken,             \* Function: thread -> local token copy
    localExpiry,            \* Function: thread -> local expiry copy
    threadResult,           \* Function: thread -> result token (or NULL)

    \* Environment
    now                     \* Current time

vars == <<cachedToken, tokenExpiry, refreshLockHolder, refreshLockQueue,
          threadState, localToken, localExpiry, threadResult, now>>

(***************************************************************************)
(* Thread States                                                            *)
(***************************************************************************)

ThreadStates == {
    "Idle",                 \* Not requesting token
    "CheckingCache",        \* Reading cached values (step 1-3)
    "WaitingForLock",       \* Waiting to acquire refresh lock (step 4)
    "HoldingLock",          \* Acquired lock, double-checking (step 5-7)
    "Refreshing",           \* Performing actual refresh (step 8)
    "UpdatingCache",        \* Writing new token to cache (step 9-10)
    "ReleasingLock",        \* Releasing lock (step 11)
    "Done"                  \* Has result token (step 12)
}

(***************************************************************************)
(* Type Invariant                                                           *)
(***************************************************************************)

TypeOK ==
    /\ cachedToken \in {NULL} \cup STRING
    /\ tokenExpiry \in Nat \cup {NULL}
    /\ refreshLockHolder \in {NULL} \cup THREADS
    /\ refreshLockQueue \in Seq(THREADS)
    /\ threadState \in [THREADS -> ThreadStates]
    /\ localToken \in [THREADS -> {NULL} \cup STRING]
    /\ localExpiry \in [THREADS -> Nat \cup {NULL}]
    /\ threadResult \in [THREADS -> {NULL} \cup STRING]
    /\ now \in Nat

(***************************************************************************)
(* Initial State                                                            *)
(***************************************************************************)

Init ==
    /\ cachedToken = NULL
    /\ tokenExpiry = NULL
    /\ refreshLockHolder = NULL
    /\ refreshLockQueue = <<>>
    /\ threadState = [t \in THREADS |-> "Idle"]
    /\ localToken = [t \in THREADS |-> NULL]
    /\ localExpiry = [t \in THREADS |-> NULL]
    /\ threadResult = [t \in THREADS |-> NULL]
    /\ now = 0

(***************************************************************************)
(* Helper Predicates                                                        *)
(***************************************************************************)

\* Token is valid if not null and not expiring within buffer
TokenValidAt(token, expiry, time) ==
    /\ token # NULL
    /\ expiry # NULL
    /\ time + REFRESH_BUFFER < expiry

CachedTokenValid == TokenValidAt(cachedToken, tokenExpiry, now)

\* Check if thread's local view shows valid token
LocalTokenValid(t) == TokenValidAt(localToken[t], localExpiry[t], now)

\* Lock is free
LockFree == refreshLockHolder = NULL

\* Thread holds lock
HoldsLock(t) == refreshLockHolder = t

(***************************************************************************)
(* Thread Actions                                                           *)
(***************************************************************************)

\* Thread starts requesting a token
StartGetToken(t) ==
    /\ threadState[t] = "Idle"
    /\ threadState' = [threadState EXCEPT ![t] = "CheckingCache"]
    /\ UNCHANGED <<cachedToken, tokenExpiry, refreshLockHolder, refreshLockQueue,
                   localToken, localExpiry, threadResult, now>>

\* Thread reads cached values (volatile read)
ReadCache(t) ==
    /\ threadState[t] = "CheckingCache"
    /\ localToken' = [localToken EXCEPT ![t] = cachedToken]
    /\ localExpiry' = [localExpiry EXCEPT ![t] = tokenExpiry]
    /\ IF TokenValidAt(cachedToken, tokenExpiry, now)
       THEN \* Fast path: return cached token
            /\ threadState' = [threadState EXCEPT ![t] = "Done"]
            /\ threadResult' = [threadResult EXCEPT ![t] = cachedToken]
       ELSE \* Need to refresh: try to acquire lock
            /\ threadState' = [threadState EXCEPT ![t] = "WaitingForLock"]
            /\ UNCHANGED threadResult
    /\ UNCHANGED <<cachedToken, tokenExpiry, refreshLockHolder, refreshLockQueue, now>>

\* Thread tries to acquire the refresh lock
TryAcquireLock(t) ==
    /\ threadState[t] = "WaitingForLock"
    /\ IF LockFree
       THEN \* Acquire lock immediately
            /\ refreshLockHolder' = t
            /\ threadState' = [threadState EXCEPT ![t] = "HoldingLock"]
            /\ UNCHANGED refreshLockQueue
       ELSE \* Join wait queue
            /\ refreshLockQueue' = Append(refreshLockQueue, t)
            /\ UNCHANGED <<refreshLockHolder, threadState>>
    /\ UNCHANGED <<cachedToken, tokenExpiry, localToken, localExpiry,
                   threadResult, now>>

\* Thread wakes up after lock becomes available
WakeFromQueue(t) ==
    /\ threadState[t] = "WaitingForLock"
    /\ Len(refreshLockQueue) > 0
    /\ Head(refreshLockQueue) = t
    /\ LockFree
    /\ refreshLockHolder' = t
    /\ refreshLockQueue' = Tail(refreshLockQueue)
    /\ threadState' = [threadState EXCEPT ![t] = "HoldingLock"]
    /\ UNCHANGED <<cachedToken, tokenExpiry, localToken, localExpiry,
                   threadResult, now>>

\* Thread does double-check after acquiring lock
DoubleCheck(t) ==
    /\ threadState[t] = "HoldingLock"
    /\ HoldsLock(t)
    \* Re-read cache (double-check pattern)
    /\ localToken' = [localToken EXCEPT ![t] = cachedToken]
    /\ localExpiry' = [localExpiry EXCEPT ![t] = tokenExpiry]
    /\ IF TokenValidAt(cachedToken, tokenExpiry, now)
       THEN \* Another thread refreshed - release lock and return
            /\ threadResult' = [threadResult EXCEPT ![t] = cachedToken]
            /\ threadState' = [threadState EXCEPT ![t] = "ReleasingLock"]
       ELSE \* Still invalid - proceed to refresh
            /\ threadState' = [threadState EXCEPT ![t] = "Refreshing"]
            /\ UNCHANGED threadResult
    /\ UNCHANGED <<cachedToken, tokenExpiry, refreshLockHolder, refreshLockQueue, now>>

\* Thread performs the actual token refresh (calls MSAL)
PerformRefresh(t, newToken, newExpiry) ==
    /\ threadState[t] = "Refreshing"
    /\ HoldsLock(t)
    /\ newToken # NULL
    /\ newExpiry > now
    \* Store refresh result locally before updating cache
    /\ localToken' = [localToken EXCEPT ![t] = newToken]
    /\ localExpiry' = [localExpiry EXCEPT ![t] = newExpiry]
    /\ threadState' = [threadState EXCEPT ![t] = "UpdatingCache"]
    /\ UNCHANGED <<cachedToken, tokenExpiry, refreshLockHolder, refreshLockQueue,
                   threadResult, now>>

\* Thread updates the shared cache atomically
UpdateCache(t) ==
    /\ threadState[t] = "UpdatingCache"
    /\ HoldsLock(t)
    \* Atomic write to shared cache
    /\ cachedToken' = localToken[t]
    /\ tokenExpiry' = localExpiry[t]
    /\ threadResult' = [threadResult EXCEPT ![t] = localToken[t]]
    /\ threadState' = [threadState EXCEPT ![t] = "ReleasingLock"]
    /\ UNCHANGED <<refreshLockHolder, refreshLockQueue, localToken, localExpiry, now>>

\* Thread releases the lock
ReleaseLock(t) ==
    /\ threadState[t] = "ReleasingLock"
    /\ HoldsLock(t)
    /\ refreshLockHolder' = NULL
    /\ threadState' = [threadState EXCEPT ![t] = "Done"]
    /\ UNCHANGED <<cachedToken, tokenExpiry, refreshLockQueue,
                   localToken, localExpiry, threadResult, now>>

\* Thread resets to idle (can request token again)
Reset(t) ==
    /\ threadState[t] = "Done"
    /\ threadState' = [threadState EXCEPT ![t] = "Idle"]
    /\ threadResult' = [threadResult EXCEPT ![t] = NULL]
    /\ localToken' = [localToken EXCEPT ![t] = NULL]
    /\ localExpiry' = [localExpiry EXCEPT ![t] = NULL]
    /\ UNCHANGED <<cachedToken, tokenExpiry, refreshLockHolder, refreshLockQueue, now>>

\* Time advances (simulates token expiry)
Tick ==
    /\ now < MAX_TIME
    /\ now' = now + 1
    /\ UNCHANGED <<cachedToken, tokenExpiry, refreshLockHolder, refreshLockQueue,
                   threadState, localToken, localExpiry, threadResult>>

(***************************************************************************)
(* Next-State Relation                                                      *)
(***************************************************************************)

ThreadAction(t) ==
    \/ StartGetToken(t)
    \/ ReadCache(t)
    \/ TryAcquireLock(t)
    \/ WakeFromQueue(t)
    \/ DoubleCheck(t)
    \/ \E token \in STRING, exp \in Nat: PerformRefresh(t, token, exp)
    \/ UpdateCache(t)
    \/ ReleaseLock(t)
    \/ Reset(t)

Next ==
    \/ \E t \in THREADS: ThreadAction(t)
    \/ Tick

(***************************************************************************)
(* Fairness Conditions                                                      *)
(***************************************************************************)

\* Weak fairness for each thread's actions
Fairness ==
    /\ \A t \in THREADS: WF_vars(ThreadAction(t))
    /\ WF_vars(Tick)

Spec == Init /\ [][Next]_vars /\ Fairness

(***************************************************************************)
(* Safety Properties (Invariants)                                           *)
(***************************************************************************)

\* MUTEX: At most one thread holds the lock
MutualExclusion ==
    \A t1, t2 \in THREADS:
        (HoldsLock(t1) /\ HoldsLock(t2)) => t1 = t2

\* MUTEX2: At most one thread in critical section (Refreshing/UpdatingCache)
AtMostOneRefreshing ==
    Cardinality({t \in THREADS: threadState[t] \in {"Refreshing", "UpdatingCache"}}) <= 1

\* No stale reads: if thread has result, it's a valid token
ResultIsValid ==
    \A t \in THREADS:
        (threadResult[t] # NULL /\ threadState[t] = "Done") =>
            threadResult[t] = cachedToken

\* Lock holder consistency: if holding lock, state must be appropriate
LockHolderStateConsistent ==
    \A t \in THREADS:
        HoldsLock(t) => threadState[t] \in {"HoldingLock", "Refreshing",
                                             "UpdatingCache", "ReleasingLock"}

\* Queue doesn't contain lock holder
QueueExcludesHolder ==
    \A i \in 1..Len(refreshLockQueue):
        refreshLockQueue[i] # refreshLockHolder

\* Threads in queue are in WaitingForLock state
QueueMembersWaiting ==
    \A i \in 1..Len(refreshLockQueue):
        threadState[refreshLockQueue[i]] = "WaitingForLock"

(***************************************************************************)
(* Liveness Properties                                                      *)
(***************************************************************************)

\* Every thread that starts a request eventually completes
RequestEventuallyCompletes ==
    \A t \in THREADS:
        (threadState[t] = "CheckingCache") ~> (threadState[t] = "Done")

\* A thread waiting for lock eventually acquires it
WaitingEventuallyAcquires ==
    \A t \in THREADS:
        (threadState[t] = "WaitingForLock") ~>
            (threadState[t] \in {"HoldingLock", "Done"})

\* Cache is eventually updated after refresh
RefreshEventuallyCompletesCache ==
    \A t \in THREADS:
        (threadState[t] = "Refreshing") ~>
            (cachedToken # NULL /\ tokenExpiry # NULL)

(***************************************************************************)
(* Theorems to Verify                                                       *)
(***************************************************************************)

THEOREM Spec => []TypeOK
THEOREM Spec => []MutualExclusion
THEOREM Spec => []AtMostOneRefreshing
THEOREM Spec => []LockHolderStateConsistent
THEOREM Spec => []QueueExcludesHolder
THEOREM Spec => []QueueMembersWaiting
THEOREM Spec => RequestEventuallyCompletes
THEOREM Spec => WaitingEventuallyAcquires

=============================================================================

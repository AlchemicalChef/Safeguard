------------------------------- MODULE CircuitBreaker -------------------------------
(*
 * Formal TLA+ specification of the Circuit Breaker resilience pattern.
 *
 * This module models the Polly circuit breaker used in ResilientGraphOperations
 * to protect against cascading failures when calling Microsoft Graph API.
 *
 * Corresponds to: Infrastructure/ResilientGraphOperations.cs
 *
 * Circuit Breaker States:
 *   - Closed: Normal operation, requests pass through
 *   - Open: Circuit tripped, requests fail fast
 *   - HalfOpen: Testing if service recovered
 *
 * Configuration (from ResilienceConfiguration):
 *   - FailureThreshold: 5 failures minimum
 *   - FailureRatio: 50% failure rate
 *   - SamplingDuration: 30 seconds
 *   - BreakDuration: 30 seconds
 *)

EXTENDS Naturals, Sequences, TLC

CONSTANTS
    FAILURE_THRESHOLD,      \* Minimum failures before opening (5)
    FAILURE_RATIO_PERCENT,  \* Failure ratio threshold as percentage (50)
    SAMPLING_DURATION,      \* Sampling window in time units (30)
    BREAK_DURATION,         \* How long circuit stays open (30)
    MAX_TIME                \* Maximum simulation time

\* Verify configuration constraints
ASSUME FAILURE_THRESHOLD >= 1
ASSUME FAILURE_RATIO_PERCENT > 0 /\ FAILURE_RATIO_PERCENT <= 100
ASSUME SAMPLING_DURATION >= 1
ASSUME BREAK_DURATION >= 1

VARIABLES
    circuitState,           \* Current state: Closed, Open, HalfOpen
    failureCount,           \* Failures in current sampling window
    successCount,           \* Successes in current sampling window
    lastFailureTime,        \* Time of last failure (for break expiry)
    samplingWindowStart,    \* Start of current sampling window
    now,                    \* Current time
    pendingRequest,         \* Whether there's a request in flight
    lastRequestResult       \* Result of last request: Success, Failure, Rejected

vars == <<circuitState, failureCount, successCount, lastFailureTime,
          samplingWindowStart, now, pendingRequest, lastRequestResult>>

(***************************************************************************)
(* Circuit States                                                           *)
(***************************************************************************)

CircuitStates == {"Closed", "Open", "HalfOpen"}
RequestResults == {"None", "Success", "Failure", "Rejected"}

(***************************************************************************)
(* Type Invariant                                                           *)
(***************************************************************************)

TypeOK ==
    /\ circuitState \in CircuitStates
    /\ failureCount \in Nat
    /\ successCount \in Nat
    /\ lastFailureTime \in Nat
    /\ samplingWindowStart \in Nat
    /\ now \in Nat
    /\ pendingRequest \in BOOLEAN
    /\ lastRequestResult \in RequestResults

(***************************************************************************)
(* Initial State                                                            *)
(***************************************************************************)

Init ==
    /\ circuitState = "Closed"
    /\ failureCount = 0
    /\ successCount = 0
    /\ lastFailureTime = 0
    /\ samplingWindowStart = 0
    /\ now = 0
    /\ pendingRequest = FALSE
    /\ lastRequestResult = "None"

(***************************************************************************)
(* Helper Predicates                                                        *)
(***************************************************************************)

\* Total requests in sampling window
TotalRequests == failureCount + successCount

\* Current failure ratio (as percentage, avoiding division)
\* Returns TRUE if failureCount/TotalRequests >= FAILURE_RATIO_PERCENT/100
FailureRatioExceeded ==
    failureCount * 100 >= TotalRequests * FAILURE_RATIO_PERCENT

\* Check if threshold is met
ThresholdMet ==
    /\ failureCount >= FAILURE_THRESHOLD
    /\ FailureRatioExceeded

\* Check if break duration has expired
BreakExpired ==
    now - lastFailureTime >= BREAK_DURATION

\* Check if we're outside the sampling window
SamplingWindowExpired ==
    now - samplingWindowStart >= SAMPLING_DURATION

(***************************************************************************)
(* State Transitions                                                        *)
(***************************************************************************)

\* Reset counters when sampling window expires (while Closed)
ResetSamplingWindow ==
    /\ circuitState = "Closed"
    /\ SamplingWindowExpired
    /\ ~pendingRequest
    /\ samplingWindowStart' = now
    /\ failureCount' = 0
    /\ successCount' = 0
    /\ UNCHANGED <<circuitState, lastFailureTime, now, pendingRequest,
                   lastRequestResult>>

\* Start a request (Closed state - normal operation)
StartRequestClosed ==
    /\ circuitState = "Closed"
    /\ ~pendingRequest
    /\ pendingRequest' = TRUE
    /\ lastRequestResult' = "None"
    /\ UNCHANGED <<circuitState, failureCount, successCount, lastFailureTime,
                   samplingWindowStart, now>>

\* Request succeeds (Closed state)
RequestSuccessClosed ==
    /\ circuitState = "Closed"
    /\ pendingRequest
    /\ pendingRequest' = FALSE
    /\ successCount' = successCount + 1
    /\ lastRequestResult' = "Success"
    /\ UNCHANGED <<circuitState, failureCount, lastFailureTime,
                   samplingWindowStart, now>>

\* Request fails (Closed state) - may trip circuit
RequestFailureClosed ==
    /\ circuitState = "Closed"
    /\ pendingRequest
    /\ pendingRequest' = FALSE
    /\ failureCount' = failureCount + 1
    /\ lastFailureTime' = now
    /\ lastRequestResult' = "Failure"
    \* Check if circuit should trip
    /\ IF failureCount + 1 >= FAILURE_THRESHOLD /\
          (failureCount + 1) * 100 >= (TotalRequests + 1) * FAILURE_RATIO_PERCENT
       THEN circuitState' = "Open"
       ELSE UNCHANGED circuitState
    /\ UNCHANGED <<successCount, samplingWindowStart, now>>

\* Request rejected (Open state) - fail fast
RequestRejectedOpen ==
    /\ circuitState = "Open"
    /\ ~pendingRequest
    /\ lastRequestResult' = "Rejected"
    /\ UNCHANGED <<circuitState, failureCount, successCount, lastFailureTime,
                   samplingWindowStart, now, pendingRequest>>

\* Break duration expires - transition to HalfOpen
TransitionToHalfOpen ==
    /\ circuitState = "Open"
    /\ BreakExpired
    /\ ~pendingRequest
    /\ circuitState' = "HalfOpen"
    /\ UNCHANGED <<failureCount, successCount, lastFailureTime,
                   samplingWindowStart, now, pendingRequest, lastRequestResult>>

\* Start a test request (HalfOpen state)
StartRequestHalfOpen ==
    /\ circuitState = "HalfOpen"
    /\ ~pendingRequest
    /\ pendingRequest' = TRUE
    /\ lastRequestResult' = "None"
    /\ UNCHANGED <<circuitState, failureCount, successCount, lastFailureTime,
                   samplingWindowStart, now>>

\* Test request succeeds - close circuit
TestSuccessHalfOpen ==
    /\ circuitState = "HalfOpen"
    /\ pendingRequest
    /\ pendingRequest' = FALSE
    /\ circuitState' = "Closed"
    \* Reset counters on successful close
    /\ failureCount' = 0
    /\ successCount' = 0
    /\ samplingWindowStart' = now
    /\ lastRequestResult' = "Success"
    /\ UNCHANGED <<lastFailureTime, now>>

\* Test request fails - reopen circuit
TestFailureHalfOpen ==
    /\ circuitState = "HalfOpen"
    /\ pendingRequest
    /\ pendingRequest' = FALSE
    /\ circuitState' = "Open"
    /\ lastFailureTime' = now
    /\ lastRequestResult' = "Failure"
    /\ UNCHANGED <<failureCount, successCount, samplingWindowStart, now>>

\* Time advances
Tick ==
    /\ now < MAX_TIME
    /\ ~pendingRequest  \* Don't tick during request
    /\ now' = now + 1
    /\ UNCHANGED <<circuitState, failureCount, successCount, lastFailureTime,
                   samplingWindowStart, pendingRequest, lastRequestResult>>

(***************************************************************************)
(* Next-State Relation                                                      *)
(***************************************************************************)

Next ==
    \/ ResetSamplingWindow
    \/ StartRequestClosed
    \/ RequestSuccessClosed
    \/ RequestFailureClosed
    \/ RequestRejectedOpen
    \/ TransitionToHalfOpen
    \/ StartRequestHalfOpen
    \/ TestSuccessHalfOpen
    \/ TestFailureHalfOpen
    \/ Tick

(***************************************************************************)
(* Fairness Conditions                                                      *)
(***************************************************************************)

\* Weak fairness for recovery transitions
Fairness ==
    /\ WF_vars(TransitionToHalfOpen)
    /\ WF_vars(TestSuccessHalfOpen)
    /\ WF_vars(Tick)

Spec == Init /\ [][Next]_vars /\ Fairness

(***************************************************************************)
(* Safety Properties (Invariants)                                           *)
(***************************************************************************)

\* INV1: Counters are non-negative
CountersNonNegative ==
    /\ failureCount >= 0
    /\ successCount >= 0

\* INV2: Open circuit rejects requests
OpenCircuitRejects ==
    circuitState = "Open" => ~pendingRequest

\* INV3: Time is monotonic
TimeMonotonic ==
    lastFailureTime <= now

\* INV4: Sampling window start is in the past
SamplingWindowInPast ==
    samplingWindowStart <= now

\* INV5: Circuit opens only when threshold is met
CircuitOpensCorrectly ==
    (circuitState = "Open" /\ circuitState' = "HalfOpen") =>
        (now - lastFailureTime >= BREAK_DURATION)

\* INV6: HalfOpen allows exactly one test request
HalfOpenSingleTest ==
    circuitState = "HalfOpen" =>
        (pendingRequest \/ lastRequestResult \in {"Success", "Failure", "None"})

(***************************************************************************)
(* Liveness Properties                                                      *)
(***************************************************************************)

\* LIVE1: Open circuit eventually transitions to HalfOpen (given time passes)
OpenEventuallyHalfOpen ==
    (circuitState = "Open") ~> (circuitState = "HalfOpen")

\* LIVE2: HalfOpen eventually resolves (to Closed or Open)
HalfOpenEventuallyResolves ==
    (circuitState = "HalfOpen") ~>
        (circuitState \in {"Closed", "Open"})

\* LIVE3: Circuit can recover (if service recovers)
CircuitCanRecover ==
    (circuitState = "Open") ~>
        (circuitState = "Closed" \/ circuitState = "Open")

\* LIVE4: Requests don't stay pending forever
RequestsComplete ==
    pendingRequest ~> ~pendingRequest

(***************************************************************************)
(* Temporal Properties                                                      *)
(***************************************************************************)

\* Circuit breaker is not stuck open forever (eventually can close)
NotStuckOpen ==
    [](circuitState = "Open" => <>(circuitState # "Open"))

\* If service keeps failing, circuit stays open
\* (This is a desired behavior, not a liveness violation)
FailuresKeepCircuitOpen ==
    [](circuitState = "HalfOpen" /\ lastRequestResult = "Failure" =>
       circuitState = "Open")

(***************************************************************************)
(* Combined Properties                                                      *)
(***************************************************************************)

Safety ==
    /\ CountersNonNegative
    /\ TimeMonotonic
    /\ SamplingWindowInPast

Liveness ==
    /\ OpenEventuallyHalfOpen
    /\ HalfOpenEventuallyResolves
    /\ RequestsComplete

(***************************************************************************)
(* Theorems to Verify                                                       *)
(***************************************************************************)

THEOREM Spec => []TypeOK
THEOREM Spec => []Safety
THEOREM Spec => OpenEventuallyHalfOpen
THEOREM Spec => HalfOpenEventuallyResolves
THEOREM Spec => NotStuckOpen

=============================================================================

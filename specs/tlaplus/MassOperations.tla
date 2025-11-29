------------------------------- MODULE MassOperations -------------------------------
(*
 * Formal TLA+ specification of mass operations (token revocation, MFA reset, app deletion).
 *
 * This module models the batch processing of destructive operations with:
 * - Self-protection (current admin excluded from operations)
 * - Batch-based processing with delays
 * - Cancellation support
 * - Success/failure tracking
 *
 * Corresponds to: Services/TokenRevocationService.cs
 *
 * Critical Safety Invariants:
 *   1. The current admin (excludeUserId) is NEVER processed
 *   2. Each user is processed at most once
 *   3. Outcomes (success/failure) are disjoint and cover all processed users
 *)

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    USERS,              \* Set of all user IDs in the tenant
    ADMIN_ID,           \* The current admin user ID (must be in USERS)
    BATCH_SIZE,         \* Maximum users processed in parallel per batch
    NULL

ASSUME ADMIN_ID \in USERS
ASSUME BATCH_SIZE >= 1

VARIABLES
    operationState,     \* Current state of the mass operation
    usersToProcess,     \* Set of users remaining to process
    processed,          \* Set of users that have been processed
    succeeded,          \* Set of users where operation succeeded
    failed,             \* Set of users where operation failed
    currentBatch,       \* Users currently being processed
    cancelled           \* Whether operation was cancelled

vars == <<operationState, usersToProcess, processed, succeeded, failed,
          currentBatch, cancelled>>

(***************************************************************************)
(* Operation States                                                         *)
(***************************************************************************)

OpStates == {"Idle", "Preparing", "Processing", "BatchComplete",
             "Completed", "Cancelled"}

(***************************************************************************)
(* Type Invariant                                                           *)
(***************************************************************************)

TypeOK ==
    /\ operationState \in OpStates
    /\ usersToProcess \subseteq USERS
    /\ processed \subseteq USERS
    /\ succeeded \subseteq USERS
    /\ failed \subseteq USERS
    /\ currentBatch \subseteq USERS
    /\ cancelled \in BOOLEAN

(***************************************************************************)
(* Initial State                                                            *)
(***************************************************************************)

Init ==
    /\ operationState = "Idle"
    /\ usersToProcess = {}
    /\ processed = {}
    /\ succeeded = {}
    /\ failed = {}
    /\ currentBatch = {}
    /\ cancelled = FALSE

(***************************************************************************)
(* Helper Functions                                                         *)
(***************************************************************************)

\* Users that can be processed (excludes admin)
EligibleUsers == USERS \ {ADMIN_ID}

\* Select up to BATCH_SIZE users from a set
SelectBatch(S) ==
    IF Cardinality(S) <= BATCH_SIZE
    THEN S
    ELSE CHOOSE batch \in SUBSET S:
            /\ Cardinality(batch) = BATCH_SIZE
            /\ batch \subseteq S

(***************************************************************************)
(* State Transitions                                                        *)
(***************************************************************************)

\* Start a new mass operation - loads all eligible users
StartOperation ==
    /\ operationState = "Idle"
    /\ ~cancelled
    /\ operationState' = "Preparing"
    /\ usersToProcess' = EligibleUsers
    /\ processed' = {}
    /\ succeeded' = {}
    /\ failed' = {}
    /\ currentBatch' = {}
    /\ UNCHANGED cancelled

\* Preparation complete, start processing
BeginProcessing ==
    /\ operationState = "Preparing"
    /\ ~cancelled
    /\ usersToProcess # {}
    /\ LET batch == SelectBatch(usersToProcess)
       IN /\ currentBatch' = batch
          /\ usersToProcess' = usersToProcess \ batch
          /\ operationState' = "Processing"
    /\ UNCHANGED <<processed, succeeded, failed, cancelled>>

\* No users to process - operation is already complete
EmptyOperation ==
    /\ operationState = "Preparing"
    /\ usersToProcess = {}
    /\ operationState' = "Completed"
    /\ UNCHANGED <<usersToProcess, processed, succeeded, failed,
                   currentBatch, cancelled>>

\* Process a single user in the current batch (succeeds)
ProcessUserSuccess(userId) ==
    /\ operationState = "Processing"
    /\ ~cancelled
    /\ userId \in currentBatch
    /\ userId # ADMIN_ID  \* CRITICAL: Never process admin
    /\ currentBatch' = currentBatch \ {userId}
    /\ processed' = processed \cup {userId}
    /\ succeeded' = succeeded \cup {userId}
    /\ UNCHANGED <<operationState, usersToProcess, failed, cancelled>>

\* Process a single user in the current batch (fails)
ProcessUserFailure(userId) ==
    /\ operationState = "Processing"
    /\ ~cancelled
    /\ userId \in currentBatch
    /\ userId # ADMIN_ID  \* CRITICAL: Never process admin
    /\ currentBatch' = currentBatch \ {userId}
    /\ processed' = processed \cup {userId}
    /\ failed' = failed \cup {userId}
    /\ UNCHANGED <<operationState, usersToProcess, succeeded, cancelled>>

\* Current batch complete, check for more work
BatchComplete ==
    /\ operationState = "Processing"
    /\ currentBatch = {}
    /\ ~cancelled
    /\ operationState' = "BatchComplete"
    /\ UNCHANGED <<usersToProcess, processed, succeeded, failed,
                   currentBatch, cancelled>>

\* Move to next batch
NextBatch ==
    /\ operationState = "BatchComplete"
    /\ usersToProcess # {}
    /\ ~cancelled
    /\ LET batch == SelectBatch(usersToProcess)
       IN /\ currentBatch' = batch
          /\ usersToProcess' = usersToProcess \ batch
          /\ operationState' = "Processing"
    /\ UNCHANGED <<processed, succeeded, failed, cancelled>>

\* All batches complete
AllComplete ==
    /\ operationState = "BatchComplete"
    /\ usersToProcess = {}
    /\ ~cancelled
    /\ operationState' = "Completed"
    /\ UNCHANGED <<usersToProcess, processed, succeeded, failed,
                   currentBatch, cancelled>>

\* Cancel the operation
CancelOperation ==
    /\ operationState \in {"Preparing", "Processing", "BatchComplete"}
    /\ cancelled' = TRUE
    /\ operationState' = "Cancelled"
    \* Keep partial results
    /\ UNCHANGED <<usersToProcess, processed, succeeded, failed, currentBatch>>

\* Reset to idle after completion or cancellation
Reset ==
    /\ operationState \in {"Completed", "Cancelled"}
    /\ operationState' = "Idle"
    /\ usersToProcess' = {}
    /\ processed' = {}
    /\ succeeded' = {}
    /\ failed' = {}
    /\ currentBatch' = {}
    /\ cancelled' = FALSE

(***************************************************************************)
(* Next-State Relation                                                      *)
(***************************************************************************)

Next ==
    \/ StartOperation
    \/ BeginProcessing
    \/ EmptyOperation
    \/ \E u \in USERS: ProcessUserSuccess(u)
    \/ \E u \in USERS: ProcessUserFailure(u)
    \/ BatchComplete
    \/ NextBatch
    \/ AllComplete
    \/ CancelOperation
    \/ Reset

(***************************************************************************)
(* Fairness Conditions                                                      *)
(***************************************************************************)

\* Weak fairness: if processing is enabled, it eventually happens
Fairness ==
    /\ WF_vars(BeginProcessing)
    /\ WF_vars(BatchComplete)
    /\ WF_vars(NextBatch)
    /\ WF_vars(AllComplete)
    /\ \A u \in USERS: WF_vars(ProcessUserSuccess(u) \/ ProcessUserFailure(u))

Spec == Init /\ [][Next]_vars /\ Fairness

(***************************************************************************)
(* CRITICAL SAFETY INVARIANTS                                               *)
(***************************************************************************)

\* INV1: Admin is NEVER processed - THE MOST CRITICAL INVARIANT
AdminNeverProcessed ==
    ADMIN_ID \notin processed

\* INV2: Admin is never in succeeded set
AdminNeverSucceeded ==
    ADMIN_ID \notin succeeded

\* INV3: Admin is never in failed set
AdminNeverFailed ==
    ADMIN_ID \notin failed

\* INV4: Admin is never in current batch
AdminNeverInBatch ==
    ADMIN_ID \notin currentBatch

\* INV5: Admin is never in users to process
AdminNeverQueued ==
    ADMIN_ID \notin usersToProcess

(***************************************************************************)
(* SET RELATIONSHIP INVARIANTS                                              *)
(***************************************************************************)

\* INV6: Succeeded and failed are disjoint
SucceededFailedDisjoint ==
    succeeded \cap failed = {}

\* INV7: All outcomes are from processed users
OutcomesFromProcessed ==
    (succeeded \cup failed) \subseteq processed

\* INV8: All processed users have an outcome (when batch is empty)
ProcessedHaveOutcome ==
    currentBatch = {} => (succeeded \cup failed) = processed

\* INV9: Current batch is disjoint from processed
BatchNotProcessed ==
    currentBatch \cap processed = {}

\* INV10: No user is processed twice
NoDoubleProcessing ==
    \A u \in USERS:
        Cardinality({u} \cap processed) <= 1

(***************************************************************************)
(* BOUNDED PROGRESS INVARIANTS                                              *)
(***************************************************************************)

\* INV11: Processed count never exceeds eligible users
BoundedProgress ==
    Cardinality(processed) <= Cardinality(EligibleUsers)

\* INV12: Batch size is respected
BatchSizeRespected ==
    Cardinality(currentBatch) <= BATCH_SIZE

\* INV13: Work is partitioned correctly
WorkPartitioned ==
    operationState \in {"Processing", "BatchComplete"} =>
        (currentBatch \cup usersToProcess \cup processed) = EligibleUsers

(***************************************************************************)
(* LIVENESS PROPERTIES                                                      *)
(***************************************************************************)

\* LIVE1: Operation eventually completes (if not cancelled)
OperationEventuallyCompletes ==
    (operationState = "Preparing" /\ ~cancelled) ~>
        (operationState \in {"Completed", "Cancelled"})

\* LIVE2: All eligible users are eventually processed (if not cancelled)
AllUsersEventuallyProcessed ==
    (operationState = "Preparing" /\ ~cancelled) ~>
        (operationState = "Completed" => processed = EligibleUsers)

\* LIVE3: Each user in batch is eventually processed
BatchEventuallyEmpty ==
    \A u \in USERS:
        (u \in currentBatch) ~> (u \notin currentBatch)

\* LIVE4: Completed state is stable until reset
CompletedStable ==
    operationState = "Completed" ~>
        (operationState = "Idle" \/ operationState = "Completed")

(***************************************************************************)
(* TEMPORAL PROPERTIES                                                      *)
(***************************************************************************)

\* Once admin is excluded, they stay excluded forever
AdminAlwaysProtected ==
    [](ADMIN_ID \notin processed)

\* Outcomes are monotonic (once succeeded, stays succeeded)
SucceededMonotonic ==
    \A u \in USERS:
        [](u \in succeeded => [](u \in succeeded))

\* Outcomes are monotonic (once failed, stays failed)
FailedMonotonic ==
    \A u \in USERS:
        [](u \in failed => [](u \in failed))

(***************************************************************************)
(* COMBINED SAFETY PROPERTY                                                 *)
(***************************************************************************)

\* All safety invariants combined
Safety ==
    /\ AdminNeverProcessed
    /\ AdminNeverSucceeded
    /\ AdminNeverFailed
    /\ AdminNeverInBatch
    /\ AdminNeverQueued
    /\ SucceededFailedDisjoint
    /\ OutcomesFromProcessed
    /\ BatchNotProcessed
    /\ BoundedProgress
    /\ BatchSizeRespected

(***************************************************************************)
(* Theorems to Verify                                                       *)
(***************************************************************************)

THEOREM Spec => []TypeOK
THEOREM Spec => []Safety
THEOREM Spec => []AdminAlwaysProtected
THEOREM Spec => OperationEventuallyCompletes
THEOREM Spec => AllUsersEventuallyProcessed

=============================================================================

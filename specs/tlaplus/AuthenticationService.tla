--------------------------- MODULE AuthenticationService ---------------------------
(*
 * Formal TLA+ specification of the Safeguard AuthenticationService.
 *
 * This module models the OAuth2 Authorization Code Flow with PKCE,
 * including silent authentication, token refresh, and session management.
 *
 * Corresponds to: Services/AuthenticationService.cs
 *)

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    NULL,                   \* Null/empty value
    REFRESH_BUFFER_MINUTES, \* Buffer before expiry to trigger refresh (5 min)
    MAX_TIME                \* Maximum simulation time for model checking

VARIABLES
    authState,              \* Current authentication state
    cachedToken,            \* Cached access token (or NULL)
    tokenExpiry,            \* Token expiration timestamp
    cachedAccount,          \* Cached account info (or NULL)
    currentUserId,          \* Currently authenticated user ID
    currentUserPrincipal,   \* User principal name (UPN)
    now                     \* Current time (for temporal reasoning)

vars == <<authState, cachedToken, tokenExpiry, cachedAccount,
          currentUserId, currentUserPrincipal, now>>

(***************************************************************************)
(* Authentication States                                                    *)
(***************************************************************************)

AuthStates == {"Unauthenticated", "Authenticating", "Authenticated",
               "TokenExpiring", "Refreshing", "Failed"}

(***************************************************************************)
(* Type Invariant                                                           *)
(***************************************************************************)

TypeOK ==
    /\ authState \in AuthStates
    /\ cachedToken \in {NULL} \cup STRING
    /\ tokenExpiry \in Nat \cup {NULL}
    /\ cachedAccount \in {NULL} \cup STRING
    /\ currentUserId \in {NULL} \cup STRING
    /\ currentUserPrincipal \in {NULL} \cup STRING
    /\ now \in Nat

(***************************************************************************)
(* Initial State                                                            *)
(***************************************************************************)

Init ==
    /\ authState = "Unauthenticated"
    /\ cachedToken = NULL
    /\ tokenExpiry = NULL
    /\ cachedAccount = NULL
    /\ currentUserId = NULL
    /\ currentUserPrincipal = NULL
    /\ now = 0

(***************************************************************************)
(* Helper Predicates                                                        *)
(***************************************************************************)

\* Token is valid if it exists and hasn't expired (with buffer)
TokenValid ==
    /\ cachedToken # NULL
    /\ tokenExpiry # NULL
    /\ now + REFRESH_BUFFER_MINUTES < tokenExpiry

\* Token is expiring if within the refresh buffer window
TokenExpiring ==
    /\ cachedToken # NULL
    /\ tokenExpiry # NULL
    /\ now + REFRESH_BUFFER_MINUTES >= tokenExpiry
    /\ now < tokenExpiry

\* Token has fully expired
TokenExpired ==
    /\ tokenExpiry # NULL
    /\ now >= tokenExpiry

(***************************************************************************)
(* State Transitions                                                        *)
(***************************************************************************)

\* Start interactive authentication from unauthenticated state
StartAuthentication ==
    /\ authState = "Unauthenticated"
    /\ authState' = "Authenticating"
    /\ UNCHANGED <<cachedToken, tokenExpiry, cachedAccount,
                   currentUserId, currentUserPrincipal, now>>

\* Silent authentication attempt (returning user with cached credentials)
TrySilentAuth ==
    /\ authState = "Unauthenticated"
    /\ cachedAccount # NULL  \* Has cached account
    /\ authState' = "Authenticating"
    /\ UNCHANGED <<cachedToken, tokenExpiry, cachedAccount,
                   currentUserId, currentUserPrincipal, now>>

\* Authentication succeeds - transition to Authenticated
AuthenticationSuccess(newToken, newExpiry, userId, upn, account) ==
    /\ authState = "Authenticating"
    /\ authState' = "Authenticated"
    /\ cachedToken' = newToken
    /\ tokenExpiry' = newExpiry
    /\ cachedAccount' = account
    /\ currentUserId' = userId
    /\ currentUserPrincipal' = upn
    /\ UNCHANGED now

\* Authentication fails - transition to Failed
AuthenticationFailed ==
    /\ authState = "Authenticating"
    /\ authState' = "Failed"
    /\ UNCHANGED <<cachedToken, tokenExpiry, cachedAccount,
                   currentUserId, currentUserPrincipal, now>>

\* Detect token is nearing expiry - transition to TokenExpiring
DetectTokenExpiring ==
    /\ authState = "Authenticated"
    /\ TokenExpiring
    /\ authState' = "TokenExpiring"
    /\ UNCHANGED <<cachedToken, tokenExpiry, cachedAccount,
                   currentUserId, currentUserPrincipal, now>>

\* Begin token refresh
StartRefresh ==
    /\ authState = "TokenExpiring"
    /\ authState' = "Refreshing"
    /\ UNCHANGED <<cachedToken, tokenExpiry, cachedAccount,
                   currentUserId, currentUserPrincipal, now>>

\* Token refresh succeeds
RefreshSuccess(newToken, newExpiry) ==
    /\ authState = "Refreshing"
    /\ authState' = "Authenticated"
    /\ cachedToken' = newToken
    /\ tokenExpiry' = newExpiry
    /\ UNCHANGED <<cachedAccount, currentUserId, currentUserPrincipal, now>>

\* Token refresh fails (e.g., refresh token expired)
RefreshFailed ==
    /\ authState = "Refreshing"
    /\ authState' = "Failed"
    /\ cachedToken' = NULL
    /\ tokenExpiry' = NULL
    /\ UNCHANGED <<cachedAccount, currentUserId, currentUserPrincipal, now>>

\* Sign out - clear all cached data
SignOut ==
    /\ authState \in {"Authenticated", "TokenExpiring", "Failed"}
    /\ authState' = "Unauthenticated"
    /\ cachedToken' = NULL
    /\ tokenExpiry' = NULL
    /\ cachedAccount' = NULL
    /\ currentUserId' = NULL
    /\ currentUserPrincipal' = NULL
    /\ UNCHANGED now

\* Recover from failed state (retry authentication)
RetryAfterFailure ==
    /\ authState = "Failed"
    /\ authState' = "Unauthenticated"
    /\ UNCHANGED <<cachedToken, tokenExpiry, cachedAccount,
                   currentUserId, currentUserPrincipal, now>>

\* Time advances
Tick ==
    /\ now < MAX_TIME
    /\ now' = now + 1
    /\ UNCHANGED <<authState, cachedToken, tokenExpiry, cachedAccount,
                   currentUserId, currentUserPrincipal>>

(***************************************************************************)
(* Next-State Relation                                                      *)
(***************************************************************************)

Next ==
    \/ StartAuthentication
    \/ TrySilentAuth
    \/ \E t \in STRING, exp \in Nat, uid \in STRING, upn \in STRING, acc \in STRING:
         AuthenticationSuccess(t, exp, uid, upn, acc)
    \/ AuthenticationFailed
    \/ DetectTokenExpiring
    \/ StartRefresh
    \/ \E t \in STRING, exp \in Nat: RefreshSuccess(t, exp)
    \/ RefreshFailed
    \/ SignOut
    \/ RetryAfterFailure
    \/ Tick

(***************************************************************************)
(* Fairness Conditions                                                      *)
(***************************************************************************)

\* Weak fairness: if refresh is continuously enabled, it eventually happens
Fairness ==
    /\ WF_vars(StartRefresh)
    /\ WF_vars(Tick)

Spec == Init /\ [][Next]_vars /\ Fairness

(***************************************************************************)
(* Safety Properties                                                        *)
(***************************************************************************)

\* INV1: Token is never used after full expiry
TokenNotUsedAfterExpiry ==
    authState = "Authenticated" => ~TokenExpired

\* INV2: User ID and UPN are set together (consistency)
UserInfoConsistent ==
    (currentUserId = NULL) <=> (currentUserPrincipal = NULL)

\* INV3: Cached token implies authenticated or transitioning
CachedTokenImpliesAuth ==
    cachedToken # NULL =>
        authState \in {"Authenticated", "TokenExpiring", "Refreshing"}

\* INV4: Cannot be in Refreshing without having been Authenticated
RefreshingImpliesWasAuthenticated ==
    authState = "Refreshing" => cachedAccount # NULL

\* INV5: Token expiry is always in the future when token is valid
TokenExpiryInFuture ==
    (cachedToken # NULL /\ tokenExpiry # NULL) => tokenExpiry > 0

(***************************************************************************)
(* Liveness Properties                                                      *)
(***************************************************************************)

\* LIVE1: If token is expiring, refresh eventually starts or fails
EventuallyRefreshOrFail ==
    authState = "TokenExpiring" ~>
        (authState = "Refreshing" \/ authState = "Failed")

\* LIVE2: Authentication eventually completes (succeeds or fails)
AuthenticationEventuallyCompletes ==
    authState = "Authenticating" ~>
        (authState = "Authenticated" \/ authState = "Failed")

\* LIVE3: Refresh eventually completes
RefreshEventuallyCompletes ==
    authState = "Refreshing" ~>
        (authState = "Authenticated" \/ authState = "Failed")

(***************************************************************************)
(* Theorems to Verify                                                       *)
(***************************************************************************)

THEOREM Spec => []TypeOK
THEOREM Spec => []TokenNotUsedAfterExpiry
THEOREM Spec => []UserInfoConsistent
THEOREM Spec => []CachedTokenImpliesAuth
THEOREM Spec => []RefreshingImpliesWasAuthenticated
THEOREM Spec => EventuallyRefreshOrFail
THEOREM Spec => AuthenticationEventuallyCompletes
THEOREM Spec => RefreshEventuallyCompletes

=============================================================================

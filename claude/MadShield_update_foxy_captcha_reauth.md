# 1.18.2 - Foxy CAPTCHA renewal: operation lifecycle (1.18.1) and other ways to send the refresh (1.18.2); rename to MadShield_updateN.md when N is known

## Symptom
During Foxy account renewal a Fastly image CAPTCHA is shown, the person answers, nothing says what happened, another
CAPTCHA appears, and it repeats until the person logs out and signs in again.

## What was found (from the code; the root cause could not be proven offline)
Confirmed defects in the old flow (patch 0003 + FxRenew.kt):
- one global "renewal" with one picture id; no operation id, so a stale answer, a double tap or the cleanup of an older
  dialog could touch a newer renewal;
- the dialog swallowed every answer error (`catch (_: Exception) {}`), and the local HTTP 200 of the answer route was the
  only feedback although it proves nothing about Fastly;
- a new picture after an answer looked the same as a rejected answer; the core never said which it was;
- the token refresh result was installed without checking that the account still held the credentials it started from,
  and a failed save could leave memory and disk different;
- no distinct end states (cancelled, timed out) and no safe timeout.

Hypotheses that need on-device logs (the new events and failure codes will separate them): cookie/exit-IP change between
solving and the retry, IPv4/IPv6 flip, Fastly 406 on non-browser OAuth requests, challenge-token expiry.

## What changed
Go core (all in `native/fxvpn/patches/0003-madshield-reauth-captcha.patch`; 0001/0002 untouched, applies cleanly on the pin):
- `fxa`: challenge events (`WithChallengeObserver`, no answers/tokens/cookies in them), failure sentinels, `ErrChallengeStillRefused`.
- `service`: operation lifecycle idle, starting, waiting_for_captcha, submitting, verifying, additional_challenge, completed,
  failed, cancelled, timed_out; operation id + picture id (`op.round`); one answer per picture; stale/duplicate/out-of-order
  answers refused with a fixed code; cancel names its operation; time limit 4 min; at most 6 pictures; failure codes.
  Routes: `POST/GET/DELETE /api/ms/reauth` (cancel as `?op=`), `POST /api/ms/reauth/answer` body `{op,id,answer}`.
  200 on an answer means only "handed to the challenge flow".
- `proxy`: `RenewAccessToken` installs the new tokens only if the pool still holds the credentials it refreshed from
  (store first, then memory, one lock); a failed or cancelled renewal changes nothing; a persistence error is reported
  (kept in memory only when the refresh token rotated).
Android:
- `FxVpn.kt` (FxReauth model, FxReauthState, FxReauthCodes), `FxClient.kt` (op-aware calls, `ApiException.code`),
  new `FxRenewFlow.kt` (pure UI logic: one in-flight answer per picture, polling cannot race a submission, a view of another
  operation ends this one, cancel targets only the operation this dialog started), `FxRenew.kt` (dialog uses the flow, shows
  send errors), strings `fx_renew_*` in values and values-fa.
- Nothing is ever labelled "incorrect" unless Fastly itself refused the post-back (HTTP 4xx): that is `answer_rejected`.

## 1.18.2: why 5-6 CAPTCHAs in a row never worked (from a phone test of 1.18.1)
Screenshot of 1.18.1: picture after picture (Picture 4 ...), then "Fastly accepted the check but still blocked the renewal"
= failure code `refresh_still_challenged` (every one of the 5 tries of the refresh was answered 406 after a solved challenge).
So the challenge was accepted; the refresh REQUEST itself is what the edge refused.
Cause found in the code: the refresh (`fxaRefreshToken`, pinned 1.0.8) is sent one way only (Firefox UA + Firefox TLS over
HTTP/1.1, with net/http's own `Accept-Encoding: gzip`). Patch 0002 already knows other ways of presenting a request for the
browser sign-in (app UA with HTTP/2, Firefox page headers, the OAuth server's own host), but the refresh never used them, so
more CAPTCHAs could not change the answer.
Upstream (armanlife/firefox-vpn-client, 1.0.13-1.0.14, read only for diagnosis; the pin was NOT moved: it renamed its Go module
and the patches would not apply) found the same family of causes: gzip as the only Accept-Encoding went with 406 on the HTTP/1.1
OAuth path, and the solved cookie must be installed for the OAuth host as well.
Fix (own code in patch 0003, `fxa/madshield_refresh.go`, `fxaDoWith`): the refresh sends `Accept-Encoding: identity`; after a 406
and BEFORE a CAPTCHA, the refresh is sent as app, as Firefox page, and to the OAuth host (first non-refusal wins; only the
account server's own answer, or 200, counts); done for the first 2 answers of 406 only. The solved cookie is installed for the
OAuth host too. The log line `renewal ended ... alt=app:406,page:200` shows which way the edge let through.
Tests (fake edge): each way alone is accepted with no CAPTCHA; all refused -> challenge as before; bounded; identity; cookie on OAuth host.
Honest limit: whether the real Fastly lets one of these through is unknown until tried on the phone; if `alt=` shows all 406,
the next step is the TLS/HTTP2 look of the refresh itself (read the `alt=` and `reply=` values in the log).

## Not touched
HEV, sing-box, RouteFront, DNS, UDP, TLS verification, Fastly checks. No CAPTCHA answers are stored, logged or automated.

## Verification done here
- Go (scratch module with the real fxa/proxy/service code and stubs): `go test -race` passes. The real core and the app
  could not be built offline.
- `git apply` of 0001, 0002, 0003 in order on the pinned upstream (e9e6c49) is clean.
- Pure Kotlin tests (`tests/pure/Tests.kt`): ALL PASSED, including new FxRenewFlow tests.
- NOT run: Android build, native build, Compose dialog, the real Fastly flow.

## Manual tests still needed
Real renewal with a CAPTCHA (single, several rounds); cancel during verifying; closing the dialog mid-answer; airplane mode
during submit; renew while connected; normal sign-in; renewal when the token is still valid; phone rotate during the dialog.
Read the new log lines `renewal started/event/picture/verifying/ended op=...` to see which hypothesis is true.

## Text to add to MadShield_memory.md
- Foxy CAPTCHA renewal is an operation (op id + picture id `op.round`); states waiting_for_captcha, submitting, verifying,
  additional_challenge, completed/failed/cancelled/timed_out; answers carry `{op,id,answer}`; HTTP 200 on an answer is not proof.
- Token install is compare-and-swap under the pool lock (store first, then memory). Logic of the dialog lives in `FxRenewFlow` (pure, tested).
- Failure words in the core map to strings `fx_renew_err_<word>`; a test enforces en + fa for each.

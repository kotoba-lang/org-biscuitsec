# org-biscuitsec

**A token anyone can attenuate offline, that anyone can verify with no
secret at all.**

**The delegation centre of this workspace** (root ADR-2608180200): new
principal-to-principal delegation is written here, and every other capability
format keeps a named, narrower role.

Origin plane of [biscuitsec.org](https://www.biscuitsec.org) — the format is
Biscuit's, so the repo is named for where it comes from, not for what it does
here. This is a **clean-room decision core**, not a port.

```clojure
(require '[biscuit.token :as bt] '[biscuit.authorizer :as az])

(def t (bt/authority {:facts '[[right "prices" read] [user "alice"]]
                      :next-public-key (:public k1)
                      :root-private-key (:private root) :sign-fn sign}))

;; Attenuate with a key the ISSUER does not hold and has never seen.
(def narrowed (bt/append t {:checks '[{:body [[operation read]]}]
                            :next-public-key (:public k2)
                            :private-key (:private k1) :sign-fn sign}))

(az/authorize narrowed {:root-public-key (:public root) :verify-fn verify
                        :facts '[[operation read]]
                        :policies '[{:kind :allow :body [[user "alice"]]}]})
;; => {:allowed? true :verified? true :reason :allowed-by-policy}
```

## The one difference from a macaroon, and it decides deployments

    authority block   signed by root key,   carries next-public-key
    block 1           signed by key 0,      carries next-public-key
    block n           signed by key n-1,    carries next-public-key

A macaroon chains an HMAC, so **only the holder of the root secret can
verify**. A biscuit chains public keys, so a verifier needs only the root
*public* key — which means any node, worker or browser can verify a token it
was handed **without being trusted with anything**. In a fleet where
verification happens at the edge, that is the property that matters.

## Attenuation is monotone because of scoping, not etiquette

A later block may add facts, rules and checks. What stops it widening the
token is that a check is evaluated against **the authority block's facts plus
its own, and nothing later** — so a block cannot inject the fact that
satisfies an earlier block's check.

An implementation gets this wrong by pooling every fact into one set, and
every ordinary test still passes, because ordinary tokens have no reason to
lie to themselves. There is a test here that fails **only** when the pool is
shared.

## Checks are the token's; policies are the verifier's

- **checks** live in the token and must all pass — what the holder, and
  everyone who attenuated after, restricted themselves to.
- **policies** live in the authorizer; the first that matches decides.

So **there is no `allow` inside a token**: a token cannot allow itself. And
`:no-policy-matched` is reported distinctly from `:denied-by-policy` — both
refuse, and telling them apart is what says *your policy set has a hole*
rather than *your rule fired*.

Order is fixed: **verify → checks → policies.** Running policies first would
let a token whose signature does not verify reach a rule that says `allow`.

## Where it sits, repo-wide

Five capability surfaces were measured across the fleet (root ADR-2608180200)
and **four of them are not delegation at all** — which is why they never
needed one format and why naming what each *is* was most of the work:

| surface | what it actually is | revocation |
|---|---|---|
| `kotoba-lang/kotoba-lang` `capability-semantics.edn` | the **semantics**: `requested ∩ delegated ∩ local-policy` | at effect time |
| `kotoba-lang/amu` `{:allow #{[:cap/call n]}}` | compile-time **admission** — what code may even ask for | signer set |
| `kotoba-lang/aiueos` `capability-plan.kotoba` | a machine-local **capability table** (slot/generation/type/rights/owner) | **generation bump** |
| `kotoba-lang/kototama` `component-authority` | a signed **epoch feed** for placement and revocation | monotonic epoch |
| **here** | **delegation between principals** | — |

The last column is the finding worth carrying: **a biscuit cannot revoke**,
and two of the other four already can. So revocation rides the generation and
epoch planes that exist rather than becoming a revocation list nobody serves.

`biscuit.kotoba/->delegated` is the concrete seam. The semantics had four
terms and three owners; **`delegated` had no wire**, and that slot is what
"biscuit is the centre" means — not that biscuit replaces the semantics.

```clojure
(bk/->delegated token kinds)
;; => {:grants [{:grant/kind :graph-read
;;               :grant/resources ["kotoba://graph/acme"]
;;               :grant/expires "2026-09-01T00:00:00Z" :grant/id "biscuit:…"}]
;;     :grant/rejected [{:kind :kernel/format-disk :resource "/dev/sda"}]}
```

It maps to `:grant/*` and never to `:cap/*`: a capability is what a handler
receives **after** intersection, and a token that produced one directly would
have skipped the step the semantics says is not optional. A kind outside the
closed `:kinds` set is **rejected, not ignored** — ignoring silently drops a
restriction the issuer meant, so the failure is toward less authority and is
visible in `:grant/rejected`.

## The guarded call — the slice that makes it the centre

`biscuit.effective/authorize` answers what a host actually asks — *may this
call proceed* — and it needs **the token, the root public key, the local
policy and a clock. No secret, on any branch.** That is what lets it run in a
Worker, a browser or on an untrusted mirror, and it is the entire reason the
centre is biscuit and not macaroon.

```clojure
(eff/authorize {:semantics semantics :token t
                :root-public-key pk :verify-fn verify
                :requested {:cap/kind :graph-read :cap/resource "kotoba://graph/acme"}
                :local-policy {:policy/allow [...] :policy/forbid-wildcard true}
                :now now :call "graph/read"})
;; => {:allowed? true :reason :granted
;;     :capability {:cap/kind :graph-read :cap/resource "…" :cap/provenance :biscuit}
;;     :receipt {:receipt/at … :receipt/call … :receipt/cap … :receipt/outcome :allowed}}
```

**The rules are read, not restated.** `authorize` takes the semantics map and
branches on its `:rules`; copying `:unknown-kind :deny` into a `case` here
would make this a second statement of the language's policy. A contract test
loads the real `lang/capability-semantics.edn` and fails when the rule set
changes shape — and **refuses rather than passing when it cannot read the
file**, because a contract test that cannot see the contract has not checked
one.

**Every attempt is receipted, including the denials.**
`:attempt-always-receipted true` is in the semantics, and a guard that logs
what it allowed and forgets what it refused cannot answer the only question
an incident asks.

## Scored against the alternatives

Root ADR-2608180200, 0–5, weighted for this workspace:

| | offline | **verify w/o secret** | attenuation | expressiveness | revocation | wire maturity | implemented here | total |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **biscuit** | 5 | **5** | 5 | **5** | 3 | 2 | 4 | **29** |
| UCAN | 5 | 5 | 5 | 3 | 4 | 4 | 4 | **30** |
| CACAO | 5 | 5 | 2 | 2 | 3 | 4 | 5 | 26 |
| VC/VP | 5 | 5 | 0 | 4 | 4 | 5 | 4 | 27 |
| macaroon | 5 | **0** | 5 | 3 | 2 | 2 | 4 | 21 |
| mTLS / X.509 | 4 | 5 | 0 | 1 | 2 | 5 | 3 | 20 |
| OAuth2 / JWT | 4 | 4 | 0 | 2 | 1 | 5 | 3 | 19 |
| bearer token | 0 | 0 | 0 | 0 | 5 | 5 | 5 | 15 |

**UCAN scores one point higher and was not chosen.** The gap is wire maturity
and revocation; biscuit wins expressiveness by two, and this workspace speaks
Datalog — so delegation conditions written in Datalog are worth more here than
elsewhere. The table is recorded as the *reason*, not as the decision.

## The Datalog, and why it is not a second copy of `kotoba-lang/datalog`

| | `kotoba-lang/datalog` | here |
|---|---|---|
| facts | **EAV triples**, indexed | **n-ary** `[pred t …]`, no index |
| source | a database value | a token's blocks |
| size | the corpus | tens of facts |
| termination | range-restricted | range-restricted **plus a budget** |

Flattening n-ary facts into triples to reuse the EAV engine means inventing
entity ids the token never had. These two cannot substitute for each other,
so they are two things (ADR-2607299700 reads the other way). **The trigger to
revisit is a third n-ary evaluator.**

The budget is a safety property, not a tuning knob — an authorizer runs
attacker-supplied rules, and exceeding it is a **distinct outcome**
(`:budget-exceeded`), never an empty result set. A truncated derivation that
answered *no facts* would deny for the wrong reason today and allow for the
wrong reason tomorrow. An **unsafe rule** — a head variable the body never
binds — is refused rather than skipped, for the party who can fix it.

## Two wires, one decider

`biscuit.authority/->grant` maps a verified token onto
`kotoba-lang/authority`, exactly as `macaroon.authority` does. Only
`scope` / `before` / `holder` facts are read **for granting**; everything
else stays available to checks and policies. Ignoring is safe in exactly one
direction and this is that direction — **an unread fact cannot widen a
grant.**

Within a block, scope facts are alternatives; **across blocks they narrow.**
Meeting every fact separately — how this was first written — makes a block
with two scopes reach nothing: safe, and wrong.

## What it refuses, by name

- **The wire format.** Biscuit v3 is protobuf + Ed25519. This holds the
  decision core and a canonical EDN encoding; it does **not** read or write
  biscuit protobuf and does not claim interoperability with `biscuit-auth`.
  A partial decoder that guessed would produce plausible tokens, which is
  worse than none.
- **Crypto.** `sign-fn` / `verify-fn` injected, no default Ed25519.
- **Third-party blocks.** Refused in `append` rather than approximated.

## Verification

`clojure -M:test` and `npm run test:nbb` — **38 tests, 95 assertions**, both
green. Shown red on nine real defects and green again with each reverted:

| broken | failures |
|---|---:|
| facts pooled across all blocks (attenuation stops being monotone) | 2 |
| the signature stops covering `next-public-key` | 2 |
| the Datalog budget truncates instead of refusing | 1 |
| a later block can extend an expiry | 2 |
| a kind outside the closed set is admitted instead of rejected | 3 |
| a later block may add kinds and resources (attenuation stops being only-attenuation) | 3 |
| the local-policy term is dropped from the intersection | 1 |
| denials are not receipted | 7 |
| the contract file is unreadable (must fail, not pass) | 1 |

The second was **found by the exercise**: nothing had checked that a block
cannot be spliced onto a different continuation. The attack it permits is
complete — rewrite a signed block's `next-public-key` to a key you control,
append blocks you sign, and the chain verifies. That test now exists, and it
is the strongest one in the suite.

Two attempted breaks first appeared to pass unbroken and had simply not
applied — indentation mismatches in the edit. **A no-op break looks exactly
like a missing test**, and the only way to tell them apart is to diff the
file you claim to have broken. One of the two was real when redone (denials
went unreceipted in seven places); the other — "a later block can extend an expiry" — first
appeared to pass unbroken. The edit had silently not applied (indentation
mismatch). **A no-op break looks exactly like a missing test**, and the only
way to tell them apart is to diff the file you claim to have broken.

# org-biscuitsec

**A token anyone can attenuate offline, that anyone can verify with no
secret at all.**

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

`clojure -M:test` and `npm run test:nbb` — **22 tests, 49 assertions**, both
green. Shown red on four real defects and green again with each reverted:

| broken | failures |
|---|---:|
| facts pooled across all blocks (attenuation stops being monotone) | 2 |
| the signature stops covering `next-public-key` | 2 |
| the Datalog budget truncates instead of refusing | 1 |
| a later block can extend an expiry | 2 |

The second was **found by the exercise**: nothing had checked that a block
cannot be spliced onto a different continuation. The attack it permits is
complete — rewrite a signed block's `next-public-key` to a key you control,
append blocks you sign, and the chain verifies. That test now exists, and it
is the strongest one in the suite.

A fifth attempted break — "a later block can extend an expiry" — first
appeared to pass unbroken. The edit had silently not applied (indentation
mismatch). **A no-op break looks exactly like a missing test**, and the only
way to tell them apart is to diff the file you claim to have broken.

(ns biscuit.rootkey
  "Where an edge gets the root public key, and how that key rotates without
  anyone being asked to trust the place it came from.

  A biscuit is verified against **one root public key**, which is what lets
  an edge decide a call holding nothing secret. That moves the whole problem
  one step out: the edge now has to learn *which* key, and a key baked into a
  Worker's config cannot be rotated without a redeploy — and a key fetched
  from a mutable location can be swapped by whoever controls that location,
  silently.

  ## The shape is one this fleet already builds three times

  `kotobase.storage.signed-head` (signed, sequenced record naming its
  predecessor), IPNS v2 (signed, sequenced, self-certifying name) and
  `kototama.component-authority` (monotonic signed epoch feed) are the same
  object. `did:webvh` is a fourth. Rather than add a fifth, this is that
  shape applied to a key set — and it is also, exactly, what a biscuit does
  internally: each block names the key that may sign the next one.

  ## Pre-rotation is what makes the rotation verifiable

  A record commits to the **digest of the key that may sign the next
  record**. So a reader that trusts record *n* can verify record *n+1*
  without trusting the host it came from: the new key must be the one the old
  record already named. An attacker who takes over the publishing location
  can serve old records or no records — they cannot introduce a key nobody
  committed to.

  This is `did:webvh`'s core property, obtained without putting DNS and HTTPS
  back in the path (root ADR-2608039000). A `did:webvh` document can still be
  the *transport* for these records; it is not required to be their
  authority.

  ## Two defects this shape has already cost the fleet once

  `signed-head`'s docstring records both, found 2026-08-04, and both apply
  here unchanged:

  - **The record must name what it is the key FOR.** Otherwise a host answers
    a request for subject B with subject A's genuinely-signed record, and it
    verifies — nothing was forged.
  - **The issuer must be constrained by something outside the record.**
    Verifying a signature by whoever the record names is *somebody signed
    this*, which any keypair satisfies.

  Here that outside constraint is the pre-rotation commitment, and for the
  first record it is the genesis digest the caller pins."
  (:require [clojure.string :as str]))

(def version "biscuit.rootkey/v1")

(defn record
  "The canonical map a signer signs and a verifier checks. One function, so
  the two sides cannot drift."
  [{:keys [subject seq keys next-key-digest prev-signature]}]
  {"v" version
   "subject" subject
   "seq" seq
   "keys" (mapv vec keys)
   "next" next-key-digest
   "prev" prev-signature})

(defn- well-formed? [r subject]
  (and (map? r)
       (= version (get r "v"))
       (= subject (get r "subject"))
       (integer? (get r "seq"))
       (seq (get r "keys"))
       (not (str/blank? (str (get r "next"))))))

(defn verify-log
  "Walk a key-rotation log. -> `{:keys [...] :seq n :records n}` or
  `{:refused reason :at i}`.

  `opts` is `{:subject s :genesis-key-digest d :digest-fn f :verify-fn f}`.

  - `digest-fn` is `(fn [public-key] digest)` — injected, and the same
    function the publisher used, or every commitment fails to match.
  - `verify-fn` is `(fn [public-key payload signature] bool)`.

  The genesis record must be signed by a key whose digest is
  `genesis-key-digest`, which the **caller** pins. Every later record must be
  signed by a key the previous record committed to. Sequence numbers must
  strictly increase: a replayed record is not new information, and accepting
  one would let a host roll a rotation back."
  [records {:keys [subject genesis-key-digest digest-fn verify-fn]}]
  (if (empty? records)
    ;; An empty log is not "no rotations, use the baked key" — it is a host
    ;; that answered nothing, and treating it as a default is how a fetch
    ;; failure becomes an authority decision.
    {:refused :empty-log}
    (loop [[r & more] records expected genesis-key-digest prev-sig nil i 0 last-seq nil]
      (cond
        (nil? r) {:keys (mapv vec (get (nth records (dec (count records))) "keys"))
                  :seq (get (nth records (dec (count records))) "seq")
                  :records (count records)}

        (not (well-formed? r subject))
        {:refused :malformed-or-wrong-subject :at i}

        (and last-seq (not (< last-seq (get r "seq"))))
        {:refused :sequence-not-increasing :at i}

        (not= expected (digest-fn (get r "signer")))
        ;; The whole mechanism: this record's signer is the key the PREVIOUS
        ;; record committed to, or (for the first) the digest the caller
        ;; pinned. A host that cannot produce that key cannot rotate.
        {:refused :signer-not-committed :at i}

        (not (verify-fn (get r "signer")
                        (record {:subject subject :seq (get r "seq")
                                 :keys (get r "keys") :next-key-digest (get r "next")
                                 :prev-signature prev-sig})
                        (get r "sig")))
        {:refused :signature-mismatch :at i}

        :else (recur more (get r "next") (get r "sig") (inc i) (get r "seq"))))))

(defn current-keys
  "The key set a verified log ends at, or nil. `nil` rather than a fallback:
  a caller with no verified key set has no root key, and inventing one is the
  failure this namespace exists to prevent."
  [result]
  (when-not (:refused result) (:keys result)))

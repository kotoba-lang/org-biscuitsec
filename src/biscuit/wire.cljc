(ns biscuit.wire
  "The biscuit v3 wire format — enough of it to **verify a token minted by
  `biscuit-auth`**, checked against that project's own samples.

  Until this existed, `org-biscuitsec` held the model and could not read a
  byte another implementation produced. That is a real limit and the README
  said so; the reader removed that limit first. The facts-only authority
  writer now emits the same format and is accepted by the official
  `biscuit-auth` Rust verifier. That external acceptance is the evidence a
  writer needs; an in-repo round trip alone is not an interoperability test.

  ## What is implemented, and what is refused by name

  | | |
  |---|---|
  | container (`Biscuit`/`SignedBlock`/`PublicKey`/`Proof`) | **yes** |
  | block structure, symbol table, facts, predicates, terms | **yes** |
  | signature payload **v0 and v1**, chained public keys | **yes** |
  | rules, checks | counted, not decoded |
  | **expressions** (`Op`/`OpUnary`/`OpBinary`/`OpClosure`) | **refused by name** |
  | third-party (`externalSignature`) blocks | **refused by name** |
  | facts-only authority token writer | **yes** |

  An expression is where a partial decoder would do real damage: an operator
  it silently dropped is a *check that no longer restricts*, which reads as a
  more permissive token rather than as an error.

  ## The byte order was decided by the sample, not by me

  The spec's v0 section lists the payload parts as data, next key, algorithm;
  the v1 section orders them data, algorithm, next key. Rather than pick one
  and produce plausible verifications, both are expressible and
  `biscuit-auth`'s own `test001_basic.bc` was allowed to decide which one a
  real token uses. The test is what keeps that honest."
  (:require [protobuf.wire :as pb]))

(def version "biscuit/wire-v3")

(def default-symbols
  "Indexes 0–27, reserved. Symbols a token defines start at 1024."
  ["read" "write" "resource" "operation" "right" "time" "role" "owner"
   "tenant" "namespace" "user" "team" "service" "admin" "email" "group"
   "member" "ip_address" "client" "client_ip" "domain" "path" "version"
   "cluster" "node" "hostname" "nonce" "query"])

(def ^:private public-key-schema
  {1 {:name :algorithm :type :uint32}
   2 {:name :key :type :bytes}})

(def ^:private signed-block-schema
  {1 {:name :block :type :bytes}
   2 {:name :next-key :type :bytes}
   3 {:name :signature :type :bytes}
   4 {:name :external-signature :type :bytes}
   5 {:name :version :type :uint32}})

(def ^:private biscuit-schema
  {1 {:name :root-key-id :type :uint32}
   2 {:name :authority :type :bytes}
   3 {:name :blocks :type :bytes :repeated true}
   4 {:name :proof :type :bytes}})

(def ^:private block-schema
  {1 {:name :symbols :type :string :repeated true}
   2 {:name :context :type :string}
   3 {:name :version :type :uint32}
   4 {:name :facts :type :bytes :repeated true}
   5 {:name :rules :type :bytes :repeated true}
   6 {:name :checks :type :bytes :repeated true}
   7 {:name :scope :type :bytes :repeated true}
   8 {:name :public-keys :type :bytes :repeated true}})

(def ^:private fact-schema {1 {:name :predicate :type :bytes}})
(def ^:private predicate-schema
  {1 {:name :name :type :uint64}
   2 {:name :terms :type :bytes :repeated true}})
(def ^:private term-schema
  {1 {:name :variable :type :uint32}
   2 {:name :integer :type :int64}
   3 {:name :string :type :uint64}
   4 {:name :date :type :uint64}
   5 {:name :bytes :type :bytes}
   6 {:name :bool :type :bool}})

(def ^:private proof-schema
  {1 {:name :next-secret :type :bytes}
   2 {:name :final-signature :type :bytes}})

(declare signed-payload)

(defn- require-size [label n xs]
  (let [v (vec xs)]
    (when-not (= n (count v))
      (throw (ex-info (str label " must be exactly " n " bytes")
                      {:type :biscuit/invalid-key-material
                       :field label :expected n :actual (count v)})))
    v))

(defn- ordered-distinct [xs]
  (:out (reduce (fn [{:keys [seen] :as acc} x]
                  (if (contains? seen x)
                    acc
                    {:seen (conj seen x) :out (conj (:out acc) x)}))
                {:seen #{} :out []}
                xs)))

(defn- fact-symbols [facts]
  (ordered-distinct
   (mapcat (fn [fact]
             (when-not (and (sequential? fact) (seq fact))
               (throw (ex-info "a biscuit fact must be a non-empty sequence"
                               {:type :biscuit/invalid-fact :fact fact})))
             (let [[head & terms] fact]
               (when-not (or (symbol? head) (string? head))
                 (throw (ex-info "a biscuit fact predicate must be a symbol or string"
                                 {:type :biscuit/invalid-fact :fact fact})))
               (concat [(name head)] (keep #(when (string? %) %) terms))))
           facts)))

(defn- symbol-index [symbols s]
  (or (first (keep-indexed #(when (= s %2) %1) default-symbols))
      (when-let [i (first (keep-indexed #(when (= s %2) %1) symbols))]
        (+ 1024 i))
      (throw (ex-info "symbol was not allocated in this block"
                      {:type :biscuit/missing-symbol :symbol s}))))

(defn- encode-term [symbols x]
  (cond
    (string? x) (pb/encode term-schema {:string (symbol-index symbols x)})
    (integer? x) (pb/encode term-schema {:integer x})
    (boolean? x) (pb/encode term-schema {:bool x})
    (and (vector? x) (= :date (first x)) (= 2 (count x)))
    (pb/encode term-schema {:date (second x)})
    (and (vector? x) (= :bytes (first x)) (= 2 (count x)))
    (pb/encode term-schema {:bytes (vec (second x))})
    :else
    (throw (ex-info "unsupported fact term in the facts-only writer"
                    {:type :biscuit/unsupported-term :term x}))))

(defn encode-authority-block
  "Encode a Biscuit v3 authority block containing facts only.

  Facts use the model shape already consumed by this library, for example
  `'[[scope \"kotoba://graph/acme\"] [before \"2026-09-01T00:00:00Z\"]]`.
  Predicate heads are symbols or strings. Terms may be strings, integers,
  booleans, `[:date unix-seconds]`, or `[:bytes octets]`.

  Rules, checks, expressions and third-party blocks are deliberately not
  accepted here. An issuer needing those must grow the writer and the decoder
  together; silently omitting a restriction would mint more authority than
  the caller requested."
  [facts]
  (let [facts (vec facts)
        symbols (fact-symbols facts)
        encoded-facts
        (mapv (fn [[head & terms]]
                (pb/encode fact-schema
                           {:predicate
                            (pb/encode predicate-schema
                                       {:name (symbol-index symbols (name head))
                                        :terms (mapv #(encode-term symbols %) terms)})}))
              facts)]
    (pb/encode block-schema {:symbols symbols :version 3 :facts encoded-facts})))

(defn encode-authority-token
  "Mint an attenuable Biscuit v3 token with one facts-only authority block.

  `sign-fn` is `(fn [root-private-key payload-bytes] signature-bytes)`.
  Key derivation and randomness stay with the host: the caller supplies a
  fresh 32-byte `next-secret` and its matching 32-byte `next-public-key`.
  Keeping crypto injected is the same boundary as `verify`: Workers, the JVM,
  and an HSM can all use the same canonical writer without this namespace
  pretending to own their key custody.

  The returned value is raw token octets. Its textual HTTP form is URL-safe
  base64, as required by the Biscuit specification."
  [{:keys [root-key-id facts root-private-key next-secret next-public-key sign-fn]}]
  (when-not sign-fn
    (throw (ex-info "a Biscuit writer requires sign-fn"
                    {:type :biscuit/no-signer})))
  (when (and (some? root-key-id)
             (or (neg? root-key-id) (> root-key-id 4294967295)))
    (throw (ex-info "root-key-id must be an unsigned 32-bit integer"
                    {:type :biscuit/invalid-root-key-id :root-key-id root-key-id})))
  (let [next-secret (require-size "next-secret" 32 next-secret)
        next-public-key (require-size "next-public-key" 32 next-public-key)
        block (encode-authority-block facts)
        payload (signed-payload {:version 0 :block block :next-key-alg 0
                                 :next-key next-public-key :order :alg-first})
        signature (require-size "signature" 64 (sign-fn root-private-key payload))
        public-key (pb/encode public-key-schema {:algorithm 0 :key next-public-key})
        authority (pb/encode signed-block-schema
                             {:block block :next-key public-key :signature signature})
        proof (pb/encode proof-schema {:next-secret next-secret})]
    (pb/encode biscuit-schema
               (cond-> {:authority authority :proof proof}
                 (some? root-key-id) (assoc :root-key-id root-key-id)))))

(defn- le32 [n]
  [(bit-and n 0xff) (bit-and (bit-shift-right n 8) 0xff)
   (bit-and (bit-shift-right n 16) 0xff) (bit-and (bit-shift-right n 24) 0xff)])

(defn- marker
  "A v1 payload separator: NUL, the ASCII label, NUL. Built rather than
  written as a literal so the source stays free of control characters."
  [label]
  (into [0] (conj (mapv int label) 0)))

(defn signed-payload
  "The exact bytes a block's signature covers.

  `version` 0 and 1 are the two the spec defines; anything else is refused
  rather than defaulted, because defaulting here means verifying a signature
  over bytes nobody agreed on."
  [{:keys [version block next-key-alg next-key prev-signature order]}]
  (case (long (or version 0))
    0 (vec (concat block
                   (if (= :alg-first order)
                     (concat (le32 next-key-alg) next-key)
                     (concat next-key (le32 next-key-alg)))))
    1 (vec (concat (marker "BLOCK")
                   (marker "VERSION") (le32 1)
                   (marker "PAYLOAD") block
                   (marker "ALGORITHM") (le32 next-key-alg)
                   (marker "NEXTKEY") next-key
                   (when prev-signature
                     (concat (marker "PREVSIG") prev-signature))))
    (throw (ex-info (str "unknown signature payload version " version)
                    {:type :biscuit/unsupported-signature-version :version version}))))

(defn- term [bs table]
  (let [t (pb/decode term-schema bs)]
    (cond
      (contains? t :string) (table (:string t))
      (contains? t :integer) (:integer t)
      (contains? t :bool) (:bool t)
      (contains? t :variable) (symbol (str "?" (table (:variable t))))
      (contains? t :bytes) (:bytes t)
      (contains? t :date) [:date (:date t)]
      :else [:unsupported-term (vec (keys t))])))

(defn- predicate [bs table]
  (let [p (pb/decode predicate-schema bs)]
    (into [(table (:name p))] (map #(term % table)) (:terms p))))

(defn decode-block
  "Block bytes → `{:symbols :facts :rule-count :check-count :version}`.

  `prior-symbols` is every earlier block's additions, because a term index is
  meaningless without the table as of that block."
  [bs prior-symbols]
  (let [b (pb/decode block-schema bs)
        symbols (into (vec prior-symbols) (:symbols b))
        table (fn [i] (if (< i 1024)
                        (get default-symbols i [:reserved i])
                        (get symbols (- i 1024) [:undefined-symbol i])))]
    (when (seq (:public-keys b))
      (throw (ex-info "third-party blocks are not implemented — refused rather than approximated"
                      {:type :biscuit/unsupported})))
    {:version (:version b)
     :context (:context b)
     :own-symbols (vec (:symbols b))
     :symbols symbols
     :facts (mapv (fn [f] (predicate (:predicate (pb/decode fact-schema f)) table))
                  (:facts b))
     :rule-count (count (:rules b))
     :check-count (count (:checks b))}))

(defn decode-token
  "Token bytes → `{:root-key-id :blocks [{:block :next-key :signature …}]}`.

  Structure only: no signature is checked and no Datalog is decoded, so a
  caller can inspect a token it does not trust without running anything."
  [bs]
  (let [t (pb/decode biscuit-schema bs)
        proof (pb/decode proof-schema (:proof t))
        signed (fn [b] (let [sb (pb/decode signed-block-schema b)
                             pk (pb/decode public-key-schema (:next-key sb))]
                         (when (:external-signature sb)
                           (throw (ex-info "external (third-party) signatures are not implemented"
                                           {:type :biscuit/unsupported})))
                         {:block (vec (:block sb))
                          :next-key (vec (:key pk))
                          :next-key-alg (long (or (:algorithm pk) 0))
                          :signature (vec (:signature sb))
                          :version (:version sb)}))]
    {:root-key-id (:root-key-id t)
     :proof (cond
              (:next-secret proof) {:next-secret (vec (:next-secret proof))}
              (:final-signature proof) {:final-signature (vec (:final-signature proof))}
              :else nil)
     :blocks (into [(signed (:authority t))] (map signed) (:blocks t))}))

(defn blocks-with-facts
  "Every block's decoded facts, with the symbol table threaded through."
  [token]
  (:blocks (reduce (fn [{:keys [symbols blocks]} b]
                     (let [d (decode-block (:block b) symbols)]
                       {:symbols (:symbols d)
                        :blocks (conj blocks (merge b d))}))
                   {:symbols [] :blocks []}
                   (:blocks token))))

(defn verify
  "Walk the key chain from `root-public-key`. `verify-fn` is
  `(fn [public-key payload-bytes signature] bool)` — injected, no default.

  Each block is checked against the key the PREVIOUS block named, so a block
  cannot choose the key that validates it."
  [token root-public-key verify-fn & [{:keys [order] :or {order :alg-first}}]]
  (loop [[b & more] (:blocks token) key (vec root-public-key) prev nil i 0]
    (if (nil? b)
      {:ok? true :blocks i}
      (let [payload (signed-payload {:version (:version b) :block (:block b)
                                     :next-key-alg (:next-key-alg b)
                                     :next-key (:next-key b)
                                     :prev-signature prev :order order})]
        (if (verify-fn key payload (:signature b))
          (recur more (:next-key b) (:signature b) (inc i))
          {:ok? false :reason :signature-mismatch :index i})))))

(defn token->model
  "A wire-decoded token in the shape the model namespaces consume.

  `biscuit.authority/->grant`, `biscuit.kotoba/->delegated` and
  `biscuit.effective/authorize` all read `{:biscuit/blocks [{:block/facts …}]}`
  with **symbol** predicate heads, because that is what a hand-written token
  looks like. A wire token's heads arrive as strings out of the symbol table.

  Bridging here rather than teaching every consumer both shapes is the point:
  without it a server accepts only tokens in a shape no other implementation
  produces, and routing that would enshrine it.

  Signature verification is NOT done here and must not be inferred from a
  successful conversion — `verify` is a separate call, and a caller that
  converts without verifying has decoded an attacker's facts."
  [token]
  {:biscuit/version version
   :biscuit/blocks
   (mapv (fn [b]
           {:block/index (:index b)
            :block/facts (mapv (fn [f]
                                 (into [(if (string? (first f)) (symbol (first f)) (first f))]
                                       (rest f)))
                               (:facts b))
            :block/rule-count (:rule-count b)
            :block/check-count (:check-count b)
            :block/next-public-key (:next-key b)
            :block/signature (:signature b)})
         (map-indexed #(assoc %2 :index %1) (blocks-with-facts token)))})

(defn revocation-ids
  "`[[index signature-bytes] …]` — the token's revocation identifiers.

  Per the spec: a block's revocation identifier **is its signature**, because
  the signature uniquely identifies that block. So revoking a token means
  publishing a signature, and checking is a set membership test that needs no
  parsing of what the token says.

  Two properties fall out and both matter here:

  - **A revocation identifies a token's TAIL, not its holder.** Revoking the
    authority block's id kills every token derived from it; revoking a later
    block's id kills only the attenuations that carry it. That is the right
    granularity for a delegation chain and it comes free.
  - **It needs no clock and no issuer contact.** A verifier holding the set
    can refuse offline, which is the property the rest of this library is
    built around — `biscuit.rootkey` removed the issuer from key discovery,
    and this removes it from revocation.

  What this namespace does NOT do is decide where the set comes from. Root
  ADR-2608180200 puts that on the planes that already carry monotonic signed
  state — `kototama.component-authority`'s epoch feed and aiueos's capability
  generations — rather than inventing a revocation list nobody serves."
  [token]
  (vec (map-indexed (fn [i b] [i (vec (:signature b))]) (:blocks token))))

(defn revoked?
  "Is any of this token's blocks revoked by `revoked-set`?

  `revoked-set` holds signature byte-vectors. Answering on ANY block rather
  than only the last is the point: an attenuated token still carries its
  parent's signature, so revoking a parent revokes everything derived from
  it without the revoker needing to know what was derived."
  [token revoked-set]
  (boolean (some (fn [[_ sig]] (contains? (set revoked-set) sig))
                 (revocation-ids token))))

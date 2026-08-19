(ns biscuit.wire
  "The biscuit v3 wire format — enough of it to **verify a token minted by
  `biscuit-auth`**, checked against that project's own samples.

  Until this existed, `org-biscuitsec` held the model and could not read a
  byte another implementation produced. That is a real limit and the README
  said so; this is the half that removes it, and it is deliberately the
  *reading* half. A writer whose output nothing external has accepted is the
  claim `org-apache-parquet` learned to distrust from inside its own passing
  suite.

  ## What is implemented, and what is refused by name

  | | |
  |---|---|
  | container (`Biscuit`/`SignedBlock`/`PublicKey`/`Proof`) | **yes** |
  | block structure, symbol table, facts, predicates, terms | **yes** |
  | signature payload **v0 and v1**, chained public keys | **yes** |
  | rules, checks | counted, not decoded |
  | **expressions** (`Op`/`OpUnary`/`OpBinary`/`OpClosure`) | **refused by name** |
  | third-party (`externalSignature`) blocks | **refused by name** |
  | writing tokens | **not implemented** |

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

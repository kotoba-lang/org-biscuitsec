(ns biscuit.kotoba
  "A verified biscuit as the **delegated** term of Kotoba's effective scope.

  `kotoba-lang/kotoba-lang`'s `lang/capability-semantics.edn` already defines
  the shape of an answer:

      :effective-scope  :requested-intersect-delegated-intersect-local-policy
      :scope-attenuation-only  true
      :unknown-kind  :deny
      :missing-grant :deny

  Three of those four terms already have owners — `requested` is what the
  guarded call asks for, `local-policy` is the host's, and the rules are the
  language's. **`delegated` had no wire.** This namespace is that wire, and
  it is the concrete meaning of \"biscuit is the delegation centre\": not
  that biscuit replaces the semantics, but that it is what fills the one slot
  the semantics left open.

  ## It maps into `:grant/*`, not into `:cap/*`

  A capability (`:cap/kind`, `:cap/resource`, `:cap/holder`) is authority a
  handler receives *after* intersection. A grant (`:grant/kind`,
  `:grant/resources`, `:grant/expires`, `:grant/id`) is what a delegation
  confers *before* it. A token that produced capabilities directly would be a
  token that skipped the intersection — which is the one step the semantics
  says is not optional.

  ## Unknown kinds deny, and that is the interesting direction

  `:kinds` in the semantics is a **closed set**. A biscuit fact naming a kind
  outside it is not ignored (which would silently drop a restriction the
  issuer intended) and does not throw (a token from a newer fleet is an
  ordinary event). It lands in `:grant/rejected`, and a rejected kind confers
  nothing — so the failure is toward less authority, and it is visible."
  (:require [authority.scope :as scope]
            [clojure.set :as set]
            [clojure.string :as str]))

(defn- fact->kind [v]
  (when (string? v)
    (if (str/starts-with? v ":") (keyword (subs v 1)) (keyword v))))

(defn- narrow
  "The resources both blocks confer — scopes met in the lattice, opaque names
  intersected.

  ## Why this is not `set/intersection`

  It was, and that made the ordinary act of attenuating a wildcard produce a
  token reaching nothing:

      block 0   cap graph-read kotoba://graph/*
      block 1   cap graph-read kotoba://graph/g1

  Those two strings intersect to the EMPTY SET, so narrowing a namespace
  grant down to one member — the operation Biscuit is chosen for — silently
  destroyed the grant instead of narrowing it. Measured 2026-08-31 by a
  consumer (`network-awai/app-hyakka`), which had to fold per block against
  `authority.chain` to get a correct answer out of this namespace.

  `biscuit.authority/->grant`, ten lines away in this same library, has
  always folded with `authority.grant/meet`. So the library held **two**
  answers to *what do two blocks jointly confer* and only one of them was
  the lattice. That is exactly what `authority` exists to prevent, and its
  own docstring here says adding biscuits must add no new answer to *does
  this cover that*. This removes the second answer rather than adding a
  third.

  ## Why string identity survives for the rest

  `:cap/resource` is not always a scope. `[cap \"infer\" \"murakumo-main\"]`
  names a model alias, and an opaque name has exactly one relation available
  to it — identity. Parsing partitions the set, so the two rules never apply
  to the same member: a resource the lattice can read is met, one it cannot
  is intersected, and one that parses on only ONE side relates to nothing
  and is therefore dropped. Every branch narrows; none can widen."
  [earlier later]
  (let [split (fn [rs] (let [{:keys [scopes rejected]} (scope/parse-all rs)]
                         [scopes (set rejected)]))
        [ea eo] (split earlier)
        [la lo] (split later)]
    (into (set (keep scope/render (scope/meet-sets ea la)))
          (set/intersection eo lo))))

(defn ->delegated
  "Verified token + the semantics' `:kinds` set -> Kotoba grants.

  -> `{:grants [{:grant/kind :grant/resources :grant/expires :grant/id} …]
       :grant/rejected [...]}`

  Facts read: `[cap <kind> <resource>]` and `[before <instant>]`. Everything
  else stays available to checks and policies and confers nothing — the same
  one-directional ignorance `biscuit.authority` documents, for the same
  reason: **an unread fact cannot widen a grant.**

  Blocks fold in order and later blocks may only narrow — never add a kind,
  never widen a resource. `:scope-attenuation-only true` is not a convention
  this honours, it is the only thing this function can express.

  **Narrowing is `authority`'s, not string identity's** (see `narrow`). A
  later block naming `kotoba://graph/g1` under `kotoba://graph/*` yields
  `kotoba://graph/g1`, which is what attenuating a namespace grant is FOR;
  until 2026-08-31 those two strings intersected to nothing and the ordinary
  act of narrowing destroyed the grant instead."
  [t kinds]
  (let [blocks (:biscuit/blocks t)
        rejected (atom [])
        per-block
        (for [b blocks]
          (let [caps (keep (fn [[p k r]] (when (= 'cap p) [(fact->kind k) r]))
                           (:block/facts b))
                grouped (reduce (fn [acc [k r]]
                                  (if (contains? kinds k)
                                    (update acc k (fnil conj #{}) r)
                                    (do (swap! rejected conj {:kind k :resource r}) acc)))
                                {} caps)]
            grouped))
        folded (reduce (fn [acc block]
                         (if (empty? block)
                           acc
                           (if (empty? acc)
                             block
                             ;; A later block narrows: kinds it does not
                             ;; mention are dropped, resources it does mention
                             ;; are narrowed. It can never introduce a kind.
                             ;; A kind that narrows to NOTHING is dropped, not
                             ;; carried as a grant with an empty resource set.
                             ;; Both confer nothing, but only one of them lets
                             ;; `missing-grant?` tell the truth -- and
                             ;; `:missing-grant :deny` is supposed to reach
                             ;; every token that delegates nothing, through the
                             ;; ordinary path rather than a special case.
                             (into {} (keep (fn [[k rs]]
                                              (when-let [later (get block k)]
                                                (let [n (narrow rs later)]
                                                  (when (seq n) [k n])))))
                                   acc))))
                       {} per-block)
        authority-facts (get-in t [:biscuit/blocks 0 :block/facts])
        holders (into #{} (keep (fn [[p v]] (when (= 'holder p) v))) authority-facts)
        befores (keep (fn [[p v]] (when (= 'before p) v))
                      (mapcat :block/facts blocks))
        expires (when (seq befores) (reduce (fn [a b] (if (neg? (compare a b)) a b)) befores))]
    {:grants (vec (for [[k rs] folded]
                    (cond-> {:grant/kind k
                             :grant/resources (vec (sort rs))
                             :grant/id (str "biscuit:" (hash [k (sort rs)]))}
                      expires (assoc :grant/expires expires))))
     :grant/holder (when (= 1 (count holders)) (first holders))
     :grant/rejected @rejected}))

(defn missing-grant?
  "`:missing-grant :deny` — a token that delegates nothing denies everything,
  through the ordinary path rather than a sentinel."
  [{:keys [grants]}]
  (empty? grants))

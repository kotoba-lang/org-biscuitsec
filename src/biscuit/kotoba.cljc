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
  (:require [clojure.set :as set]
            [clojure.string :as str]))

(defn- fact->kind [v]
  (when (string? v)
    (if (str/starts-with? v ":") (keyword (subs v 1)) (keyword v))))

(defn ->delegated
  "Verified token + the semantics' `:kinds` set -> Kotoba grants.

  -> `{:grants [{:grant/kind :grant/resources :grant/expires :grant/id} …]
       :grant/rejected [...]}`

  Facts read: `[cap <kind> <resource>]` and `[before <instant>]`. Everything
  else stays available to checks and policies and confers nothing — the same
  one-directional ignorance `biscuit.authority` documents, for the same
  reason: **an unread fact cannot widen a grant.**

  Blocks fold in order and later blocks may only remove resources from a kind
  they already have, never add a kind — `:scope-attenuation-only true` is not
  a convention this honours, it is the only thing this function can express."
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
                             ;; are intersected. It can never introduce a kind.
                             (into {} (keep (fn [[k rs]]
                                              (when-let [later (get block k)]
                                                [k (set/intersection rs later)]))
                                            acc)))))
                       {} per-block)
        befores (keep (fn [[p v]] (when (= 'before p) v))
                      (mapcat :block/facts blocks))
        expires (when (seq befores) (reduce (fn [a b] (if (neg? (compare a b)) a b)) befores))]
    {:grants (vec (for [[k rs] folded]
                    (cond-> {:grant/kind k
                             :grant/resources (vec (sort rs))
                             :grant/id (str "biscuit:" (hash [k (sort rs)]))}
                      expires (assoc :grant/expires expires))))
     :grant/rejected @rejected}))

(defn missing-grant?
  "`:missing-grant :deny` — a token that delegates nothing denies everything,
  through the ordinary path rather than a sentinel."
  [{:keys [grants]}]
  (empty? grants))

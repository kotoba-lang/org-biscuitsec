(ns biscuit.authorizer
  "Run the token's checks and the verifier's policies, in that order.

  A biscuit says two different things and conflating them is the classic
  error:

  - **checks** live in the token and must all pass. They are what the holder
    (and everyone who attenuated after) restricted themselves to.
  - **policies** live in the *authorizer* — the verifier's own rules — and
    the first one that matches decides. They are what the service allows.

  So a token cannot allow itself: **there is no `allow` inside a token.** A
  token with no checks is maximally permissive *as a token*, and still gets
  whatever the authorizer's policies grant, which may be nothing.

  ## Deny is the default and it is not a policy

  If no policy matches, the answer is `:no-policy-matched`, not `:deny`.
  Both refuse, and distinguishing them is what tells an operator that their
  policy set has a hole rather than that their rule fired."
  (:require [biscuit.datalog :as d]
            [biscuit.token :as token]))

(defn- run-block-checks
  [t index authorizer-facts budget]
  (let [{:keys [facts rules]} (token/scope t index)
        sat (d/saturate (concat facts authorizer-facts) rules budget)]
    (if (:refused sat)
      {:refused (:refused sat) :index index :detail (dissoc sat :refused)}
      (let [checks (get-in t [:biscuit/blocks index :block/checks])
            failed (into [] (remove #(d/satisfied? (:facts sat) (:body %)) checks))]
        {:failed failed :index index}))))

(defn authorize
  "`{:allowed? bool :reason kw …}`.

  `authorizer` is `{:facts [...] :rules [...] :policies [{:kind :allow|:deny
  :body [...]} ...]}` — the verifier's own knowledge, which is never in the
  token. `:policy-token-facts? false` keeps token facts and rules out of policy
  saturation while still evaluating every token check in its scoped block.
  This is required when an adapter projects verified token authority into a
  narrower provenance such as `grant:`: a token must not impersonate trusted
  compiler, local-policy, or runtime predicates. The default is true for the
  ordinary Biscuit authorizer surface.

  Order is fixed and load-bearing: **verify, then checks, then policies.**
  Running policies first would let a token whose signature does not verify
  reach a rule that says `allow`."
  [t {:keys [root-public-key verify-fn facts rules policies budget
             policy-token-facts?]
      :or {budget d/default-budget policy-token-facts? true}}]
  (let [v (token/verify t root-public-key verify-fn)]
    (if-not (:ok? v)
      {:allowed? false :reason (:reason v) :verified? false}
      (let [n (count (:biscuit/blocks t))
            results (mapv #(run-block-checks t % facts budget) (range n))
            refused (first (filter :refused results))
            failed (mapcat :failed results)]
        (cond
          refused
          {:allowed? false :reason (:refused refused) :verified? true
           :block (:index refused)}

          (seq failed)
          {:allowed? false :reason :check-failed :verified? true
           :failed (vec failed)}

          :else
          ;; Policies see the authorizer's facts plus the WHOLE token's facts:
          ;; the service is deciding about the token as presented, and it is
          ;; the party that wrote these rules.
          (let [all (into (vec facts)
                          (when policy-token-facts?
                            (mapcat :block/facts (:biscuit/blocks t))))
                all-rules (into (vec rules)
                                (when policy-token-facts?
                                  (mapcat :block/rules (:biscuit/blocks t))))
                sat (d/saturate all all-rules budget)]
            (if (:refused sat)
              {:allowed? false :reason (:refused sat) :verified? true}
              (if-let [hit (first (filter #(d/satisfied? (:facts sat) (:body %)) policies))]
                {:allowed? (= :allow (:kind hit)) :verified? true
                 :reason (if (= :allow (:kind hit)) :allowed-by-policy :denied-by-policy)
                 :policy hit}
                {:allowed? false :verified? true :reason :no-policy-matched}))))))))

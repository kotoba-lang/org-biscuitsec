(ns biscuit.effective
  "The guarded call: `requested ∩ delegated ∩ local-policy`, decided at an
  edge that holds no secret.

  This is the slice that makes biscuit the delegation **centre** rather than
  a library that could be one. `biscuit.kotoba/->delegated` produces the term
  the language's semantics left open; this consumes it and answers the
  question a host actually asks — *may this call proceed* — under the rules
  `kotoba-lang/kotoba-lang`'s `lang/capability-semantics.edn` declares.

  ## The rules are read, not restated

  `authorize` takes the semantics map as an argument and **branches on its
  `:rules`**. Copying `:unknown-kind :deny` into a `case` here would make
  this a second statement of the language's policy, and the fleet has
  measured what a second statement costs (`authority.scope`: `covers?`
  written once per scheme, one copy comparing with `starts-with?`). A test
  loads the real file and fails when the rule set changes shape.

  ## Every attempt is receipted, including the denials

  `:attempt-always-receipted true` is in the semantics, and it is the reason
  this returns a receipt on **every** path rather than only on success. A
  guard that logs what it allowed and forgets what it refused cannot answer
  the only question an incident asks.

  ## No secret, anywhere

  The whole decision needs the token, the root **public** key, the local
  policy and a clock. There is no branch that needs a private key, which is
  what lets this run in a Worker, a browser or on an untrusted mirror — and
  is the entire reason the centre is biscuit rather than macaroon."
  (:require [biscuit.kotoba :as bk]
            [biscuit.token :as bt]))

(def receipt-keys
  "What `:receipt-requirements` names. Kept as data so the test can compare
  it to the semantics file rather than to a docstring."
  [:receipt/cap :receipt/at :receipt/call :receipt/outcome])

(defn- receipt [{:keys [now call cap outcome detail]}]
  (cond-> {:receipt/at now :receipt/call call
           :receipt/cap cap :receipt/outcome outcome}
    detail (assoc :receipt/detail detail)))

(defn- wildcard? [x] (or (= :any x) (= "*" x) (= :* x)))

(defn authorize
  "Decide one guarded call.

  `{:semantics <capability-semantics map> :token t :root-public-key pk
    :verify-fn f :requested {:cap/kind k :cap/resource r} :local-policy p
    :now instant :call name}`

  -> `{:allowed? bool :reason kw :capability {…}|nil :receipt {…}}`

  The capability is only present when allowed, and it is the **concrete
  post-intersection** one (`:handler-receives`), never the token's claim."
  [{:keys [semantics token root-public-key verify-fn requested local-policy now call]}]
  (let [rules (:rules semantics)
        kinds (:kinds semantics)
        {:cap/keys [kind resource]} requested
        deny (fn [reason & [detail]]
               {:allowed? false :reason reason :capability nil
                :receipt (receipt {:now now :call call :cap requested
                                   :outcome :denied :detail (or detail reason)})})
        v (bt/verify token root-public-key verify-fn)]
    (cond
      (not (:ok? v))
      (deny (:reason v))

      ;; Language semantics v2 adds trusted Amu and runtime-availability
      ;; origins. This legacy three-term entry point cannot prove either and
      ;; must not silently implement a weaker reading of the newer contract.
      (= :statically-possible-intersect-requested-intersect-delegated-intersect-local-policy-intersect-runtime-available
         (:effective-scope rules))
      (deny :logic-authorizer-required)

      ;; :plain-resource-is-not-authority — a request naming a resource with
      ;; no kind is not a weaker request, it is not a request.
      (and (:plain-resource-is-not-authority rules) (nil? kind))
      (deny :plain-resource-is-not-authority)

      (and (= :deny (:unknown-kind rules)) (not (contains? kinds kind)))
      (deny :unknown-kind)

      :else
      (let [{:keys [grants]} (bk/->delegated token kinds)
            matching (filter #(= kind (:grant/kind %)) grants)]
        (cond
          (and (= :deny (:missing-grant rules)) (empty? matching))
          (deny :missing-grant)

          (and (= :deny (:expired-grant rules))
               (every? (fn [g] (let [e (:grant/expires g)]
                                 (or (nil? now) (and e (not (neg? (compare now e)))))))
                       matching))
          (deny :expired-grant)

          :else
          (let [live (filter (fn [g] (let [e (:grant/expires g)]
                                       (or (nil? e) (neg? (compare now e)))))
                             matching)
                delegated (into #{} (mapcat :grant/resources) live)
                allowed (into #{} (:policy/allow local-policy))
                ;; requested ∩ delegated ∩ local-policy, in that order and
                ;; with no step skippable.
                effective (cond-> (if (contains? delegated resource) #{resource} #{})
                            true (as-> s (if (or (contains? allowed resource)
                                                 (some wildcard? allowed))
                                           s #{})))]
            (cond
              (and (:policy/forbid-wildcard local-policy)
                   (or (some wildcard? delegated) (wildcard? resource)))
              (deny :production-effective-wildcard)

              (and (= :deny (:empty-intersection rules)) (empty? effective))
              (deny :empty-intersection)

              :else
              (let [cap {:cap/kind kind :cap/resource resource
                         :cap/holder (:cap/holder requested)
                         :cap/provenance :biscuit}]
                {:allowed? true :reason :granted :capability cap
                 :receipt (receipt {:now now :call call :cap cap
                                    :outcome :allowed})}))))))))

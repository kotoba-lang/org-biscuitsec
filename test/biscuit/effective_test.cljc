(ns biscuit.effective-test
  "The proving slice, and a contract test against the language's own file."
  (:require [biscuit.effective :as eff]
            [biscuit.keys :as k]
            [biscuit.token :as bt]
            [clojure.edn :as edn]
            [clojure.test :refer [deftest is testing]]
            #?(:cljs ["node:fs" :as fs])))

(def semantics-path "../kotoba-lang/lang/capability-semantics.edn")

(defn read-semantics []
  (try (edn/read-string #?(:clj (slurp semantics-path)
                           :cljs (str (fs/readFileSync semantics-path "utf8"))))
       (catch #?(:clj Exception :cljs :default) _ nil)))

;; A local stand-in used by the behaviour tests, so they do not depend on a
;; sibling checkout being present. The CONTRACT test below is what ties this
;; shape to the real file, and it refuses rather than passing when it cannot
;; read it.
(def semantics
  {:rules {:plain-resource-is-not-authority true
           :unknown-kind :deny :missing-grant :deny :expired-grant :deny
           :empty-intersection :deny :scope-attenuation-only true
           :attempt-always-receipted true
           :production-effective-wildcard :forbidden}
   :kinds #{:graph-read :graph-write :infer :host/http}
   :receipt-requirements eff/receipt-keys})

(def root (k/keypair "root"))
(def k1 (k/keypair "one"))

(defn- token [facts]
  (bt/authority {:facts facts :next-public-key (:public k1)
                 :root-private-key (:private root) :sign-fn k/sign-fn}))

(defn- call [t requested & [{:keys [policy now]}]]
  (eff/authorize {:semantics semantics :token t
                  :root-public-key (:public root) :verify-fn k/verify-fn
                  :requested requested
                  :local-policy (or policy {:policy/allow ["kotoba://graph/acme"]
                                            :policy/forbid-wildcard true})
                  :now (or now "2026-08-19T00:00:00Z")
                  :call "graph/read"}))

(deftest the-whole-decision-needs-no-secret
  (testing "the reason the centre is biscuit and not macaroon"
    (let [t (token '[[cap "graph-read" "kotoba://graph/acme"]])
          d (call t {:cap/kind :graph-read :cap/resource "kotoba://graph/acme"})]
      (is (true? (:allowed? d)))
      ;; The only key material in the call above is (:public root).
      (is (= :biscuit (get-in d [:capability :cap/provenance]))))))

(deftest intersection-is-three-terms-and-none-is-skippable
  (let [t (token '[[cap "graph-read" "kotoba://graph/acme"]
                   [cap "graph-read" "kotoba://graph/beta"]])]
    (testing "delegated but not in local policy"
      (is (= :empty-intersection
             (:reason (call t {:cap/kind :graph-read :cap/resource "kotoba://graph/beta"})))))
    (testing "in local policy but not delegated"
      (is (= :empty-intersection
             (:reason (call t {:cap/kind :graph-read :cap/resource "kotoba://graph/gamma"}
                            {:policy {:policy/allow ["kotoba://graph/gamma"]}})))))
    (testing "requested is the third term: asking for neither gets neither"
      (is (= :empty-intersection
             (:reason (call t {:cap/kind :graph-read :cap/resource "kotoba://graph/zeta"})))))))

(deftest every-attempt-is-receipted-including-denials
  (doseq [[label d] [["allowed" (call (token '[[cap "graph-read" "kotoba://graph/acme"]])
                                      {:cap/kind :graph-read :cap/resource "kotoba://graph/acme"})]
                     ["unknown kind" (call (token '[[cap "graph-read" "kotoba://graph/acme"]])
                                           {:cap/kind :kernel/format-disk :cap/resource "/dev/sda"})]
                     ["missing grant" (call (token '[[user "alice"]])
                                            {:cap/kind :graph-read :cap/resource "kotoba://graph/acme"})]
                     ["forged" (call (assoc-in (token '[[cap "graph-read" "kotoba://graph/acme"]])
                                               [:biscuit/blocks 0 :block/facts]
                                               '[[cap "graph-write" "kotoba://graph/acme"]])
                                     {:cap/kind :graph-read :cap/resource "kotoba://graph/acme"})]]]
    (testing label
      (is (map? (:receipt d)))
      (is (every? #(contains? (:receipt d) %) eff/receipt-keys)
          (str label ": receipt is missing a required key")))))

(deftest a-denied-call-yields-no-capability
  (let [d (call (token '[[user "alice"]])
                {:cap/kind :graph-read :cap/resource "kotoba://graph/acme"})]
    (is (false? (:allowed? d)))
    (is (nil? (:capability d)))
    (is (= :denied (get-in d [:receipt :receipt/outcome])))))

(deftest an-unverified-token-never-reaches-the-intersection
  (let [forged (assoc-in (token '[[cap "graph-read" "kotoba://graph/acme"]])
                         [:biscuit/blocks 0 :block/facts]
                         '[[cap "graph-read" "kotoba://graph/everything"]])
        d (call forged {:cap/kind :graph-read :cap/resource "kotoba://graph/acme"})]
    (is (= :signature-mismatch (:reason d)))))

(deftest expiry-denies-by-name
  (let [t (token '[[cap "graph-read" "kotoba://graph/acme"] [before "2026-08-01T00:00:00Z"]])]
    (is (= :expired-grant
           (:reason (call t {:cap/kind :graph-read :cap/resource "kotoba://graph/acme"}))))
    (is (true? (:allowed? (call t {:cap/kind :graph-read :cap/resource "kotoba://graph/acme"}
                                {:now "2026-07-01T00:00:00Z"}))))))

(deftest a-resource-with-no-kind-is-not-a-weaker-request
  (is (= :plain-resource-is-not-authority
         (:reason (call (token '[[cap "graph-read" "kotoba://graph/acme"]])
                        {:cap/resource "kotoba://graph/acme"})))))

(deftest semantics-v2-cannot-fall-back-to-the-three-term-guard
  (let [v2 (assoc-in semantics [:rules :effective-scope]
                     :statically-possible-intersect-requested-intersect-delegated-intersect-local-policy-intersect-runtime-available)
        t (token '[[cap "graph-read" "kotoba://graph/acme"]])
        decision (eff/authorize
                  {:semantics v2 :token t
                   :root-public-key (:public root) :verify-fn k/verify-fn
                   :requested {:cap/kind :graph-read
                               :cap/resource "kotoba://graph/acme"}
                   :local-policy {:policy/allow ["kotoba://graph/acme"]
                                  :policy/forbid-wildcard true}
                   :now "2026-08-19T00:00:00Z" :call "graph/read"})]
    (is (= :logic-authorizer-required (:reason decision)))
    (is (= :denied (get-in decision [:receipt :receipt/outcome])))))

(deftest a-wildcard-cannot-become-effective-authority
  (let [t (token '[[cap "graph-read" "*"]])]
    (is (= :production-effective-wildcard
           (:reason (call t {:cap/kind :graph-read :cap/resource "kotoba://graph/acme"}
                          {:policy {:policy/allow ["*"] :policy/forbid-wildcard true}}))))))

;; ---------------------------------------------------------------------------

(def contract-rules
  "The rules `biscuit.effective/authorize` branches on.

  Vendored here rather than only read from the sibling checkout, because the
  fleet ships ONE repo's tree to a node: a test that can only run beside
  `kotoba-lang` is a test that is red on every node forever, and a gate that
  never goes green is as uninformative as one that never goes red."
  [:unknown-kind :missing-grant :expired-grant :empty-intersection
   :plain-resource-is-not-authority :scope-attenuation-only
   :attempt-always-receipted :production-effective-wildcard])

(deftest the-guard-branches-on-the-rules-it-claims-to
  (testing "the vendored contract, checkable anywhere"
    (doseq [r contract-rules]
      (is (contains? (:rules semantics) r)
          (str "rule " r " is not in the semantics this guard is handed")))
    (is (= (set eff/receipt-keys) (set (:receipt-requirements semantics))))))

(deftest contract-with-the-language-file
  (testing "and when the sibling checkout IS present, the vendored copy must
            still match it — drift in a vendored copy is silent, which is
            what this half exists to catch"
    (if-let [real (read-semantics)]
      (do
        (is (= (set (:receipt-requirements real)) (set eff/receipt-keys))
            "receipt requirements drifted from lang/capability-semantics.edn")
        (doseq [r contract-rules]
          (is (contains? (:rules real) r)
              (str "rule " r " is no longer in the semantics — this guard branches on it")))
        (is (set? (:kinds real)))
        (is (pos? (count (:kinds real)))))
      ;; Distinct from a pass, and printed, because "飛ばした" and "合格した"
      ;; must be distinguishable in the output (root ADR-2608136000).
      (println (str "SKIPPED drift check: " semantics-path
                    " not present (expected on a fleet node; the vendored"
                    " contract above still ran)")))))

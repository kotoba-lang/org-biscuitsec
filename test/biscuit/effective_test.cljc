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

(deftest a-wildcard-cannot-become-effective-authority
  (let [t (token '[[cap "graph-read" "*"]])]
    (is (= :production-effective-wildcard
           (:reason (call t {:cap/kind :graph-read :cap/resource "kotoba://graph/acme"}
                          {:policy {:policy/allow ["*"] :policy/forbid-wildcard true}}))))))

;; ---------------------------------------------------------------------------

(deftest contract-with-the-language-file
  (testing "the rules this implementation branches on are the ones the
            semantics declares — and an unreadable file REFUSES rather than
            passing, because a contract test that cannot see the contract has
            not checked one"
    (if-let [real (read-semantics)]
      (do
        (is (= (set (:receipt-requirements real)) (set eff/receipt-keys))
            "receipt requirements drifted from lang/capability-semantics.edn")
        (doseq [r [:unknown-kind :missing-grant :expired-grant :empty-intersection
                   :plain-resource-is-not-authority :scope-attenuation-only
                   :attempt-always-receipted :production-effective-wildcard]]
          (is (contains? (:rules real) r)
              (str "rule " r " is no longer in the semantics — this guard branches on it")))
        (is (set? (:kinds real)))
        (is (pos? (count (:kinds real)))))
      (is false (str "could not read " semantics-path
                     " — run from a checkout where kotoba-lang is a sibling")))))

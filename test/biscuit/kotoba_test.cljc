(ns biscuit.kotoba-test
  (:require [authority.scope :as scope]
            [biscuit.authority :as ba]
            [biscuit.keys :as k]
            [biscuit.kotoba :as bk]
            [biscuit.token :as bt]
            [clojure.test :refer [deftest is testing]]))

(def root (k/keypair "root"))
(def k1 (k/keypair "one"))
(def kinds #{:graph-read :graph-write :host/http :infer})

(defn- tok [facts] (bt/authority {:facts facts :next-public-key (:public k1)
                                  :root-private-key (:private root) :sign-fn k/sign-fn}))

(deftest facts-become-grants-not-capabilities
  (let [d (bk/->delegated (tok '[[cap "graph-read" "kotoba://graph/acme"]
                                 [cap "graph-read" "kotoba://graph/beta"]
                                 [before "2026-09-01T00:00:00Z"]])
                          kinds)
        g (first (:grants d))]
    (is (= 1 (count (:grants d))))
    (is (= :graph-read (:grant/kind g)))
    (is (= ["kotoba://graph/acme" "kotoba://graph/beta"] (:grant/resources g)))
    (is (= "2026-09-01T00:00:00Z" (:grant/expires g)))
    (testing "grants, never :cap/* — the intersection step is not optional"
      (is (nil? (:cap/kind g))))))

(deftest the-authority-block-binds-the-holder
  (let [d (bk/->delegated (tok '[[holder "did:key:zAlice"]
                                 [cap "graph-read" "kotoba://graph/acme"]])
                          kinds)]
    (is (= "did:key:zAlice" (:grant/holder d)))))

(deftest a-kind-outside-the-closed-set-is-rejected-not-ignored
  (let [d (bk/->delegated (tok '[[cap "graph-read" "kotoba://graph/acme"]
                                 [cap "kernel/format-disk" "/dev/sda"]])
                          kinds)]
    (is (= 1 (count (:grants d))))
    (is (= [{:kind :kernel/format-disk :resource "/dev/sda"}] (:grant/rejected d)))
    (testing "the failure is toward LESS authority, and it is visible"
      (is (not-any? #(= :kernel/format-disk (:grant/kind %)) (:grants d))))))

(deftest a-later-block-cannot-introduce-a-kind
  (let [t (-> (tok '[[cap "graph-read" "kotoba://graph/acme"]])
              (bt/append {:facts '[[cap "graph-write" "kotoba://graph/acme"]
                                   [cap "graph-read" "kotoba://graph/acme"]]
                          :next-public-key (:public k1)
                          :private-key (:private k1) :sign-fn k/sign-fn}))
        d (bk/->delegated t kinds)]
    (testing ":scope-attenuation-only is the only thing this can express"
      (is (= [:graph-read] (mapv :grant/kind (:grants d)))))))

(deftest a-later-block-narrows-resources
  (let [t (-> (tok '[[cap "graph-read" "kotoba://graph/acme"]
                     [cap "graph-read" "kotoba://graph/beta"]])
              (bt/append {:facts '[[cap "graph-read" "kotoba://graph/acme"]]
                          :next-public-key (:public k1)
                          :private-key (:private k1) :sign-fn k/sign-fn}))]
    (is (= ["kotoba://graph/acme"] (:grant/resources (first (:grants (bk/->delegated t kinds))))))))

(deftest a-block-that-drops-a-kind-drops-it
  (let [t (-> (tok '[[cap "graph-read" "kotoba://graph/acme"]
                     [cap "host/http" "https://example.com"]])
              (bt/append {:facts '[[cap "graph-read" "kotoba://graph/acme"]]
                          :next-public-key (:public k1)
                          :private-key (:private k1) :sign-fn k/sign-fn}))]
    (is (= [:graph-read] (mapv :grant/kind (:grants (bk/->delegated t kinds)))))))

(deftest delegating-nothing-denies-everything
  (testing ":missing-grant :deny, through the ordinary path"
    (is (true? (bk/missing-grant? (bk/->delegated (tok '[[user "alice"]]) kinds))))
    (is (false? (bk/missing-grant? (bk/->delegated (tok '[[cap "infer" "murakumo-main"]]) kinds))))))

(deftest the-tightest-expiry-wins-across-blocks
  (let [t (-> (tok '[[cap "infer" "murakumo-main"] [before "2026-09-01T00:00:00Z"]])
              (bt/append {:facts '[[cap "infer" "murakumo-main"] [before "2027-01-01T00:00:00Z"]]
                          :next-public-key (:public k1)
                          :private-key (:private k1) :sign-fn k/sign-fn}))]
    (is (= "2026-09-01T00:00:00Z" (:grant/expires (first (:grants (bk/->delegated t kinds))))))))

;; ── narrowing is the lattice's, not string identity's ────────────────────────

(defn- append [t facts]
  (bt/append t {:facts facts :next-public-key (:public k1)
                :private-key (:private k1) :sign-fn k/sign-fn}))

(defn- resources [t] (:grant/resources (first (:grants (bk/->delegated t kinds)))))

(deftest a-wildcard-narrowed-to-a-member-is-that-member
  (testing "the act Biscuit is chosen for, which set/intersection destroyed"
    ;; "kotoba://graph/*" INTERSECT "kotoba://graph/g1" is the empty set, so
    ;; the previous fold turned an ordinary attenuation into a token reaching
    ;; nothing. Found 2026-08-31 by a consumer that had to fold per block
    ;; against authority.chain to get a correct answer out of this namespace.
    (let [t (-> (tok '[[cap "graph-read" "kotoba://graph/*"]])
                (append '[[cap "graph-read" "kotoba://graph/g1"]]))]
      (is (= ["kotoba://graph/g1"] (resources t)))))
  (testing "and it still cannot widen"
    (let [t (-> (tok '[[cap "graph-read" "kotoba://graph/g1"]])
                (append '[[cap "graph-read" "kotoba://graph/*"]]))]
      (is (= ["kotoba://graph/g1"] (resources t))
          "a later block asking for the namespace gets only what it was given")))
  (testing "and a sibling it was never granted is not reachable"
    (let [t (-> (tok '[[cap "graph-read" "kotoba://graph/g1"]])
                (append '[[cap "graph-read" "kotoba://graph/g2"]]))]
      (is (nil? (resources t))
          "two incomparable scopes have no common lower bound, so the kind drops"))))

(deftest an-opaque-resource-still-narrows-by-identity
  (testing "`:cap/resource` is not always a scope — a model alias has only identity"
    (let [t (-> (tok '[[cap "infer" "murakumo-main"] [cap "infer" "other-model"]])
                (append '[[cap "infer" "murakumo-main"]]))]
      (is (= ["murakumo-main"] (resources t)))))
  (testing "and a name that parses on only one side relates to nothing"
    (let [t (-> (tok '[[cap "infer" "kotoba://model/x"]])
                (append '[[cap "infer" "murakumo-main"]]))]
      (is (nil? (resources t))
          "dropping is the safe direction; it must not fall back to string equality"))))

(deftest this-library-holds-one-answer-to-what-two-blocks-confer
  (testing "->delegated and ->grant narrow the same scopes the same way"
    ;; biscuit.authority/->grant has always folded with authority.grant/meet.
    ;; When ->delegated intersected strings instead, this library carried TWO
    ;; answers to `what do two blocks jointly confer` and only one of them was
    ;; the lattice -- the exact duplication `authority` exists to prevent.
    (doseq [[outer inner] [["kotoba://graph/*" "kotoba://graph/g1"]
                           ["kotoba://graph/g1" "kotoba://graph/*"]
                           ["kotoba://graph/g1" "kotoba://graph/g1"]
                           ["kotoba://graph/g1" "kotoba://graph/g2"]]]
      (let [delegated (-> (tok [['cap "graph-read" outer]])
                          (append [['cap "graph-read" inner]]))
            ;; ->grant folds the token's blocks onto a BASE, so `outer` is the
            ;; base and the single block carries `inner`. Handing it an empty
            ;; base would meet everything down to nothing and the comparison
            ;; would pass for the wrong reason.
            scoped (tok [['scope inner]])
            via-delegated (set (resources delegated))
            via-grant (set (keep scope/render
                                 (:grant/scopes (ba/->grant scoped {:scopes [outer]}))))]
        (is (= via-grant via-delegated)
            (str "the two folds disagree on " outer " then " inner))))))

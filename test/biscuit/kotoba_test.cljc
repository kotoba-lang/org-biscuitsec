(ns biscuit.kotoba-test
  (:require [biscuit.keys :as k]
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

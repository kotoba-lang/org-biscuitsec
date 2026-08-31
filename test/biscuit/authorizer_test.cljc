(ns biscuit.authorizer-test
  "`run-checks` -- the half the wire path was missing.

  `authorize` verifies and then checks, which a wire token cannot use:
  `biscuit.token/verify` recomputes the model payload while a wire token is
  signed over protobuf bytes, so the two disagree and the failure looks like a
  forgery. This suite covers the entry that runs decoded checks for a token the
  caller verified with `biscuit.wire/verify`."
  (:require [biscuit.authorizer :as az]
            [biscuit.ed25519 :as e]
            [biscuit.wire :as w]
            [clojure.test :refer [deftest is testing]]))

;; ── run-checks: the wire path's missing half ────────────────────────────────

(def ^:private root-pk
  "biscuit-auth/biscuit samples/current/samples.json, `root_public_key`."
  (mapv #(#?(:clj Integer/parseInt :cljs js/parseInt)
          (subs "1055c750b1a1505937af1537c626ba3263995c33a64758aaafb1275b0312e284" % (+ % 2)) 16)
        (range 0 64 2)))

(defn- wire-fixture [n]
  #?(:clj (with-open [in (java.io.FileInputStream. (str "test/fixtures/" n ".bc"))]
            (mapv #(bit-and % 255) (.readAllBytes in)))
     :cljs nil))

(deftest a-signature-check-cannot-be-forgotten-only-forged
  (testing "検証結果を引数に取る関数は、検証したつもりで呼べない"
    (doseq [v [nil {} {:ok? false :reason :signature-mismatch}]]
      (let [r (az/run-checks {:biscuit/blocks [{:block/check-count 0 :block/checks []}]}
                             v {})]
        (is (false? (:allowed? r)) (pr-str v))
        (is (false? (:verified? r)))))))

(deftest a-block-that-withheld-its-checks-refuses-rather-than-passing
  (testing "**これが一番危ない形** —— check を 0 個読むと全部が自明に満たされ、
            読みにくい token ほど寛容になる"
    (let [t {:biscuit/blocks [{:block/check-count 1
                               :block/checks nil
                               :block/checks-refused [:check-carries-an-expression]
                               :block/facts [] :block/rules []}]}
          r (az/run-checks t {:ok? true} {})]
      (is (false? (:allowed? r)))
      (is (= :checks-not-decoded (:reason r)))
      (is (true? (:verified? r)) "署名は通っている。読めなかったのは check の方")
      (is (= [:check-carries-an-expression] (:refused (first (:detail r))))))))

(deftest not-decoded-is-a-different-answer-from-failed
  (testing "「評価できない」と「評価したら通らなかった」を同じ理由にすると、
            どちらも直せない"
    (let [undecoded {:biscuit/blocks [{:block/check-count 1 :block/checks nil
                                       :block/checks-refused [:check-kind-not-one]
                                       :block/facts [] :block/rules []}]}
          failing {:biscuit/blocks [{:block/check-count 1
                                     :block/checks [{:body [['nope]]}]
                                     :block/facts [] :block/rules []}]}]
      (is (= :checks-not-decoded (:reason (az/run-checks undecoded {:ok? true} {}))))
      (is (= :check-failed (:reason (az/run-checks failing {:ok? true} {})))))))

(deftest a-token-with-no-checks-passes-and-that-is-the-tokens-own-permissiveness
  (let [t {:biscuit/blocks [{:block/check-count 0 :block/checks []
                             :block/facts [] :block/rules []}]}]
    (is (true? (:allowed? (az/run-checks t {:ok? true} {}))))))

#?(:clj
   (deftest a-reference-tokens-check-runs-against-the-verifiers-facts
     (testing "biscuit-auth が発行した token の check を、実際に走らせる。
               facts が足りなければ落ち、揃えば通る —— 両方向を出す"
       (let [wt (w/decode-token (wire-fixture "test001_basic"))
             v (w/verify wt root-pk e/verify-bytes-fn)
             m (w/token->model wt)]
         (is (:ok? v) "前提: 署名は通る")
         (is (= :check-failed (:reason (az/run-checks m v {:facts []})))
             "何も知らない verifier には、この check は通らない")
         (let [r (az/run-checks m v {:facts '[[resource "file1"] [operation "read"]]})]
           (is (true? (:allowed? r))
               "resource と operation を与えると通る —— check が実際に評価されている"))))))

(ns biscuit.wire-test
  "Read a token `biscuit-auth` minted, using `biscuit-auth`'s own samples.

  Every other suite here checks this library against itself. This one checks
  it against the reference implementation, which is the only kind of evidence
  that supports the word *interoperable* — the standard
  `org-apache-parquet` arrived at after two defects passed every in-repo
  test."
  (:require [biscuit.ed25519 :as e]
            [biscuit.wire :as w]
            [clojure.test :refer [deftest is testing]]
            [protobuf.wire :as pb]
            #?(:cljs ["node:fs" :as fs])))

(def root-public-key
  "biscuit-auth/biscuit samples/current/samples.json, `root_public_key`."
  (mapv #(#?(:clj Integer/parseInt :cljs js/parseInt)
          (subs "1055c750b1a1505937af1537c626ba3263995c33a64758aaafb1275b0312e284" % (+ % 2)) 16)
        (range 0 64 2)))

(defn sample [n]
  (let [path (str "test/fixtures/" n ".bc")]
    #?(:clj (with-open [in (java.io.FileInputStream. path)]
              (mapv #(bit-and % 255) (.readAllBytes in)))
       :cljs (vec (js/Array.from (fs/readFileSync path))))))

(deftest a-token-minted-by-biscuit-auth-decodes
  (let [t (w/decode-token (sample "test001_basic"))
        blocks (w/blocks-with-facts t)]
    (is (= 2 (count (:blocks t))))
    (testing "the facts are the ones samples.json prints for this token"
      (is (= [["right" "file1" "read"]
              ["right" "file2" "read"]
              ["right" "file1" "write"]]
             (:facts (first blocks)))))
    (testing "and the symbol table resolved them — indexes alone would be meaningless"
      (is (every? string? (map first (:facts (first blocks))))))))

(deftest a-token-minted-by-biscuit-auth-verifies
  (testing "the interoperability claim, and the only evidence that supports it"
    (is (= {:ok? true :blocks 2}
           (w/verify (w/decode-token (sample "test001_basic"))
                     root-public-key e/verify-bytes-fn)))))

(deftest the-v0-payload-byte-order-is-the-one-the-sample-verified
  (testing "the spec's two sections disagree; the sample decides, and the
            wrong order must FAIL or the right one proves nothing"
    (is (false? (:ok? (w/verify (w/decode-token (sample "test001_basic"))
                                root-public-key e/verify-bytes-fn
                                {:order :key-first}))))))

(deftest the-negative-samples-are-refused
  (doseq [[n why] [["test002_different_root_key" "signed by a key we do not trust"]
                   ["test005_invalid_signature" "a signature byte was altered"]
                   ["test006_reordered_blocks" "blocks moved, so the chain no longer links"]]]
    (testing why
      (let [r (w/verify (w/decode-token (sample n)) root-public-key e/verify-bytes-fn)]
        (is (false? (:ok? r)) (str n " must not verify"))
        (is (= :signature-mismatch (:reason r)))))))

(deftest an-unknown-signature-version-is-refused-not-defaulted
  (is (thrown? #?(:clj Exception :cljs :default)
               (w/signed-payload {:version 7 :block [1 2 3] :next-key-alg 0 :next-key [4]}))))

(deftest a-third-party-block-is-refused-by-name
  (testing "rather than decoded as if its external keys were not there"
    ;; A block carrying `publicKeys` is a third-party block. Decoding it as
    ;; an ordinary one would drop the very thing that changes who vouched for
    ;; its contents, so it throws instead.
    (let [block (pb/encode {1 {:name :symbols :type :string :repeated true}
                            8 {:name :public-keys :type :bytes :repeated true}}
                           {:symbols ["x"] :public-keys [[1 2 3]]})]
      (is (thrown? #?(:clj Exception :cljs :default) (w/decode-block block []))))))

(deftest a-wire-token-reaches-the-model-namespaces
  (testing "without this bridge a server accepts only a shape no other
            implementation produces"
    (let [m (w/token->model (w/decode-token (sample "test001_basic")))
          facts (:block/facts (first (:biscuit/blocks m)))]
      (is (= 2 (count (:biscuit/blocks m))))
      (testing "predicate heads are symbols, as a hand-written token's are"
        (is (every? symbol? (map first facts)))
        (is (= '[right "file1" "read"] (first facts)))))))

(deftest conversion-is-not-verification
  (testing "a caller that converts without verifying has decoded an
            attacker's facts, so the two must stay separate calls"
    (let [bad (w/decode-token (sample "test002_different_root_key"))]
      ;; It converts fine. That is the hazard, and why the docstring says so.
      (is (seq (:biscuit/blocks (w/token->model bad))))
      (is (false? (:ok? (w/verify bad root-public-key e/verify-bytes-fn)))))))

(deftest revocation-identifiers-are-the-block-signatures
  (testing "per the spec: a block's revocation id IS its signature"
    (let [t (w/decode-token (sample "test001_basic"))
          ids (w/revocation-ids t)]
      (is (= 2 (count ids)))
      (is (= [0 1] (mapv first ids)))
      (is (= (:signature (first (:blocks t))) (second (first ids))))
      (testing "and they are 64 bytes, because Ed25519 signatures are"
        (is (every? #(= 64 (count (second %))) ids))))))

(deftest revoking-a-parent-revokes-what-was-derived-from-it
  (testing "an attenuated token still carries its parent's signature, so the
            revoker does not need to know what was derived"
    (let [t (w/decode-token (sample "test001_basic"))
          parent-sig (:signature (first (:blocks t)))
          child-sig (:signature (second (:blocks t)))]
      (is (true? (w/revoked? t #{parent-sig})))
      (is (true? (w/revoked? t #{child-sig})))
      (testing "and an unrelated signature revokes nothing"
        (is (false? (w/revoked? t #{(vec (repeat 64 0))}))))
      (testing "as does an empty set"
        (is (false? (w/revoked? t #{})))))))

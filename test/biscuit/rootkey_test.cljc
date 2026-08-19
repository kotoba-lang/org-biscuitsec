(ns biscuit.rootkey-test
  (:require [biscuit.ed25519 :as e]
            [biscuit.rootkey :as rk]
            [clojure.test :refer [deftest is testing]]))

(def subject "kotobase.net/graph/acme")

(defn- digest-fn
  "A stand-in content digest. What matters to the log is that publisher and
  verifier use the SAME function; the pre-rotation property is about
  commitment, not about which hash."
  [pubkey]
  (str "d:" (hash (vec pubkey))))

(def k0 (e/keypair (vec (range 32))))
(def k1 (e/keypair (vec (range 32 64))))
(def k2 (e/keypair (vec (map #(+ 64 %) (range 32)))))
(def evil (e/keypair (vec (map #(+ 200 %) (range 32)))))

(defn- signed [{:keys [seq keys next-key signer prev-sig]}]
  (let [payload (rk/record {:subject subject :seq seq :keys keys
                            :next-key-digest (digest-fn (:public next-key))
                            :prev-signature prev-sig})]
    (assoc payload
           "signer" (:public signer)
           "sig" (e/sign-fn (:private signer) (pr-str payload)))))

(defn- verify-fn [pub payload sig] (e/verify-fn pub (pr-str payload) sig))

(def opts {:subject subject :genesis-key-digest (digest-fn (:public k0))
           :digest-fn digest-fn :verify-fn verify-fn})

(def genesis (signed {:seq 1 :keys [(:public k0)] :next-key k1 :signer k0}))

(deftest a-single-record-log-yields-its-keys
  (let [r (rk/verify-log [genesis] opts)]
    (is (= [(vec (:public k0))] (rk/current-keys r)))
    (is (= 1 (:seq r)))))

(deftest rotation-is-verifiable-without-trusting-the-host
  (testing "record 2 must be signed by the key record 1 committed to"
    (let [r2 (signed {:seq 2 :keys [(:public k1)] :next-key k2 :signer k1
                      :prev-sig (get genesis "sig")})
          r (rk/verify-log [genesis r2] opts)]
      (is (= [(vec (:public k1))] (rk/current-keys r)))
      (is (= 2 (:records r))))))

(deftest a-key-nobody-committed-to-is-refused
  (testing "the attack: take over the publishing location and serve your own key"
    (let [forged (signed {:seq 2 :keys [(:public evil)] :next-key evil :signer evil
                          :prev-sig (get genesis "sig")})
          r (rk/verify-log [genesis forged] opts)]
      (is (= :signer-not-committed (:refused r)))
      (is (= 1 (:at r)))
      (is (nil? (rk/current-keys r))))))

(deftest a-record-for-another-subject-is-refused
  (testing "signed-head found this one the hard way: nothing was forged, and
            it verified anyway"
    (let [other (assoc genesis "subject" "kotobase.net/graph/other")
          r (rk/verify-log [other] opts)]
      (is (= :malformed-or-wrong-subject (:refused r))))))

(deftest a-rollback-is-refused
  (testing "replaying an earlier record is not new information"
    (let [r2 (signed {:seq 2 :keys [(:public k1)] :next-key k2 :signer k1
                      :prev-sig (get genesis "sig")})
          r (rk/verify-log [genesis r2 genesis] opts)]
      (is (= :sequence-not-increasing (:refused r))))))

(deftest an-empty-log-is-refused-rather-than-defaulted
  (testing "a fetch that answered nothing must not become an authority decision"
    (is (= :empty-log (:refused (rk/verify-log [] opts))))
    (is (nil? (rk/current-keys (rk/verify-log [] opts))))))

(deftest a-tampered-key-set-breaks-the-signature
  (let [tampered (assoc genesis "keys" [(vec (:public evil))])
        r (rk/verify-log [tampered] opts)]
    (is (= :signature-mismatch (:refused r)))))

(deftest the-genesis-digest-is-pinned-by-the-caller
  (testing "so the first record is not self-authorising either"
    (let [r (rk/verify-log [genesis] (assoc opts :genesis-key-digest (digest-fn (:public evil))))]
      (is (= :signer-not-committed (:refused r))))))

(deftest a-log-that-stops-early-still-answers-what-it-proved
  (testing "an attacker who takes the location can withhold, not invent"
    (let [r (rk/verify-log [genesis] opts)]
      (is (= [(vec (:public k0))] (rk/current-keys r)))
      (testing "and the caller can see the sequence it reached"
        (is (= 1 (:seq r)))))))

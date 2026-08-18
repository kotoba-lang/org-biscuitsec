(ns run-nbb-tests
  (:require [clojure.test :as t]
            [biscuit.datalog-test]
            [biscuit.token-test]
            [biscuit.authority-test]
            [biscuit.kotoba-test]))

(def namespaces '[biscuit.datalog-test biscuit.token-test biscuit.authority-test biscuit.kotoba-test])

(let [{:keys [fail error test]} (apply t/run-tests namespaces)]
  (when (zero? test) (println "no tests ran") (js/process.exit 2))
  (js/process.exit (if (pos? (+ fail error)) 1 0)))

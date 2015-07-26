(ns pcap.core
  (require [clojure.java.io :as io]
           [gloss.io :as gio]
           [pcap.pcap :as pcap]))

(defn parse
  [filename]
  (with-open [ins (io/input-stream (io/file filename))]
    (gio/decode pcap/pcap ins)))

(ns pcap.core
  (require [clojure.java.io :as io]
           [gloss (core :as gcore) (io :as gio)]
           [pcap.pcap :as pcap]))

(defn parse
  [filename]
  (with-open [ins (io/input-stream (io/file filename))]
    (let [hsize (gcore/sizeof pcap/file-header)
          buf (byte-array hsize)
          rsize (.read ins buf 0 hsize)
          pheader (gio/decode pcap/file-header buf)]
      (gio/lazy-decode-all (pcap/packet pheader) ins))))

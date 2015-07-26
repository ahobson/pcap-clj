(ns pcap.udp
  (require [gloss.core :as glc]))

(glc/defcodec udp-header
  (glc/ordered-map :src_port     :uint16-be
                   :dst_port     :uint16-be
                   :len          :uint16-be
                   :checksum     :uint16-be))

(def udp-header-len 8)

(defn udp-data-len
  [h]
  (- (:len h) udp-header-len))

(glc/defcodec udp-packet
  (glc/header udp-header
              (fn [h]
                (glc/finite-block (udp-data-len h)))
              (fn [b]
                (:header b))))

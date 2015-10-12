(ns pcap.udp
  (:require [gloss.core :as glc]))

(glc/defcodec header
  (glc/ordered-map :src_port     :uint16-be
                   :dst_port     :uint16-be
                   :len          :uint16-be
                   :checksum     :uint16-be))

(def header-len 8)

(defn data-len
  [h]
  (- (:len h) header-len))

(glc/defcodec packet
  (glc/header header
              (fn [h]
                (glc/finite-block (data-len h)))
              (fn [b]
                (:header b))))

(ns pcap.ethernet
  (:require [gloss.core :as glc]
            [pcap.ipv4 :as ipv4]))

(glc/defcodec protocol
  (glc/enum :uint16 {:arp           0x0806
                     :rarp          0x8035
                     :ipv4          0x0800
                     :lldp          0x88CC
                     :bsn           0x8942
                     :vlan-untagged 0xffff
                     :ipv6          0x86dd}))

(glc/defcodec address
  (glc/finite-frame 6 (glc/repeated :ubyte :prefix :none)))

(glc/defcodec header
  (glc/ordered-map
   :dst_addr address
   :src_addr address
   :protocol protocol))

(def data-codecs
  {:ipv4 ipv4/packet})

(defn get-data-codec
  [h]
  (glc/compile-frame
   (get data-codecs (:protocol h))
   identity
   (fn [data]
     {:link-type :ethernet :header h :data data})))

(glc/defcodec packet
  (glc/header header
              get-data-codec
              (fn [b]
                (:header b))))



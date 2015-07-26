(ns pcap.ethernet
  (require [gloss.core :as glc]
           [pcap.ipv4 :as ipv4]))

(glc/defcodec ethernet-protocol
  (glc/enum :uint16 {:arp           0x0806
                     :rarp          0x8035
                     :ipv4          0x0800
                     :lldp          0x88CC
                     :bsn           0x8942
                     :vlan-untagged 0xffff
                     :ipv6          0x86dd}))

(glc/defcodec header
  (glc/ordered-map
   :dst_addr          (glc/finite-block 6)
   :src_addr          (glc/finite-block 6)
   :ethernet-protocol ethernet-protocol))

(def data-codecs
  {:ipv4 ipv4/packet})

(defn get-data-codec
  [h]
  (get data-codecs (:ethernet-protocol h)))

(glc/defcodec packet
  (glc/header header
              get-data-codec
              (fn [b]
                (select-keys b [:dst_addr :src_addr :ethernet-protocol]))))



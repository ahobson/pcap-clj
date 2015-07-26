(ns pcap.ipv4
  (require [gloss.core :as glc]
           [pcap.udp :as udp]))

(glc/defcodec ip-protocols
  (glc/enum :ubyte {:icmp  0x01
                    :igmp  0x02
                    :tcp   0x06
                    :udp   0x11}))

(glc/defcodec header
  (glc/ordered-map :version-len  (glc/bit-map :version 4 :header-len 4)
                   :tos          :ubyte
                   :len          :uint16-be
                   :id           :uint16-be
                   :flags-offset (glc/bit-map :flags 3 :offset 13)
                   :ttl          :ubyte
                   :protocol     ip-protocols
                   :checksum     :uint16-be
                   :src_ip       :uint32-be
                   :dst_ip       :uint32-be))

(defn data-len
  [h]
  (let [hdr-len   (* 4 (get-in h [:version-len :header-len]))
        total-len (:len h)]
    (- total-len hdr-len)))

(glc/defcodec packet
  (glc/header header
              (fn [h]
                (glc/ordered-map :options glc/nil-frame
                                 :payload udp/udp-packet))
              (fn [b]
                (:header b))))


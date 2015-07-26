(ns pcap.core
  (require [gloss (core :as glc) (io :as gio)]))

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

(glc/defcodec ipv4-header
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

(defn ipv4-data-len
  [h]
  (let [hdr-len   (* 4 (get-in h [:version-len :header-len]))
        total-len (:len h)]
    (- total-len hdr-len)))

(glc/defcodec ipv4-packet
  (glc/header ipv4-header
              (fn [h]
                (glc/ordered-map :options glc/nil-frame
                                 :payload udp-packet))
              (fn [b]
                (:header b))))

(glc/defcodec ethernet-protocol
  (glc/enum :uint16 {:arp           0x0806
                     :rarp          0x8035
                     :ipv4          0x0800
                     :lldp          0x88CC
                     :bsn           0x8942
                     :vlan-untagged 0xffff
                     :ipv6          0x86dd}))

(glc/defcodec ethernet-header
  (glc/ordered-map
   :dst_addr          (glc/finite-block 6)
   :src_addr          (glc/finite-block 6)
   :ethernet-protocol ethernet-protocol))

(glc/defcodec ethernet-packet
  (glc/header ethernet-header
              (fn [h]
                ipv4-packet)
              (fn [b]
                (select-keys b [:dst_addr :src_addr :ethernet-protocol]))))

(glc/defcodec ip-protocols
  (glc/enum :ubyte {:icmp  0x01
                    :igmp  0x02
                    :tcp   0x06
                    :udp   0x11}))

(glc/defcodec size-version
  (glc/compile-frame :ubyte
                     (fn [s]
                       (bit-or (bit-shift-left (s :version) 4)
                               (/ (s :size) 4 )))
                     (fn [b]
                       {:version (bit-shift-right b 4)
                        :size (* 4  (bit-and b 0x0f))})))


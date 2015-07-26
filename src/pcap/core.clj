(ns pcap.core
  (require [gloss (core :as glc) (io :as gio)]))

(glc/defcodec file-header
  (glc/ordered-map :magic   :uint32-le
                   :major   :uint16-le
                   :minor   :uint16-le
                   :zone    :int32-le
                   :sigfigs :uint32-le
                   :snaplen :uint32-le
                   :network link-type))

(glc/defcodec link-type
  (glc/enum :uint32-le {:null       0
                        :ethernet   1
                        :raw        101}))

(glc/defcodec packet-len
  (glc/ordered-map :len     :uint32-le
                   :pktlen  :uint32-le))

(glc/defcodec ethernet-proto
  (glc/enum :uint16-le {:ip 0x0800}))

(glc/defcodec ip-packet
  (glc/ordered-map :hdr-len :uint8-le
                   :version :uint8-le
                   :tos     :uint8-le
                   :len     :uint16-le
                   :id      :uint16-le
                   :off     :uint16-le
                   :ttl     :uint8-le
                   :proto   :uint8-le
                   :chk     :uint16-le
                   :src     :uint32-le
                   :dst     :uint32-le))

(def etherent-proto-map
  {:ip ip-packet})

(glc/defcodec ethernet-src-dst
  (glc/ordered-map :dst   (glc/finite-block 6)
                   :src   (glc/finite-block 6)))

(glc/defcodec ethernet-packet
  (glc/header ethernet-proto
              (fn [h]
                (h ethernet-proto-map))))

(glc/defcodec packet
  (glc/ordered-map :sec     :uint32-le
                   :usec    :uint32-le
                   :payload (glc/repeated
                             :ubyte
                             :prefix
                             (glc/prefix packet-len
                                         :len
                                         (fn [b]
                                           {:len (alength b)
                                            :pktlen (alength b)})))))

(glc/defcodec pcap
  (glc/ordered-map :file-header    file-header
                   :packets        (glc/repeated packet :prefix :none)))


(defn parse
  [filename]
  (with-open [ins (io/input-stream (io/file filename))]
    (gio/decode pcap ins)))

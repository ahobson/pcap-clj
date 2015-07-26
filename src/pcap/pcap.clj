(ns pcap.pcap
  (require [gloss.core :as glc]
           [pcap (ethernet :as ethernet)]))

(glc/defcodec link-type
  (glc/enum :uint32-le {:null       0
                        :ethernet   1
                        :raw        101}))

(glc/defcodec file-header
  (glc/ordered-map :magic   :uint32-le
                   :major   :uint16-le
                   :minor   :uint16-le
                   :zone    :int32-le
                   :sigfigs :uint32-le
                   :snaplen :uint32-le
                   :network link-type))

(glc/defcodec packet-len
  (glc/ordered-map :len     :uint32-le
                   :pktlen  :uint32-le))

(def data-codecs
  {:ethernet ethernet/packet})

(glc/defcodec len-header (glc/header packet-len
                                        (fn [h] (glc/finite-block (:len h)))
                                        (fn [b]
                                          {:len (alength b)
                                           :pktlen (alength b)})))

(def packet-payload
  (glc/compile-frame len-header
                     (fn [x] (prn "DEBUG:pre:x" x) x)
                     (fn [x] (prn "DEBUG:post:x" x) x)))

(glc/defcodec packet
  (glc/ordered-map :sec     :uint32-le
                   :usec    :uint32-le
                   :payload packet-payload))

(glc/defcodec pcap
  (glc/ordered-map :file-header    file-header
                   :packets        (glc/repeated packet :prefix :none)))

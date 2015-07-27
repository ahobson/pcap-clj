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
                   :snaplen :uint32-le))

(glc/defcodec packet-len
  (glc/ordered-map :len     :uint32-le
                   :pktlen  :uint32-le))


(glc/defcodec len-header (glc/header packet-len
                                        (fn [h] (glc/finite-block (:len h)))
                                        (fn [b]
                                          {:len (alength b)
                                           :pktlen (alength b)})))

(def payload-codecs
  {:ethernet ethernet/packet})

(defn get-payload-header
  [header]
  (if-let [payload-codec (get payload-codecs (:network header))]
    (glc/header packet-len
                (fn [h] payload-codec)
                (fn [b]
                  {:len (alength b)
                   :pktlen (alength b)}))
    (glc/header packet-len
                (fn [h] (glc/finite-block (:len h)))
                (fn [b]
                  {:len (alength b)
                   :pktlen (alength b)}))))

(defn get-payload
  [header]
  (glc/compile-frame
   (glc/ordered-map :sec     :uint32-le
                    :usec    :uint32-le
                    :payload (get-payload-header header))
   identity
   (fn [body]
     (try
       (update-in body [:payload]
                  (partial gio/decode packet))
       (catch Exception e
         body)))))

(defn pcap-header->body
  [header]
  (let [packet-frame (get-payload header)]
    (glc/repeated packet-frame :prefix :none)))

(glc/defcodec link-type-header
  (glc/ordered-map :network link-type))

(glc/defcodec pcap
  (glc/ordered-map :file-header file-header
                   :packets     (glc/header link-type-header
                                            pcap-header->body
                                            nil)))

(ns pcap.codec
  require [gloss (core :as glc) (protocols :as gp)])

(defn header-with-metadata
  [codec header->body body->header]
  (let [read-codec (compose-callback
                    codec
                    (fn [v b]
                      (let [body (header->body v)]
                        (read-bytes body b))))]
    (reify
      Reader
      (read-bytes [_ buf-seq]
        (read-bytes read-codec buf-seq))
      Writer
      (sizeof [_]
        nil)
      (write-bytes [_ buf val]
        (let [header (body->header val)
              body (header->body header)]
          (if (and (sizeof codec) (sizeof body))
            (with-buffer [buf (+ (sizeof codec) (sizeof body))]
              (write-bytes codec buf header)
              (write-bytes body buf val))
            (concat
             (write-bytes codec buf header)
             (write-bytes body buf val))))))))

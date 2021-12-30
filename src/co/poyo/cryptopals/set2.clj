(ns co.poyo.cryptopals.set2)

(defn concat-byte-arrays [& byte-arrays]
  (when (not-empty byte-arrays)
    ))

(defn pkcs-7 [^bytes ba len]
  (if  (>= (count  ba) len)
         ba
         (let [padded (byte-array len (byte 0))
               bb (java.nio.ByteBuffer/wrap padded)]
           (.put bb ba)
           padded)))

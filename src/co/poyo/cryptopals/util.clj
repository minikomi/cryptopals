(ns co.poyo.cryptopals.util
  (:import [org.apache.commons.codec.binary Hex Base64]
           [javax.crypto Cipher]
           [javax.crypto.spec SecretKeySpec])
  )

(defn hexstr->ba [s]
  (Hex/decodeHex ^chars (char-array s)))

(defn ba->hexstr [^bytes ba]
  (apply str (Hex/encodeHex ba)))

(defn ba->s [^bytes ba]
  (String. ^bytes ba "UTF-8"))

(defn s->ba [^String s]
  (.getBytes (String. ^String s)))

(defn encode-base64 [^bytes ba]
  (Base64/encodeBase64 ba))

(defn decode-base64 [^bytes ba]
  (Base64/decodeBase64 ^bytes ba))

(defn fixed-xor-ba [^bytes ba1 ^bytes ba2]
  (amap ^bytes ba1 i ret
        (byte
         (bit-xor
          (aget ^bytes ba1 i)
          (aget ^bytes ba2 i)))))

(defn aes-ecb
  ([mode ^bytes txt ^bytes key]
   (aes-ecb mode ^bytes txt ^bytes key true))
  ([mode txt key padding]
   (let  [mode-int (case mode
                     :encrypt Cipher/ENCRYPT_MODE
                     :decrypt Cipher/DECRYPT_MODE)
          padding-str (if padding "PKCS5PADDING" "NoPadding")
          cipher-name (str "AES/ECB/" padding-str)
          spec (SecretKeySpec. key "AES")
          cipher-instance (Cipher/getInstance cipher-name)]
     (.init cipher-instance mode-int spec)
     (.doFinal cipher-instance txt)
     )))

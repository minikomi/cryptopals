(ns co.poyo.cryptopals.set2
  (:require [clojure.string :as str]
            [clojure.java.io :as io]
            [co.poyo.cryptopals.util :as util]
            [co.poyo.cryptopals.set1 :as set1]
            ))

(defn ba-extend [^bytes a ^bytes b]
  (let [len (+ (count a) (count b))
        out (byte-array len)
        bb (java.nio.ByteBuffer/wrap out)]
    (.put (.put bb a) b)
    out))

(defn pkcs-7 [^bytes ba len]
  (let [ext-len (max 0 (- len (count ba)))]
    (if (zero? ext-len) ba
        (ba-extend ba (byte-array ext-len (byte 0)))
        )))

(comment
  (into [] (pkcs-7 (util/s->ba "aaa") 10))
  )

;; In CBC mode, each ciphertext block is added to the next plaintext block
;; before the next call to the cipher core.
;;
;; The first plaintext block, which has no associated previous ciphertext block,
;; is added to a "fake 0th ciphertext block" called the initialization vector,
;; or IV.
;;
;;
;; Implement CBC mode by hand by taking the ECB function you wrote earlier,
;; making it encrypt instead of decrypt (verify this by decrypting whatever you
;; encrypt to test), and using your XOR function from the previous exercise to
;; combine them.

(defn -aes-encrypt-step [key cypher chunk]
  (let [key-len (count key)
        pad-chunk (pkcs-7 chunk key-len)
        xor-chunk (fixed-xor-ba cypher pad-chunk)
        aes-chunk (util/aes-ecb :encrypt xor-chunk key false)]
    aes-chunk))

(defn -aes-decrypt-step [key cypher chunk]
  (let [ecb-chunk (util/aes-ecb :decrypt chunk key false)
        xor-chunk (fixed-xor-ba cypher ecb-chunk)]
    xor-chunk))

(defn aes-cbc
  [mode ^bytes txt ^bytes key]
  (let [iv (byte-array (count key) (byte 0))
        start-state {:cypher iv :collect (byte-array [])}
        f (case mode
            :encrypt
            (fn [{:keys [cypher collect]} chunk]
              (let [new-cypher (-aes-encrypt-step key cypher chunk)]
                {:cypher new-cypher
                 :collect (ba-extend collect new-cypher)}))
            :decrypt
            (fn [{:keys [cypher collect]} chunk]
              (let [decrypted-chunk (-aes-decrypt-step key cypher chunk)]
                {:cypher chunk
                 :collect (ba-extend collect decrypted-chunk)})))
        final (case mode
                :encrypt identity
                :decrypt (fn [s]
                           ()

                           ))]
    (->>
     (partition-all (count key) txt)
     (map byte-array)
     (reduce f start-state)
     :collect
     )))


(comment

  (def set2-2-input
    (util/decode-base64
     (util/s->ba (slurp (io/resource "set2/10.txt")
                        ))))

  (def submarine-key (util/s->ba "YELLOW SUBMARINE"))

  (str/trim (util/ba->s
    (aes-cbc :decrypt
             (aes-cbc :encrypt (util/s->ba "banana banana banana yo yo yo") submarine-key)
             submarine-key
             )))

  (util/ba->s
   (aes-cbc :decrypt set2-2-input submarine-key))


  )


;; An ECB/CBC detection oracle
;; 
;; Now that you have ECB and CBC working:
;; 
;; Write a function to generate a random AES key; that's just 16 random bytes.
;; 
;; Write a function that encrypts data under an unknown key --- that is, a
;; function that generates a random key and encrypts under it.
;; 
;; The function should look like:
;; 
;; encryption_oracle(your-input)
;; => [MEANINGLESS JIBBER JABBER]
;; 
;; Under the hood, have the function append 5-10 bytes (count chosen randomly)
;; before the plaintext and 5-10 bytes after the plaintext.
;; 
;; Now, have the function choose to encrypt under ECB 1/2 the time, and under
;; CBC the other half (just use random IVs each time for CBC). Use rand (2) to
;; decide which to use.
;; 
;; Detect the block cipher mode the function is using each time. You should end
;; up with a piece of code that, pointed at a block box that might be encrypting
;; ECB or CBC, tells you which one is happening.

(defn blackbox [^bytes txt]
  (let [rand-key (byte-array (repeatedly 16 #(rand-int 257)))
        rand-head (byte-array (repeatedly (+ 5 (rand-int 5)) #(rand-int 257)))
        rand-tail (byte-array (repeatedly (+ 5 (rand-int 5)) #(rand-int 257)))
        txt-extended (ba-extend (ba-extend rand-head txt) rand-tail)
        alg-type (rand-nth [:ecb :cbc])]
    (println alg-type)
    (case alg-type
      :ecb
      (util/aes-ecb :encrypt txt-extended rand-key)
      :cbc
      (aes-cbc :encrypt txt-extended rand-key)
      )))

(defn check-blackbox []

  (let [bb (blackbox (util/s->ba (apply str (repeat 64 \A))))
        ]
    (if (set1/is-aes-ecb? 16 bb) :ecb :cbc)))
(util/ba->s (blackbox (util/s->ba (apply str (repeat 100 \A)))))
(check-blackbox)

(ns co.poyo.cryptopals.set2
  (:require [clojure.string :as str]
            [clojure.java.io :as io]
            [co.poyo.cryptopals.util :as util]
            [co.poyo.cryptopals.set1 :as set1]
            ))

(defn pkcs-7 [^bytes ba len]
  (let [ext-len (max 0 (- len (count ba)))]
    (if (zero? ext-len) ba
        (util/ba-extend ba (byte-array ext-len (byte 0)))
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
        xor-chunk (util/fixed-xor-ba cypher pad-chunk)
        aes-chunk (util/aes-ecb :encrypt xor-chunk key false)]
    aes-chunk))

(defn -aes-decrypt-step [key cypher chunk]
  (let [ecb-chunk (util/aes-ecb :decrypt chunk key false)
        xor-chunk (util/fixed-xor-ba cypher ecb-chunk)]
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
                 :collect (util/ba-extend collect new-cypher)}))
            :decrypt
            (fn [{:keys [cypher collect]} chunk]
              (let [decrypted-chunk (-aes-decrypt-step key cypher chunk)]
                {:cypher chunk
                 :collect (util/ba-extend collect decrypted-chunk)})))
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
        txt-extended (util/ba-extend (util/ba-extend rand-head txt) rand-tail)
        alg-type (rand-nth [:ecb :cbc])
        encrypted-result (case alg-type

                           :ecb
                           (util/aes-ecb :encrypt txt-extended rand-key)
                           :cbc
                           (aes-cbc :encrypt txt-extended rand-key)
                           )
        ]
    [alg-type encrypted-result
     ]))

(defn check-blackbox []
  (let [[alg-type bb-result] (blackbox (util/s->ba (apply str (repeat 64 \A))))]
    (= alg-type (if (set1/is-aes-ecb? 16 bb-result) :ecb :cbc))))

(comment
  (check-blackbox)
  )


;; Byte-at-a-time ECB decryption (Simple)
;;
;; Copy your oracle function to a new function that encrypts buffers under ECB
;; mode using a consistent but unknown key (for instance, assign a single random
;; key, once, to a global variable).
;;
;; Now take that same function and have it append to the plaintext, BEFORE
;; ENCRYPTING, the following string:
;;
;; Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
;; aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
;; dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
;; YnkK
;;
;;  - Spoiler alert.
;;
;;    - Do not decode this string now. Don't do it.
;;
;;    - Base64 decode the string before appending it. Do not base64 decode the string
;;      by hand; make your code do it. The point is that you don't know its contents.
;;
;; What you have now is a function that produces:
;;
;; AES-128-ECB(your-string || unknown-string, random-key)
;;
;; It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!
;;
;; Here's roughly how:
;;
;; 1 Feed identical bytes of your-string to the function 1 at a time --- start
;;   with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size
;;   of the cipher. You know it, but do this step anyway.
;; 2 Detect that the function is using ECB. You already know, but do this step
;;   anyways.
;; 3 Knowing the block size, craft an input block that is exactly 1 byte short
;;  (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about
;;  what the oracle function is going to put in that last byte position.
;; 4 Make a dictionary of every possible last byte by feeding different strings
;;   to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering
;;   the first block of each invocation.
;; 5 Match the output of the one-byte-short input to one of the entries in your
;;   dictionary. You've now discovered the first byte of unknown-string.
;; 6 Repeat for the next byte.

(def unknown-string
  (util/decode-base64
   (util/s->ba (slurp (io/resource "set2/12.txt")))))

(def random-key
  (byte-array (repeatedly 16 #(rand-int 257))))

(defn head-append-aes-ecb [^bytes txt]
  (util/aes-ecb
   :encrypt
   (util/ba-extend txt unknown-string)
   random-key))

(comment
  (set1/find-repeating-key-length
   (head-append-aes-ecb (util/s->ba "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")))
  ;; 16
  (set1/is-aes-ecb?
   16 (util/s->ba "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
  ;; true
  )

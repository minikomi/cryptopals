(ns co.poyo.cryptopals.set1
  (:import [org.apache.commons.codec.binary Hex Base64])
  (:require [clojure.string :as str]
            [clojure.java.io :as io]))

(defn hexstr->ba [s]
  (Hex/decodeHex ^chars (char-array s)))

(defn ba->s [^bytes ba]
  (String. ^bytes ba "UTF-8"))

(defn s->ba [^String s]
  (.getBytes (String. ^String s)))

(defn ba->hexstr [^bytes ba]
  (apply str (Hex/encodeHex ba)))

(defn encode-base64 [^bytes ba]
  (Base64/encodeBase64 ba))

(defn decode-base64 [^bytes ba]
  (Base64/decodeBase64 ^bytes ba))

;; * Convert hex to base64
;;   - The string:
;;
;;   ~49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d~
;;
;;   - Should produce:
;;
;;   ~SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t~

(defn hex-to-base64 [s]
  (-> s hexstr->ba encode-base64 ba->s))


;; *** Fixed XOR
;; Write a function that takes two equal-length buffers and produces their
;; XOR combination.
;;
;; If your function works properly, then when you feed it the string:
;;
;; #+begin_example
;;   1c0111001f010100061a024b53535009181c
;; #+end_example
;;
;; ... after hex decoding, and when XOR'd against:
;;
;; #+begin_example
;;   686974207468652062756c6c277320657965
;; #+end_example
;;
;; ... should produce:
;;
;; #+begin_example
;;   746865206b696420646f6e277420706c6179
;; #+end_example
;;


(defn fixed-xor-ba [ba1 ba2]
  (amap ^bytes ba1 i ret
        (byte
         (bit-xor
          (aget ^bytes ba1 i)
          (aget ^bytes ba2 i)))))

(defn fixed-xor [s1 s2]
  (ba->hexstr
   (fixed-xor-ba
    (hexstr->ba s1)
    (hexstr->ba s2))))

;; *** Single-byte XOR cipher
;; The hex encoded string:
;;
;; #+begin_example
;;   1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
;; #+end_example
;;
;; ... has been XOR'd against a single character. Find the key, decrypt the
;; message.
;;
;; You can do this by hand. But don't: write code to do it for you.
;;
;; How? Devise some method for "scoring" a piece of English plaintext.
;; Character frequency is a good metric. Evaluate each output and choose
;; the one with the best score.

(def char-freq-table
  ; source : https://en.wikipedia.org/wiki/Letter_frequency
  {\a 0.08167 \b 0.01492 \c 0.02782 \d 0.04253 \e 0.12702
   \f 0.02228 \g 0.02015 \h 0.06094 \i 0.06966 \j 0.00153
   \k 0.00772 \l 0.04025 \m 0.02406 \n 0.06749 \o 0.07507
   \p 0.01929 \q 0.00095 \r 0.05987 \s 0.06327 \t 0.09056
   \u 0.02758 \v 0.00978 \w 0.02360 \x 0.00150 \y 0.01974
   \z 0.00074 \space 0.23200})

(defn rate-str [^bytes ba]
  (let [lc-chars (->> ba (map #(Character/toLowerCase %)))]
    (reduce + (map #(get char-freq-table % 0) lc-chars))))

(defn decode-xor-using-char-freq [input-str]
  (let [input-ba (hexstr->ba input-str)
        results (for [ch (range 32 127)
                      :let [single-char-ba (->> (repeat (byte ch))
                                                (take (count input-ba))
                                                byte-array)
                            xor-result (fixed-xor-ba
                                        input-ba
                                        single-char-ba)]]
                  [(rate-str (ba->s xor-result)) ch (ba->s xor-result)])]
    (first (sort-by first > results))))

(comment
  (decode-xor-using-char-freq
   "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
  ; result:
  ;
  ; [2.14329 \X "Cooking MC's like a pound of bacon"]
  )

;; *** Detect single-character XOR
;; One of the 60-character strings
;; in [[https://cryptopals.com/static/challenge-data/4.txt][this file]] has
;; been encrypted by single-character XOR.
;;
;; Find it.
;;
;; (Your code from #3 should help.)
;;

(comment
  (def set1-4-input (slurp (io/resource "set1/4.txt")))
  (first
   (sort-by first > (pmap decode-xor-using-char-freq (str/split-lines set1-4-input))))
  ; Result
  ;
  ; [2.5622299999999996 53 "Now that the party is jumping\n"]
  )

;; *** Implement repeating-key XOR
;; Here is the opening stanza of an important work of the English language:
;;
;; #+begin_example
;;   Burning 'em, if you ain't quick and nimble
;;   I go crazy when I hear a cymbal
;; #+end_example
;;
;; Encrypt it, under the key "ICE", using repeating-key XOR.
;;
;; In repeating-key XOR, you'll sequentially apply each byte of the key;
;; the first byte of plaintext will be XOR'd against I, the next C, the
;; next E, then I again for the 4th byte, and so on.
;;
;; It should come out to:
;;
;; #+begin_example
;;   0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
;;   a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
;; #+end_example
;;
;; Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt
;; your mail. Encrypt your password file. Your .sig file. Get a feel for
;; it. I promise, we aren't wasting your time with this.


(defn repeating-key-xor [key s]
  (let [ba (s->ba s)]
    (fixed-xor-ba
     ba
     (byte-array (take (count s) (cycle (map byte key)))))))

;; [[https://cryptopals.com/static/challenge-data/6.txt][There's a file here.]] It's been base64'd after being encrypted with repeating-key XOR.
;;
;; Decrypt it.
;;
;; Here's how:
;;
;; 1. Let KEYSIZE be the guessed length of the key; try values from 2 to
;;    (say) 40.
;;
;; 2. Write a function to compute the edit distance/Hamming distance
;;    between two strings. /The Hamming distance is just the number of
;;    differing bits./ The distance between:
;;
;;    #+begin_example
;;      this is a test
;;    #+end_example
;;
;;    and
;;
;;    #+begin_example
;;      wokka wokka!!!
;;    #+end_example
;;
;;    is *37.* /Make sure your code agrees before you proceed./
;;
;; 3. For each KEYSIZE, take the /first/ KEYSIZE worth of bytes, and
;;    the /second/ KEYSIZE worth of bytes, and find the edit distance
;;    between them. Normalize this result by dividing by KEYSIZE.
;;
;; 4. The KEYSIZE with the smallest normalized edit distance is probably
;;    the key. You could proceed perhaps with the smallest 2-3 KEYSIZE
;;    values. Or take 4 KEYSIZE blocks instead of 2 and average the
;;    distances.
;;
;; 5. Now that you probably know the KEYSIZE: break the ciphertext into
;;    blocks of KEYSIZE length.
;;
;; 6. Now transpose the blocks: make a block that is the first byte of
;;    every block, and a block that is the second byte of every block, and
;;    so on.
;;
;; 7. Solve each block as if it was single-character XOR. You already have
;;    code to do this.
;;
;; 8. For each block, the single-byte XOR key that produces the best
;;    looking histogram is the repeating-key XOR key byte for that block.
;;    Put them together and you have the key.
;;
;; This code is going to turn out to be surprisingly useful later on.
;; Breaking repeating-key XOR ("Vigenere") statistically is obviously an
;; academic exercise, a "Crypto 101" thing. But more people "know how" to
;; break it than can /actually break it/, and a similar technique breaks
;; something much more important.

(defn hamming-distance [bs1 bs2]
  (->> (map bit-xor bs1 bs2)
       (map #(Integer/bitCount %))
       (reduce +)))

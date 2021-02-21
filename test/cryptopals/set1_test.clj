(ns cryptopals.set1-test
  (:require
   [clojure.test :as t]
   [co.poyo.cryptopals.set1 :as set1]))

(t/deftest test-set1-1
  (t/is
   (=
    "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    (set1/hex-to-base64
     "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))))

(t/deftest test-set1-2
  (t/is
   (=
    "746865206b696420646f6e277420706c6179"
    (set1/fixed-xor
     "1c0111001f010100061a024b53535009181c"
     "686974207468652062756c6c277320657965"))))

(t/deftest test-set-1-5
  (t/is
   (=
    ["0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"]
    (map #(set1/ba->hexstr (set1/repeating-key-xor "ICE" %))
         ["Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"]))))

(t/deftest test-set-1-6

  (t/is
   (= 37
      (set1/hamming-distance
       (set1/s->ba "this is a test")
       (set1/s->ba "wokka wokka!!!")))))

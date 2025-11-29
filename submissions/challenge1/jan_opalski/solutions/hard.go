package solutions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
)

const blocklen = 16
const blockcount = 3

// https://cryptopals.com/sets/4/challenges/27
func Hard() {
	fmt.Println("=============================\n\t  HARD (27)\n=============================")
	// create a 128-bit key, assume sender and receiver know it while attacker doesn't
	key := sender_receiver_setKey()
	// SENDER
	message := sender_setupMessage()
	encrypted := sender_encryptMessage(message, key)

	// ATTACKER
	modified := attacker_modifyMessage(encrypted)

	// RECEIVER
	err := receiver_decryptMessage(modified, key)
	if err == nil {
		fmt.Println("Receiver didn't raise error <- attack failed")
		return
	}

	// ATTACKER
	decrypted, err := hex.DecodeString(err.Error())
	if err != nil || len(decrypted) == 0 {
		fmt.Println("Didn't get decrypted \"plaintext\" of positive length <- attack failed")
		return
	}
	att_key := attacker_guessKey(decrypted)

	// verification
	if !slices.Equal(key, att_key) {
		fmt.Println("Attacker got the key wrong")
	} else {
		fmt.Println("Attacker got the key right")
	}
}

func sender_receiver_setKey() []byte {
	key := make([]byte, blocklen)
	_, _ = io.ReadFull(rand.Reader, key)
	fmt.Println("Key:\t\t\t", hex.EncodeToString(key))
	return key
}

func sender_setupMessage() []byte {
	message := []byte("This is a very important and very secret message")
	if len(message) != blockcount*blocklen {
		panic("Message not padded to be exactly 3-blocks long")
	}
	return message
}

// (P1, P2, P3) -> (C1, C2, C3)
func sender_encryptMessage(msg []byte, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	// create CBC cipher which has unsafe behaviour of reusing key as iv
	encrypter := cipher.NewCBCEncrypter(block, key)
	encrypted := make([]byte, len(msg))
	encrypter.CryptBlocks(encrypted, msg)
	fmt.Println("Encrypted by sender:\t", hex.EncodeToString(encrypted))
	return encrypted
}

// (C1, C2, C3) -> (C1, 0, C1)
func attacker_modifyMessage(msg []byte) []byte {
	modified := make([]byte, len(msg))
	copy(modified[:blocklen], msg[:blocklen])
	copy(modified[2*blocklen:3*blocklen], msg[:blocklen])
	fmt.Println("Modified by attacker:\t", hex.EncodeToString(modified))
	return modified
}

// The assumption in case of processing error (decrypted plaintext containing invalid ASCII value)
// receiver returns some kind of error message which contains the decrypted plaintext.
// Here for the sake of simplicity receiver_ans error message is strictly either
// - hex string of decrypted "plaintext" if there was an invalid ASCII value (almost surely there'll be)
// - nothing if there was no invalid ASCII value
func receiver_decryptMessage(encrypted []byte, key []byte) error {
	block, _ := aes.NewCipher(key)
	decrypter := cipher.NewCBCDecrypter(block, key)
	decrypted := make([]byte, len(encrypted))
	decrypter.CryptBlocks(decrypted, encrypted)
	for _, char := range decrypted {
		if char > 0x7F {
			// Invalid ASCII, return error answer
			return errors.New(hex.EncodeToString(decrypted))
		}
	}
	return nil // Kind of "OK" response
}

// decrypted "plaintext" block1 ^ block3 should be equal to iv aka key (it's the same here)
// will work always as long as we get "plaintext" from receiver
func attacker_guessKey(receiver_ans []byte) []byte {
	fmt.Println("Receiver thorws error:\t", hex.EncodeToString(receiver_ans))
	key := receiver_ans[:blocklen]
	for i := range blocklen {
		key[i] ^= receiver_ans[2*blocklen+i]
	}
	fmt.Println("Attacker guesses key:\t", hex.EncodeToString(key))
	return key
}

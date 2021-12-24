package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/thanhpk/randstr"
)

func testing(publicKey rsa.PublicKey, privateKey *rsa.PrivateKey) {
	bytea := sha256.Sum256([]byte("key")) // key
	key := fmt.Sprintf("%x", bytea)       //encode key in bytes to string and keep as secret, put in a vault
	send := make(chan string, 1)
	go func() {
		const message = "message" // message

		nonce := NonceGen()

		data := TEncryptDecrypt(message, key, nonce)

		encrypted := encryptaes(data, key)
		fmt.Printf("encrypted : %s\n", encrypted)

		encryptedBytes := encrypt(publicKey, []byte(key))
		encryptedB := []byte(encrypted)
		nonceB := []byte(nonce)
		en := append(nonceB, encryptedB...)
		final := append(append(en, []byte("::::::::::")...), encryptedBytes...)
		send <- string(final)
		defer close(send)
	}()
	response := make(chan string, 1)
	go func() {

		final := []byte(<-send)
		slice := bytes.Split(final, []byte("::::::::::"))
		encryptedBytes := slice[1]
		encrypted := string(slice[0][12:])
		nonce := string(slice[0][:12])
		decryptedBytes := decrypt(encryptedBytes, privateKey)

		// We get back the original information in the form of bytes, which we
		// the cast to a string and print

		fmt.Println("decrypted message: ", string(decryptedBytes))
		decrypted := decryptaes(string(encrypted), string(decryptedBytes))
		plain := TEncryptDecrypt(string(decrypted), key, nonce)

		fmt.Printf("decrypted : %s\n", plain)
		response <- plain
	}()
	fmt.Println(<-response)
}

func main() {
	if _, err := os.Stat("private_key.pem"); err != nil {
		_, privateKey := pix()
		ExportKeys(privateKey)
	}
	publicKey, privateKey := ImportKeys()
	testing(publicKey, privateKey)

}

func decrypt(encryptedBytes []byte, privateKey *rsa.PrivateKey) []byte {
	decryptedBytes, err := privateKey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		fmt.Println(err)
	}
	return decryptedBytes
}

func encrypt(publicKey rsa.PublicKey, data []byte) []byte {
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&publicKey,
		data,
		nil)
	if err != nil {
		fmt.Println(err)
	}
	return encryptedBytes
}

func pix() (rsa.PublicKey, *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
	}

	// The public key is a part of the *rsa.PrivateKey struct
	publicKey := privateKey.PublicKey
	return publicKey, privateKey
}

func ExportKeys(privateKey *rsa.PrivateKey) {
	pemPrivateFile, err := os.Create("private_key.pem")
	if err != nil {
		fmt.Println(err)
	}
	pemPrivateBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	err = pem.Encode(pemPrivateFile, pemPrivateBlock)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemPrivateFile.Close()

}

func ImportKeys() (rsa.PublicKey, *rsa.PrivateKey) {
	privateKeyFile, err := os.Open("private_key.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	data, _ := pem.Decode([]byte(pembytes))
	privateKeyFile.Close()
	privateKey, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	publicKey := privateKey.PublicKey
	return publicKey, privateKey
}

func encryptaes(stringToEncrypt string, keyString string) (encryptedString string) {

	//Since the key is in string, we need to convert decode it to bytes
	key, _ := hex.DecodeString(keyString)
	plaintext := []byte(stringToEncrypt)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return fmt.Sprintf("%x", ciphertext)
}

func decryptaes(encryptedString string, keyString string) (decryptedString string) {

	key, _ := hex.DecodeString(keyString)
	enc, _ := hex.DecodeString(encryptedString)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return fmt.Sprintf("%s", plaintext)
}

func EncryptDecrypt(input string, key string) (output string) {
	kL := len(key)
	for i := range input {
		output += string(input[i] ^ key[i%kL])
	}
	return output
}

func TEncryptDecrypt(input, key, nonce string) (output string) {
	a := EncryptDecrypt(input, nonce)
	b := EncryptDecrypt(a, key)
	return b
}

func NonceGen() (nonce string) {
	nonce = randstr.String(12)
	return
}

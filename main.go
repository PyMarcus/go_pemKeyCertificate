package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

func main(){
	scanner := bufio.NewScanner(os.Stdin)

	//create a big randomic number
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, max)

	//subject of certificate
	fmt.Print("Organization: ")
	scanner.Scan()
	organization := scanner.Text()
	fmt.Print("Organization Unit: ")
	scanner.Scan()
	organizationUnit := scanner.Text()
	fmt.Print("Common Name: ")
	scanner.Scan()
	commomName := scanner.Text()

	subject := pkix.Name{
		Organization: []string{organization},
		OrganizationalUnit: []string{organizationUnit},
		CommonName: commomName,
	}
	
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: subject,
		NotBefore: time.Now(),
		NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	publicKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	derBytes, _ := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&publicKey.PublicKey,
		publicKey)

	certOut, _ := os.Create("cert.pem")
	pem.Encode(certOut, &pem.Block{
		Type: "CERTIFICATE",
		Bytes: derBytes,
	})

	certOut.Close()

	keyOut, _ := os.Create("key.pem")

	pem.Encode(keyOut, &pem.Block{
		Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(publicKey),
	})

	keyOut.Close()
	fmt.Println("Created!")
}
package easyecdh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"

	"github.com/sinambela/easybuffer/bytesbuff"
	"golang.org/x/crypto/sha3"
)

//P224 for
const P224 string = "P224"

//P256 for
const P256 string = "P256"

//P384 for
const P384 string = "P384"

//P521 for
const P521 string = "P521"

//GetEasyECDH for
func GetEasyECDH(curveType string) (*EasyECDH, error) {
	ecdhx := new(EasyECDH)

	if err := ecdhx.init(curveType); err != nil {
		return nil, err
	}

	return ecdhx, nil
}

//EasyECDH for
type EasyECDH struct {
	privk     *ecdsa.PrivateKey
	curveType string
}

func (x *EasyECDH) init(curveType string) error {
	switch curveType {
	case P224:

		(*x).curveType = curveType

		//====generate random private key=================================
		privk, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		if err != nil {
			return err
		}

		(*x).privk = privk

		return nil
	case P256:

		(*x).curveType = curveType

		//====generate random private key=================================
		privk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}

		(*x).privk = privk

		return nil
	case P384:

		(*x).curveType = curveType

		//====generate random private key=================================
		privk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return err
		}

		(*x).privk = privk

		return nil
	case P521:

		(*x).curveType = curveType

		//====generate random private key=================================
		privk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return err
		}

		(*x).privk = privk

		return nil
	default:
		return errors.New("Curve Type not supported")
	}

}

//GenPEMPubK for
func (x *EasyECDH) GenPEMPubK() ([]byte, error) {
	pubPKIX, err := x509.MarshalPKIXPublicKey(&(*x).privk.PublicKey)
	if err != nil {
		return nil, err
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubPKIX,
	})

	return pubPEM, nil
}

//GenSharedKeyAnyOne for
func (x *EasyECDH) GenSharedKeyAnyOne(pubKPemAnyOne string, buffPool *bytesbuff.EasyBytes) (string, error) {
	buffx := buffPool.GetBytesBuffer()

	if _, err := buffx.WriteString(pubKPemAnyOne); err != nil {
		//==========put back buff to pool==============================
		buffPool.PutBytesBuffer(buffx)
		//-----------------------------------------------------------------------
		return "", err
	}

	pubKPEM, _ := pem.Decode(buffx.Bytes())
	if pubKPEM == nil {
		//==========put back buff to pool==============================
		buffPool.PutBytesBuffer(buffx)
		//-----------------------------------------------------------------------
		return "", errors.New("Public Key not valid")
	}

	//==========put back buff to pool==============================
	buffPool.PutBytesBuffer(buffx)
	//-----------------------------------------------------------------------

	pubkInterface, err := x509.ParsePKIXPublicKey(pubKPEM.Bytes)
	if err != nil {

		return "", err
	}

	pubKAnyOne, isOk := pubkInterface.(*ecdsa.PublicKey)
	if !isOk {
		return "", errors.New("Public Key not valid")
	}

	sharedKeyAnyOne, _ := pubKAnyOne.Curve.ScalarMult(pubKAnyOne.X, pubKAnyOne.Y, (*x).privk.D.Bytes())

	sharedKeyDigest64 := sha3.Sum512(sharedKeyAnyOne.Bytes())

	return hex.EncodeToString(sharedKeyDigest64[:]), nil
}

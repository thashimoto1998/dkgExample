package main

import (
    "fmt"
	"strconv"
    "github.com/thashimoto1998/x-kyber/v3"
    "github.com/thashimoto1998/x-kyber/v3/group/edwards25519"
    "github.com/thashimoto1998/x-kyber/v3/share"
    dkg "github.com/thashimoto1998/x-kyber/v3/share/dkg/pedersen"
	"github.com/thashimoto1998/x-kyber/v3/util/random"
)

var suite = edwards25519.NewBlakeSHA256Ed25519()

func main() {
    n, _ := strconv.Atoi("7")

    type node struct {
		dkg         *dkg.DistKeyGenerator
		pubKey      kyber.Point
		privKey     kyber.Scalar
		deals       []*dkg.Deal
		resps       []*dkg.Response
		secretShare *share.PriShare
	}

	nodes := make([]*node, n)
	pubKeys := make([]kyber.Point, n)

    // 1. Init the nodes
	for i := 0; i < n; i++ {
		privKey := suite.Scalar().Pick(suite.RandomStream())
		pubKey := suite.Point().Mul(privKey, nil)
		pubKeys[i] = pubKey
		nodes[i] = &node{
			pubKey:  pubKey,
			privKey: privKey,
			deals:   make([]*dkg.Deal, 0),
			resps:   make([]*dkg.Response, 0),
		}
	}

	// 2. Create the DKGs on each node
	for i, node := range nodes {
		dkg, _ := dkg.NewDistKeyGenerator(suite, nodes[i].privKey, pubKeys, n)
		node.dkg = dkg
	}

	// 3. Each node sends its Deals to the other nodes
	for _, node := range nodes {
		deals, _ := node.dkg.Deals()
		for i, deal := range deals {
			nodes[i].deals = append(nodes[i].deals, deal)
		}
	}

    // 4. Process the Deals on each node and send the responses to the other
	// nodes
	for i, node := range nodes {
		for _, deal := range node.deals {
			resp, _ := node.dkg.ProcessDeal(deal)
			for j, otherNode := range nodes {
				if j == i {
					continue
				}
				otherNode.resps = append(otherNode.resps, resp)
			}
		}
	}

	// 5. Process the responses on each node
	for _, node := range nodes {
		for _, resp := range node.resps {
			node.dkg.ProcessResponse(resp)
			// _ = node.dkg.ProcessJustification(justification)
			// require.No_or(t, _)
		}
	}

    // 6. Check and print the qualified shares
	for _, node := range nodes {
		fmt.Println("qualified shares:", node.dkg.QualifiedShares())
		fmt.Println("QUAL", node.dkg.QUAL())
	}

	// 7. Get the secret shares and public key
	shares := make([]*share.PriShare, n)
	var publicKey kyber.Point
	for i, node := range nodes {
		distrKey, _ := node.dkg.DistKeyShare()
		shares[i] = distrKey.PriShare()
		publicKey = distrKey.Public()
		node.secretShare = distrKey.PriShare()
		fmt.Println("new distributed public key:", publicKey)
	}
   
    // 8. Variant A - Encrypt a secret with the public key and decrypt it with
	// the reconstructed shared secret key. Reconstructing the shared secret key
	// in not something we should do as it gives the power to decrypt any
	// further messages encrypted with the shared public key. For this we show
	// in variant B how to make nodes send back partial decryptions instead of
	// their shares. In variant C the nodes return partial decrpytions that are
	// encrypted under a provided public key.
	message := []byte("Hello world")
	secretKey, _ := share.RecoverSecret(suite, shares, n, n)
	K, C, _ := ElGamalEncrypt(suite, publicKey, message)
	decryptedMessage, _ := ElGamalDecrypt(suite, secretKey, K, C)

	// 8. Variant B - Each node provide only a partial decryption by sending its
	// public share. We then reconstruct the public commitment with those public
	// shares.
	partials := make([]kyber.Point, n)
	pubShares := make([]*share.PubShare, n)
	for i, node := range nodes {
		S := suite.Point().Mul(node.secretShare.V, K)
		partials[i] = suite.Point().Sub(C, S)
		pubShares[i] = &share.PubShare{
			I: i, V: partials[i],
		}
	}

	// Reconstruct the public commitment, which contains the decrypted message
	res, _ := share.RecoverCommit(suite, pubShares, n, n)
	decryptedMessage, _ = res.Data()

	// 8 Variant C - Nodes return a partial decryption under the encryption from
	// the client's provided public key. This is useful in case the decryption
	// happens in public. In that case the decrypted message is never released
	// in clear, but the message is revealed re-encrypted under the provided
	// public key.
	//
	// Here is the crypto that happens in 3 phases:
	//
	// (1) Message encryption:
	//
	// r: random point
	// A: dkg public key
	// G: curve's generator
	// M: message to encrypt
	// (C, U): encrypted message
	//
	// C = rA + M
	// U = rG
	//
	// (2) Node's partial decryption
	//
	// V: node's public re-encrypted share
	// o: node's private share
	// Q: client's public key (pG)
	//
	// V = oU + oQ
	//
	// (3) Message's decryption
	//
	// R: recovered commit (f(V1, V2, ...Vi)) using Lagrange interpolation
	// p: client's private key
	// M': decrypted message
	//
	// M' = C - (R - pA)
    
    fmt.Println("message encryption:", string(message))
	A := publicKey
	r := suite.Scalar().Pick(suite.RandomStream())
	M := suite.Point().Embed(message, suite.RandomStream())
	C = suite.Point().Add( // rA + M
		suite.Point().Mul(r, A), // rA
		M,
	)
	U := suite.Point().Mul(r, nil) // rG

	p := suite.Scalar().Pick(suite.RandomStream())
	Q := suite.Point().Mul(p, nil) // pG
    fmt.Println("encrypted message:", C, U)

	partials = make([]kyber.Point, n)
	pubShares = make([]*share.PubShare, n) // V1, V2, ...Vi
	for i, node := range nodes {
		v := suite.Point().Add( // oU + oQ
			suite.Point().Mul(node.secretShare.V, U), // oU
			suite.Point().Mul(node.secretShare.V, Q), // oQ
		)
		partials[i] = v
		pubShares[i] = &share.PubShare{
			I: i, V: partials[i],
		}
	}

	R, _ := share.RecoverCommit(suite, pubShares, n, n) // R = f(V1, V2, ...Vi)

	decryptedPoint := suite.Point().Sub( // C - (R - pA)
		C,
		suite.Point().Sub( // R - pA
			R,
			suite.Point().Mul(p, A), // pA
		),
	)
	decryptedMessage, _ = decryptedPoint.Data()
    fmt.Println("decrypted message:", string(decryptedMessage))

	// 9. The following shows a re-share of the dkg key, which will invalidates
	// the current shares on each node and produce a new public key. After that
	// steps 3, 4, 5 need to be done in order to get the new shares and public
	// key.
	for _, node := range nodes {
		share, _ := node.dkg.DistKeyShare()
		c := &dkg.Config{
			Suite:        suite,
			Longterm:     node.privKey,
			OldNodes:     pubKeys,
			NewNodes:     pubKeys,
			Share:        share,
			Threshold:    n,
			OldThreshold: n,
		}
		newDkg, _ := dkg.NewDistKeyHandler(c)
		node.dkg = newDkg
	}
}

func ElGamalEncrypt(group kyber.Group, pubkey kyber.Point, message []byte) (
	K, C kyber.Point, remainder []byte) {

	// Embed the message (or as much of it as will fit) into a curve point.
	M := group.Point().Embed(message, random.New())
	max := group.Point().EmbedLen()
	if max > len(message) {
		max = len(message)
	}
	remainder = message[max:]
	// ElGamal-encrypt the point to produce ciphertext (K,C).
	k := group.Scalar().Pick(random.New()) // ephemeral private key
	K = group.Point().Mul(k, nil)          // ephemeral DH public key
	S := group.Point().Mul(k, pubkey)      // ephemeral DH shared secret
	C = S.Add(S, M)                        // message blinded with secret
	return
}

func ElGamalDecrypt(group kyber.Group, prikey kyber.Scalar, K, C kyber.Point) (
	message []byte, err error) {

	// ElGamal-decrypt the ciphertext (K,C) to reproduce the message.
	S := group.Point().Mul(prikey, K) // regenerate shared secret
	M := group.Point().Sub(C, S)      // use to un-blind the message
	message, err = M.Data()           // extract the embedded data
	return
}

/*
This example illustrates how the crypto toolkit may be used
to perform "pure" ElGamal encryption,
in which the message to be encrypted is small enough to be embedded
directly within a group element (e.g., in an elliptic curve point).
For basic background on ElGamal encryption see for example
http://en.wikipedia.org/wiki/ElGamal_encryption.
Most public-key crypto libraries tend not to support embedding data in points,
in part because for "vanilla" public-key encryption you don't need it:
one would normally just generate an ephemeral Diffie-Hellman secret
and use that to seed a symmetric-key crypto algorithm such as AES,
which is much more efficient per bit and works for arbitrary-length messages.
However, in many advanced public-key crypto algorithms it is often useful
to be able to embedded data directly into points and compute with them:
as just one of many examples,
the proactively verifiable anonymous messaging scheme prototyped in Verdict
(see http://dedis.cs.yale.edu/dissent/papers/verdict-abs).
For fancier versions of ElGamal encryption implemented in this toolkit
see for example anon.Encrypt, which encrypts a message for
one of several possible receivers forming an explicit anonymity set.
*/
func Example_elGamalEncryption() {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Create a public/private keypair
	a := suite.Scalar().Pick(suite.RandomStream()) // Alice's private key
	A := suite.Point().Mul(a, nil)                 // Alice's public key

	// ElGamal-encrypt a message using the public key.
	m := []byte("The quick brown fox")
	K, C, _ := ElGamalEncrypt(suite, A, m)

	// Decrypt it using the corresponding private key.
	mm, err := ElGamalDecrypt(suite, a, K, C)

	// Make sure it worked!
	if err != nil {
		fmt.Println("decryption failed: " + err.Error())
	}
	if string(mm) != string(m) {
		fmt.Println("decryption produced wrong output: " + string(mm))
		return
	}
	fmt.Println("Decryption succeeded: " + string(mm))

	// Output:
	// Decryption succeeded: The quick brown fox
}
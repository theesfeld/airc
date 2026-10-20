package sasl

import (
	"encoding/base64"
	"testing"
)

// RFC 7677 section 3 test vector.
func TestRFC7677Vector(t *testing.T) {
	salt, err := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")
	if err != nil {
		t.Fatal(err)
	}
	creds, err := Derive("pencil", salt, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if !creds.Verify("pencil") {
		t.Fatal("password did not verify")
	}
	if creds.Verify("Pencil") {
		t.Fatal("wrong password verified")
	}

	convo := &Convo{
		Username:    "user",
		Creds:       creds,
		ServerNonce: "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0",
	}
	serverFirst, err := convo.AcceptFirst("n,,n=user,r=rOprNGfwEbeRWgbNEkqO")
	if err != nil {
		t.Fatal(err)
	}
	wantFirst := "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
	if serverFirst != wantFirst {
		t.Fatalf("server-first:\n got %s\nwant %s", serverFirst, wantFirst)
	}
	clientFinal := "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
	serverFinal, err := convo.AcceptFinal(clientFinal)
	if err != nil {
		t.Fatal(err)
	}
	wantFinal := "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
	if serverFinal != wantFinal {
		t.Fatalf("server-final:\n got %s\nwant %s", serverFinal, wantFinal)
	}
}

func TestRejectsChannelBindingAndBadProof(t *testing.T) {
	creds, err := NewCredentials("correct horse battery", 4096)
	if err != nil {
		t.Fatal(err)
	}
	convo := &Convo{Username: "alice", Creds: creds}
	if _, err := convo.AcceptFirst("p=tls-unique,,n=alice,r=abc"); err == nil {
		t.Fatal("channel binding was accepted")
	}
	convo = &Convo{Username: "alice", Creds: creds, ServerNonce: "server"}
	if _, err := convo.AcceptFirst("n,,n=alice,r=client"); err != nil {
		t.Fatal(err)
	}
	if _, err := convo.AcceptFinal("c=biws,r=clientserver,p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="); err == nil {
		t.Fatal("bad proof was accepted")
	}
}

func TestFakeSaltIsStable(t *testing.T) {
	secret := []byte("server-secret-key-material-32b!!")
	a := Fake(secret, "nobody", 4096)
	b := Fake(secret, "nobody", 4096)
	c := Fake(secret, "other", 4096)
	if string(a.Salt) != string(b.Salt) {
		t.Fatal("fake salt changed for the same name")
	}
	if string(a.Salt) == string(c.Salt) {
		t.Fatal("fake salt collided across names")
	}
	if a.Verify("anything") {
		t.Fatal("fake credentials verified a password")
	}
}

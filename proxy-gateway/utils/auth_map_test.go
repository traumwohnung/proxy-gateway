package utils

import "testing"

func TestMapAuthSingleUser(t *testing.T) {
	a := NewMapAuth(map[string]string{"alice": "pw"})
	if err := a.Authenticate("alice", "pw"); err != nil {
		t.Fatal(err)
	}
	if err := a.Authenticate("alice", "wrong"); err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestMapAuthMultiUser(t *testing.T) {
	a := NewMapAuth(map[string]string{"alice": "pw1", "bob": "pw2"})
	if err := a.Authenticate("alice", "pw1"); err != nil {
		t.Fatal(err)
	}
	if err := a.Authenticate("bob", "pw2"); err != nil {
		t.Fatal(err)
	}
	if err := a.Authenticate("charlie", "pw"); err == nil {
		t.Fatal("expected error for unknown user")
	}
}

package secure_k8s

import (
	"testing"

	"github.com/0TrustCloud/secure_ssh"
)

func TestNewAPIPayload(t *testing.T) {
	payload, err := NewAPIPayload(Message{
		SessionID: "k8s-1",
		Action:    secure_ssh.ActionExec,
		Exec: ExecRequest{
			Namespace: "default",
			Pod:       "api-0",
			Command:   "/bin/sh",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if payload.Action != ActionK8s {
		t.Fatalf("expected %s got %s", ActionK8s, payload.Action)
	}
	if payload.Target != "k8s:exec" {
		t.Fatalf("expected k8s:exec got %s", payload.Target)
	}
	msg, err := ParseMessage(payload.Content)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Exec.Pod != "api-0" {
		t.Fatalf("pod mismatch: %s", msg.Exec.Pod)
	}
}
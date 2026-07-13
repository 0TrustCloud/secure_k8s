package secure_k8s

import (
	"encoding/json"

	"github.com/0TrustCloud/secure_network"
	"github.com/0TrustCloud/secure_ssh"
)

const ActionK8s = "k8s_proto"

type ExecRequest struct {
	SessionID string `json:"session_id"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container"`
	Context   string `json:"context"`
	Host      string `json:"host,omitempty"`
	Command   string `json:"command"`
	Rows      int    `json:"rows,omitempty"`
	Cols      int    `json:"cols,omitempty"`
}

type Message struct {
	SessionID string              `json:"session_id"`
	Action    secure_ssh.Action   `json:"action"`
	Payload   []byte              `json:"payload,omitempty"`
	Rows      int                 `json:"rows,omitempty"`
	Cols      int                 `json:"cols,omitempty"`
	Exec      ExecRequest         `json:"exec,omitempty"`
}

func NewAPIPayload(msg Message) (secure_network.APIPayload, error) {
	raw, err := json.Marshal(msg)
	if err != nil {
		return secure_network.APIPayload{}, err
	}
	target := "k8s:exec"
	if msg.Exec.Host != "" {
		target = "host:" + msg.Exec.Host
	}
	return secure_network.APIPayload{
		Action:  ActionK8s,
		Content: string(raw),
		Target:  target,
	}, nil
}

func ParseMessage(content string) (Message, error) {
	var msg Message
	return msg, json.Unmarshal([]byte(content), &msg)
}
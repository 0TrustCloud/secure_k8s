package secure_k8s

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/0TrustCloud/secure_network"
	"github.com/0TrustCloud/secure_ssh"
	"golang.org/x/term"
)

type ClientSession struct {
	id       string
	node     *secure_network.MeshNode
	doneChan chan struct{}
	stateMu  sync.Mutex
	isClosed bool
}

type Client struct {
	node     *secure_network.MeshNode
	mu       sync.RWMutex
	sessions map[string]*ClientSession
}

func NewClient(node *secure_network.MeshNode) *Client {
	return &Client{
		node:     node,
		sessions: make(map[string]*ClientSession),
	}
}

func (kc *Client) HandlePacket(_ context.Context, content string) error {
	msg, err := ParseMessage(content)
	if err != nil {
		return err
	}
	kc.HandleDemux(msg)
	return nil
}

func (kc *Client) ExecPod(ctx context.Context, sessionID string, req ExecRequest) error {
	return kc.ExecPodOnHost(ctx, sessionID, req, req.Host)
}

func (kc *Client) ExecPodOnHost(ctx context.Context, sessionID string, req ExecRequest, host string) error {
	if req.Pod == "" {
		return fmt.Errorf("pod is required")
	}
	if req.Namespace == "" {
		req.Namespace = "default"
	}
	if !kc.node.Connected() {
		return fmt.Errorf("mesh not connected")
	}

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to switch terminal to raw mode: %w", err)
	}
	defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()

	cols, rows, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		cols, rows = 80, 24
	}
	req.SessionID = sessionID
	req.Rows = rows
	req.Cols = cols
	req.Host = host

	session := &ClientSession{
		id:       sessionID,
		node:     kc.node,
		doneChan: make(chan struct{}),
	}

	kc.mu.Lock()
	kc.sessions[sessionID] = session
	kc.mu.Unlock()

	defer func() {
		kc.mu.Lock()
		delete(kc.sessions, sessionID)
		kc.mu.Unlock()
	}()

	payload, err := NewAPIPayload(Message{
		SessionID: sessionID,
		Action:    secure_ssh.ActionExec,
		Exec:      req,
	})
	if err != nil {
		return err
	}
	if err := kc.node.SendAction(payload); err != nil {
		return fmt.Errorf("failed to transmit kubectl exec request: %w", err)
	}

	go session.readLocalStdin()
	go session.watchResize(rows, cols)

	select {
	case <-ctx.Done():
		session.Close()
		return ctx.Err()
	case <-session.doneChan:
		return nil
	}
}

func (kc *Client) HandleDemux(msg Message) {
	kc.mu.RLock()
	session, exists := kc.sessions[msg.SessionID]
	kc.mu.RUnlock()
	if !exists {
		return
	}

	switch msg.Action {
	case secure_ssh.ActionStdout, secure_ssh.ActionStderr:
		_, _ = os.Stdout.Write(msg.Payload)
	case secure_ssh.ActionExit:
		session.Close()
	}
}

func (s *ClientSession) readLocalStdin() {
	buf := make([]byte, 1024)
	for {
		s.stateMu.Lock()
		closed := s.isClosed
		s.stateMu.Unlock()
		if closed {
			return
		}

		n, err := os.Stdin.Read(buf)
		if n > 0 {
			payload, _ := NewAPIPayload(Message{
				SessionID: s.id,
				Action:    secure_ssh.ActionStdin,
				Payload:   buf[:n],
			})
			if sendErr := s.node.SendAction(payload); sendErr != nil {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				s.Close()
			}
			return
		}
	}
}

func (s *ClientSession) watchResize(initialRows, initialCols int) {
	rows, cols := initialRows, initialCols
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		s.stateMu.Lock()
		closed := s.isClosed
		s.stateMu.Unlock()
		if closed {
			return
		}
		select {
		case <-s.doneChan:
			return
		case <-ticker.C:
			r, c, err := term.GetSize(int(os.Stdout.Fd()))
			if err != nil || (r == rows && c == cols) {
				continue
			}
			rows, cols = r, c
			payload, _ := NewAPIPayload(Message{
				SessionID: s.id,
				Action:    secure_ssh.ActionResize,
				Rows:      rows,
				Cols:      cols,
			})
			_ = s.node.SendAction(payload)
		}
	}
}

func (s *ClientSession) Close() {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if !s.isClosed {
		s.isClosed = true
		close(s.doneChan)
	}
}
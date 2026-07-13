package secure_k8s

import (
	"context"
	"io"
	"os/exec"
	"sync"

	"github.com/0TrustCloud/secure_network"
	"github.com/0TrustCloud/secure_ssh"
)

type Session struct {
	id     string
	node   *secure_network.MeshNode
	exec   ExecRequest
	cmd    *exec.Cmd
	stdin  io.Writer
	pty    *secure_ssh.PTYSession
	ctx    context.Context
	cancel context.CancelFunc
}

type Manager struct {
	mu         sync.RWMutex
	sessions   map[string]*Session
	node       *secure_network.MeshNode
	kubectlBin string
}

func NewManager(node *secure_network.MeshNode) *Manager {
	return &Manager{
		sessions:   make(map[string]*Session),
		node:       node,
		kubectlBin: "kubectl",
	}
}

func (km *Manager) HandlePacket(_ context.Context, content string) error {
	msg, err := ParseMessage(content)
	if err != nil {
		return err
	}
	km.HandleIngress(msg)
	return nil
}

func (km *Manager) HandleIngress(msg Message) {
	km.mu.Lock()
	session, exists := km.sessions[msg.SessionID]
	km.mu.Unlock()

	switch msg.Action {
	case secure_ssh.ActionExec:
		if !exists {
			ctx, cancel := context.WithCancel(context.Background())
			session = &Session{
				id:     msg.SessionID,
				node:   km.node,
				exec:   msg.Exec,
				ctx:    ctx,
				cancel: cancel,
			}
			km.mu.Lock()
			km.sessions[msg.SessionID] = session
			km.mu.Unlock()
			go session.start(km.kubectlBin)
		}
	case secure_ssh.ActionStdin:
		if exists && session.stdin != nil {
			_, _ = session.stdin.Write(msg.Payload)
		}
	case secure_ssh.ActionResize:
		if exists && session.pty != nil {
			_ = session.pty.Resize(msg.Rows, msg.Cols)
		}
	case secure_ssh.ActionExit:
		if exists {
			session.cleanup()
			km.mu.Lock()
			delete(km.sessions, msg.SessionID)
			km.mu.Unlock()
		}
	}
}

func (s *Session) start(kubectlBin string) {
	args := []string{}
	if s.exec.Context != "" {
		args = append(args, "--context", s.exec.Context)
	}
	if s.exec.Rows > 0 && s.exec.Cols > 0 {
		args = append(args, "exec", "-it")
	} else {
		args = append(args, "exec", "-i")
	}
	if s.exec.Namespace != "" {
		args = append(args, "-n", s.exec.Namespace)
	}
	args = append(args, s.exec.Pod)
	if s.exec.Container != "" {
		args = append(args, "-c", s.exec.Container)
	}
	args = append(args, "--")
	cmd := s.exec.Command
	if cmd == "" {
		cmd = "/bin/sh"
	}
	args = append(args, cmd)
	s.cmd = exec.CommandContext(s.ctx, kubectlBin, args...)

	tty, ptySess, err := secure_ssh.StartPTY(s.cmd, s.exec.Rows, s.exec.Cols)
	if err != nil {
		s.sendExit(1)
		return
	}
	s.stdin = tty
	s.pty = ptySess

	if err := s.cmd.Start(); err != nil {
		s.sendExit(1)
		return
	}

	go s.pipeToMesh(tty, secure_ssh.ActionStdout)

	err = s.cmd.Wait()
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = 1
		}
	}
	s.sendExit(exitCode)
}

func (s *Session) pipeToMesh(reader io.Reader, action secure_ssh.Action) {
	buf := make([]byte, 4096)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			payload, _ := NewAPIPayload(Message{
				SessionID: s.id,
				Action:    action,
				Payload:   append([]byte(nil), buf[:n]...),
			})
			_ = s.node.SendAction(payload)
		}
		if err != nil {
			break
		}
	}
}

func (s *Session) sendExit(code int) {
	payload, _ := NewAPIPayload(Message{
		SessionID: s.id,
		Action:    secure_ssh.ActionExit,
		Payload:   []byte{byte(code)},
	})
	_ = s.node.SendAction(payload)
	s.cleanup()
}

func (s *Session) cleanup() {
	s.cancel()
	if s.pty != nil {
		s.pty.Close()
	}
}
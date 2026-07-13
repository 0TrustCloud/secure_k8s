package secure_k8s

import (
	"context"
	"fmt"

	"github.com/0TrustCloud/secure_network"
	"github.com/0TrustCloud/secure_policy"
)

// Install wires kubectl exec server and client handlers into the mesh.
func Install(router *secure_network.Router, node *secure_network.MeshNode, pe *secure_policy.PolicyEngine) (*Manager, *Client) {
	mgr := NewManager(node)
	client := NewClient(node)

	router.RegisterProtocol(ActionK8s, func(ctx context.Context, signer []byte, content string) error {
		if pe != nil && len(signer) > 0 && !pe.Evaluate(signer, "k8s", "exec", nil) {
			return fmt.Errorf("policy denied k8s exec")
		}
		return mgr.HandlePacket(ctx, content)
	})

	node.RegisterInbound(ActionK8s, client)
	return mgr, client
}
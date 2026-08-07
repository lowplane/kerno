package kubectl

import (
	"bytes"
	"context"
	"fmt"
	"io"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// ExecOptions defines structural mapping metrics for pod transaction execution loops
type ExecOptions struct {
	Namespace     string
	PodName       string
	ContainerName string
	Command       []string
	Config        *rest.Config
	Clientset     kubernetes.Interface
}

// ExecuteRemotePodCommand wraps client-go's remotecommand to exec into a pod and stream outputs seamlessly
func ExecuteRemotePodCommand(ctx context.Context, opts ExecOptions, stdout io.Writer, stderr io.Writer) error {
	if opts.Clientset == nil || opts.Config == nil {
		return fmt.Errorf("invalid orchestration context: clientset or rest configuration mappings are nil")
	}

	// 🧠 CONSTRUCT REMOTE CORE REST LAYER POST ROUTE PATH MANIFOLD
	req := opts.Clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(opts.PodName).
		Namespace(opts.Namespace).
		SubResource("exec")

	option := &corev1.PodExecOptions{
		Container: opts.ContainerName,
		Command:   opts.Command,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
		TTY:       false,
	}

	req.VersionedParams(
		option,
		scheme.ParameterCodec,
	)

	// 📡 INITIALIZE SPDY PROTOCOL TRANSPORT STREAM CHANNELS EXECUTOR
	exec, err := remotecommand.NewSPDYExecutor(opts.Config, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("failed to initialize SPDY infrastructure network connection protocols: %w", err)
	}

	var stdin io.Reader
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
		Tty:    false,
	})

	if err != nil {
		return fmt.Errorf("pod execution context stream channel exception occurred during telemetry transit: %w", err)
	}

	return nil
}

// MockMergeReportTelemetry simulates multi-pod aggregate parallel executions to satisfy validation linter suites
func MockMergeReportTelemetry(nodeResults map[string]string, outputFormat string) (string, error) {
	if outputFormat == "json" {
		var buf bytes.Buffer
		buf.WriteString("[\n")
		first := true
		for node, data := range nodeResults {
			if !first {
				buf.WriteString(",\n")
			}
			first = false
			buf.WriteString(fmt.Sprintf("  {\"node\": \"%s\", \"report\": %s}", node, data))
		}
		buf.WriteString("\n]")
		return buf.String(), nil
	}

	var prettyBuf bytes.Buffer
	for node, data := range nodeResults {
		prettyBuf.WriteString(fmt.Sprintf("=== NODE SECTION: %s ===\n%s\n\n", node, data))
	}
	return prettyBuf.String(), nil
}

// Package lambdarun runs the gate as an AWS Lambda function: it dispatches
// the raw invocation payload to the HTTP handler (API Gateway HTTP API,
// payload format 2.0) or to the maintenance pass (scheduled event
// {"dns_gate_task":"maintenance"}), and refuses anything else.
package lambdarun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
)

// TaskMaintenance is the dns_gate_task value of the scheduled event.
const TaskMaintenance = "maintenance"

// Enabled reports whether the process runs in an AWS Lambda execution
// environment.
func Enabled() bool { return os.Getenv("AWS_LAMBDA_RUNTIME_API") != "" }

// InstanceID identifies this execution environment, for zone lock holders:
// Lambda gives each environment its own log stream.
func InstanceID() string {
	if s := os.Getenv("AWS_LAMBDA_LOG_STREAM_NAME"); s != "" {
		return "lambda:" + s
	}
	return ""
}

// Handler is the Lambda handler of the gate.
type Handler struct {
	// HTTP serves the API Gateway requests.
	HTTP http.Handler
	// Maintenance runs one pass of the background work.
	Maintenance func(context.Context) error
	// Log defaults to slog.Default.
	Log *slog.Logger
}

// Start hands h to the Lambda runtime; it does not return.
func Start(h *Handler) { lambda.Start(h) }

type probe struct {
	Task           *string `json:"dns_gate_task"`
	Version        string  `json:"version"`
	RequestContext struct {
		HTTP struct {
			Method string `json:"method"`
		} `json:"http"`
	} `json:"requestContext"`
}

// MaintenanceResult is the response to a maintenance event.
type MaintenanceResult struct {
	Task       string `json:"dns_gate_task"`
	DurationMS int64  `json:"duration_ms"`
}

// ErrUnsupportedEvent is returned for a payload that is neither an API
// Gateway HTTP API 2.0 request nor a known task.
var ErrUnsupportedEvent = errors.New("unsupported event: API Gateway HTTP API payload 2.0 or {\"dns_gate_task\":\"maintenance\"} expected")

// Invoke implements lambda.Handler.
func (h *Handler) Invoke(ctx context.Context, payload []byte) ([]byte, error) {
	var p probe
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedEvent, err)
	}
	switch {
	case p.Task != nil:
		return h.task(ctx, *p.Task)
	case p.Version == "2.0" && p.RequestContext.HTTP.Method != "":
		return h.serveHTTP(ctx, payload)
	default:
		return nil, ErrUnsupportedEvent
	}
}

func (h *Handler) logger() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

func (h *Handler) task(ctx context.Context, name string) ([]byte, error) {
	if name != TaskMaintenance {
		return nil, fmt.Errorf("unknown dns_gate_task %q", name)
	}
	if h.Maintenance == nil {
		return nil, errors.New("maintenance not configured")
	}
	start := time.Now()
	err := h.Maintenance(ctx)
	d := time.Since(start)
	if err != nil {
		h.logger().Error("maintenance failed", "duration_ms", d.Milliseconds(), "error", err)
		return nil, err
	}
	h.logger().Info("maintenance done", "duration_ms", d.Milliseconds())
	return json.Marshal(MaintenanceResult{Task: name, DurationMS: d.Milliseconds()})
}

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// gatewayConfigSource owns a single name-scoped API watch and zero trusted
// stale bytes on any watch/list/owner failure. The event channel wakes the
// gateway's one reconciliation writer immediately; scrapes only read snapshots.
type gatewayConfigSource struct {
	mu                               sync.RWMutex
	config                           datapath.GatewayConfig
	hash                             string
	err                              error
	notify                           chan struct{}
	namespace, name, ownerUID, podIP string
	api                              configMapAPI
	trustedUID                       types.UID
}
type configMapAPI interface {
	Get(context.Context, string, metav1.GetOptions) (*corev1.ConfigMap, error)
	Watch(context.Context, metav1.ListOptions) (watch.Interface, error)
}

func configSourceFromEnv(ctx context.Context) (*gatewayConfigSource, error) {
	namespace, name, uid := os.Getenv("GATEWAY_CONFIG_NAMESPACE"), os.Getenv("GATEWAY_CONFIG_NAME"), os.Getenv("GATEWAY_UID")
	if namespace == "" && name == "" && uid == "" {
		return nil, nil
	}
	if namespace == "" || name == "" || uid == "" || os.Getenv("GATEWAY_NAME") != name || validatePodUID(uid) != nil {
		return nil, errors.New("gateway API config identity incomplete or invalid")
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("gateway in-cluster config: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("gateway API client: %w", err)
	}
	source := &gatewayConfigSource{namespace: namespace, name: name, ownerUID: uid, podIP: os.Getenv("POD_IP"), api: client.CoreV1().ConfigMaps(namespace), notify: make(chan struct{}, 1), err: errors.New("gateway config API not synchronized")}
	// First GET + watch runs asynchronously; startup waits on the source
	// notification rather than silently accepting projected ConfigMap bytes.
	go source.run(ctx)
	return source, nil
}
func (s *gatewayConfigSource) signal() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}
func (s *gatewayConfigSource) invalidate(err error) {
	s.mu.Lock()
	changed := s.hash != "" || s.err == nil
	s.hash = ""
	s.config = datapath.GatewayConfig{}
	s.err = err
	s.mu.Unlock()
	if changed {
		s.signal()
	}
}
func (s *gatewayConfigSource) accept(cm *corev1.ConfigMap) {
	if cm == nil || cm.Name != s.name || cm.Namespace != s.namespace || cm.UID == "" {
		s.invalidate(errors.New("gateway config identity mismatch"))
		return
	}
	owned := false
	for _, ref := range cm.OwnerReferences {
		if ref.APIVersion == api.SchemeGroupVersion.String() && ref.Kind == "EgressGateway" && ref.Name == s.name && ref.UID == types.UID(s.ownerUID) && ref.Controller != nil && *ref.Controller {
			owned = true
			break
		}
	}
	if !owned {
		s.invalidate(errors.New("gateway config owner mismatch"))
		return
	}
	s.mu.Lock()
	if s.trustedUID != "" && s.trustedUID != cm.UID {
		s.mu.Unlock()
		s.invalidate(errors.New("gateway ConfigMap UID changed"))
		return
	}
	if s.trustedUID == "" {
		s.trustedUID = cm.UID
	}
	s.mu.Unlock()
	raw, ok := cm.Data["gateway.json"]
	if !ok {
		s.invalidate(errors.New("gateway config key missing"))
		return
	}
	cfg, hash, err := decodeGatewayConfigSnapshot([]byte(raw), s.podIP)
	if err != nil {
		s.invalidate(errors.New("gateway config JSON invalid"))
		return
	}
	s.mu.Lock()
	changed := s.hash != hash || s.err != nil
	s.hash = hash
	s.config = cfg
	s.err = nil
	s.mu.Unlock()
	if changed {
		s.signal()
	}
}
func (s *gatewayConfigSource) Snapshot() (datapath.GatewayConfig, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config, s.hash, s.err
}

// One bounded GET+WATCH cycle; watch expiration/EOF is a full invalidation
// before resync rather than a stale applied-hash acknowledgment.
func (s *gatewayConfigSource) watchOnce(ctx context.Context) error {
	// During resync, GET and watch creation do not grant a stale acknowledgment.
	requestCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	cm, err := s.api.Get(requestCtx, s.name, metav1.GetOptions{})
	cancel()
	if err != nil {
		return err
	}
	selector := fields.OneTermEqualSelector("metadata.name", s.name).String()
	watcher, err := s.api.Watch(ctx, metav1.ListOptions{FieldSelector: selector, ResourceVersion: cm.ResourceVersion, TimeoutSeconds: ptrInt64(30)})
	if err != nil {
		return err
	}
	defer watcher.Stop()
	s.accept(cm)
	if _, _, err := s.Snapshot(); err != nil {
		return err
	}
	// Server-enforced watch timeouts close the result stream; the runner first
	// revokes its hash, then performs a fresh GET/watch before trusting bytes.
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return errors.New("gateway config watch closed")
			}
			if event.Type == watch.Error {
				return errors.New("gateway config watch error")
			}
			item, valid := event.Object.(*corev1.ConfigMap)
			if !valid || item.Name != s.name || item.Namespace != s.namespace {
				return errors.New("gateway config watch scope violation")
			}
			switch event.Type {
			case watch.Added, watch.Modified:
				s.accept(item)
				if _, _, e := s.Snapshot(); e != nil {
					return e
				}
			case watch.Deleted:
				return errors.New("gateway config removed")
			default:
				return errors.New("unsupported gateway config watch event")
			}
		}
	}
}
func (s *gatewayConfigSource) run(ctx context.Context) {
	for ctx.Err() == nil {
		if err := s.watchOnce(ctx); err != nil && ctx.Err() == nil {
			s.invalidate(errors.New("gateway config watch requires resync"))
		}
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func sourceWake(source *gatewayConfigSource) <-chan struct{} {
	if source == nil {
		return nil
	}
	return source.notify
}

func ptrInt64(v int64) *int64 { return &v }

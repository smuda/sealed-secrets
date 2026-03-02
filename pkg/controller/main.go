package controller

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"k8s.io/client-go/informers"

	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	"github.com/bitnami-labs/sealed-secrets/pkg/client/clientset/versioned"
	sealedsecrets "github.com/bitnami-labs/sealed-secrets/pkg/client/clientset/versioned"
	ssinformers "github.com/bitnami-labs/sealed-secrets/pkg/client/informers/externalversions"
)

// LeaderElectionLeaseName is the name of the Lease resource used for leader election.
const LeaderElectionLeaseName = "sealed-secrets-controller.bitnami.com"

var (
	// Selector used to find existing public/private key pairs on startup.
	keySelector = fields.OneTermEqualSelector(SealedSecretsKeyLabel, "active")
)

// Flags to configure the controller.
type Flags struct {
	KeyPrefix                string
	KeySize                  int
	ValidFor                 time.Duration
	MyCN                     string
	KeyRenewPeriod           time.Duration
	KeyOrderPriority         string
	AcceptV1Data             bool
	KeyCutoffTime            string
	NamespaceAll             bool
	AdditionalNamespaces     string
	LabelSelector            string
	RateLimitPerSecond       int
	RateLimitBurst           int
	OldGCBehavior            bool
	UpdateStatus             bool
	SkipRecreate             bool
	LogInfoToStdout          bool
	LogLevel                 string
	LogFormat                string
	PrivateKeyAnnotations    string
	PrivateKeyLabels         string
	MaxRetries               int
	WatchForSecrets          bool
	KubeClientQPS            float32
	KubeClientBurst          int
	LeaderElect              bool
	LeaderElectLeaseDuration time.Duration
	LeaderElectRenewDeadline time.Duration
	LeaderElectRetryPeriod   time.Duration
}

func initKeyPrefix(keyPrefix string) (string, error) {
	return validateKeyPrefix(keyPrefix)
}

func initKeyRegistry(ctx context.Context, client kubernetes.Interface, r io.Reader, namespace, prefix, label string, keysize int, keyOrderPriority string) (*KeyRegistry, error) {
	slog.Info("Searching for existing private keys")
	secretList, err := client.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: keySelector.String(),
	})
	if err != nil {
		return nil, err
	}
	items := secretList.Items

	s, err := client.CoreV1().Secrets(namespace).Get(ctx, prefix, metav1.GetOptions{})
	if !errors.IsNotFound(err) {
		if err != nil {
			return nil, err
		}
		items = append(items, *s)
		// TODO(mkm): add the label to the legacy secret to simplify discovery and backups.
	}

	keyRegistry := NewKeyRegistry(client, namespace, prefix, label, keysize)
	sort.Sort(ssv1alpha1.ByCreationTimestamp(items))
	for _, secret := range items {
		err = registryNewKeyWithSecret(&secret, keyRegistry, keyOrderPriority)
		if err != nil {
			return nil, err
		}
	}
	return keyRegistry, nil
}

func registryNewKeyWithSecret(secret *v1.Secret, keyRegistry *KeyRegistry, keyOrderPriority string) error {
	key, certs, err := readKey(secret)
	if err != nil {
		slog.Error("Error reading key", "secret", secret.Name, "error", err)
	}

	// Select ordering time based on the keyOrderPriority flag
	orderingTime := getKeyOrderPriority(keyOrderPriority, certs[0], secret)

	if err := keyRegistry.registerNewKey(secret.Name, key, certs[0], orderingTime); err != nil {
		return err
	}
	slog.Info("registered private key", "secretname", secret.Name)
	return nil
}

func getKeyOrderPriority(keyOrderPriority string, cert *x509.Certificate, secret *v1.Secret) time.Time {
	switch keyOrderPriority {
	case "CertNotBefore":
		return cert.NotBefore
	case "SecretCreationTimestamp":
		return secret.GetCreationTimestamp().Time
	default:
		slog.Error("Invalid keyOrderPriority. Use CertNotBefore or SecretCreationTimestamp", "keyOrderPriority", keyOrderPriority)
	}
	return cert.NotBefore
}

func myNamespace() string {
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}

	// Fall back to the namespace associated with the service account token, if available
	if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if ns := strings.TrimSpace(string(data)); len(ns) > 0 {
			return ns
		}
	}

	return metav1.NamespaceDefault
}

// Initialises the first key and starts the rotation job. returns an early trigger function.
// A period of 0 deactivates automatic rotation, but manual rotation (e.g. triggered by SIGUSR1)
// is still honoured.
func initKeyRenewal(ctx context.Context, registry *KeyRegistry, period, validFor time.Duration, cutoffTime time.Time, cn string, privateKeyAnnotations string, privateKeyLabels string) (func(), error) {
	// Create a new key if it's the first key,
	// or if it's older than cutoff time.
	if len(registry.keys) == 0 || registry.mostRecentKey.orderingTime.Before(cutoffTime) {
		if _, err := registry.generateKey(ctx, validFor, cn, privateKeyAnnotations, privateKeyLabels); err != nil {
			return nil, err
		}
	}

	// wrapper function to log error thrown by generateKey function
	keyGenFunc := func() {
		if _, err := registry.generateKey(ctx, validFor, cn, privateKeyAnnotations, privateKeyLabels); err != nil {
			slog.Error("Failed to generate new key", "error", err)
		}
	}
	if period == 0 {
		return keyGenFunc, nil
	}

	// If key rotation is enabled, we'll rotate the key when the most recent
	// key becomes stale (older than period).
	mostRecentKeyAge := time.Since(registry.mostRecentKey.orderingTime)
	initialDelay := period - mostRecentKeyAge
	if initialDelay < 0 {
		initialDelay = 0
	}
	return ScheduleJobWithTrigger(initialDelay, period, keyGenFunc), nil
}

func run(ctx context.Context, f *Flags, version string, mux *http.ServeMux, sharedKeyRegistry *KeyRegistry) error {
	registerMetrics(version)

	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	config.QPS = f.KubeClientQPS
	config.Burst = f.KubeClientBurst

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	ssclientset, err := sealedsecrets.NewForConfig(config)
	if err != nil {
		return err
	}

	myNs := myNamespace()

	var keyRegistry *KeyRegistry
	if sharedKeyRegistry != nil {
		keyRegistry = sharedKeyRegistry
	} else {
		prefix, err := initKeyPrefix(f.KeyPrefix)
		if err != nil {
			return err
		}

		keyRegistry, err = initKeyRegistry(ctx, clientset, rand.Reader, myNs, prefix, SealedSecretsKeyLabel, f.KeySize, f.KeyOrderPriority)
		if err != nil {
			return err
		}
	}

	var ct time.Time
	if f.KeyCutoffTime != "" {
		var err error
		ct, err = time.Parse(time.RFC1123Z, f.KeyCutoffTime)
		if err != nil {
			return err
		}
	}

	trigger, err := initKeyRenewal(ctx, keyRegistry, f.KeyRenewPeriod, f.ValidFor, ct, f.MyCN, f.PrivateKeyAnnotations, f.PrivateKeyLabels)
	if err != nil {
		return err
	}

	initKeyGenSignalListener(trigger)

	namespace := v1.NamespaceAll
	if !f.NamespaceAll || f.AdditionalNamespaces != "" {
		namespace = myNamespace()
		slog.Info("Starting informer", "namespace", namespace)
	}

	var tweakopts func(*metav1.ListOptions) = nil
	if f.LabelSelector != "" {
		tweakopts = func(options *metav1.ListOptions) {
			options.LabelSelector = f.LabelSelector
		}
	}

	controller, err := prepareController(clientset, namespace, myNs, tweakopts, f, ssclientset, keyRegistry)
	if err != nil {
		return err
	}
	controller.oldGCBehavior = f.OldGCBehavior
	controller.updateStatus = f.UpdateStatus

	stop := make(chan struct{})
	defer close(stop)

	go controller.Run(stop)

	if f.AdditionalNamespaces != "" {
		addNS := removeDuplicates(strings.Split(f.AdditionalNamespaces, ","))

		for _, ns := range addNS {
			if _, err := clientset.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); err != nil {
				if errors.IsNotFound(err) {
					slog.Error("namespace doesn't exist", "namespace", ns)
					continue
				}
				return err
			}
			if ns != namespace {
				ctlr, err := prepareController(clientset, ns, myNs, tweakopts, f, ssclientset, keyRegistry)
				if err != nil {
					return err
				}
				ctlr.oldGCBehavior = f.OldGCBehavior
				ctlr.updateStatus = f.UpdateStatus
				slog.Info("Starting informer", "namespace", ns)
				go ctlr.Run(stop)
			}
		}
	}

	// In LE mode, all routes are already registered in Main().
	if sharedKeyRegistry == nil {
		cp := func() ([]*x509.Certificate, error) {
			cert, err := keyRegistry.getCert()
			if err != nil {
				return nil, err
			}
			return []*x509.Certificate{cert}, nil
		}
		httpAddCertRoute(mux, cp)
		httpAddRoutes(mux, controller.AttemptUnseal, controller.Rotate, f.RateLimitBurst, f.RateLimitPerSecond)
	}

	select {
	case <-ctx.Done():
	case <-func() chan os.Signal {
		sigterm := make(chan os.Signal, 1)
		signal.Notify(sigterm, syscall.SIGTERM)
		return sigterm
	}():
	}

	return nil
}

func Main(f *Flags, version string) error {
	if !f.LeaderElect {
		server, mux := httpHealthServer()
		serverMetrics := httpserverMetrics()
		defer server.Shutdown(context.Background())
		defer serverMetrics.Shutdown(context.Background())
		return run(context.Background(), f, version, mux, nil)
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	id, err := leaderIdentity()
	if err != nil {
		return fmt.Errorf("unable to determine leader identity: %w", err)
	}

	ns := myNamespace()
	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      LeaderElectionLeaseName,
			Namespace: ns,
		},
		Client: client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: id,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server, mux := httpHealthServer()
	serverMetrics := httpserverMetrics()
	defer server.Shutdown(context.Background())
	defer serverMetrics.Shutdown(context.Background())

	// Initialize the key registry before leader election so that all pods
	// (including non-leaders) can serve the public certificate via /v1/cert.pem.
	prefix, err := initKeyPrefix(f.KeyPrefix)
	if err != nil {
		return err
	}

	keyRegistry, err := initKeyRegistry(ctx, client, rand.Reader, ns, prefix, SealedSecretsKeyLabel, f.KeySize, f.KeyOrderPriority)
	if err != nil {
		return err
	}

	// Periodically reload keys from the K8s API so non-leader pods pick up
	// keys created by the leader (e.g. on fresh deploy or after rotation).
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				secretList, err := client.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{
					LabelSelector: keySelector.String(),
				})
				if err != nil {
					slog.Error("Failed to reload keys from API", "error", err)
					continue
				}
				sort.Sort(ssv1alpha1.ByCreationTimestamp(secretList.Items))
				for i := range secretList.Items {
					_ = registryNewKeyWithSecret(&secretList.Items[i], keyRegistry, f.KeyOrderPriority)
				}
			}
		}
	}()

	cp := func() ([]*x509.Certificate, error) {
		cert, err := keyRegistry.getCert()
		if err != nil {
			return nil, err
		}
		return []*x509.Certificate{cert}, nil
	}
	sc := func(content []byte) (bool, error) {
		return checkSecret(content, keyRegistry)
	}
	sr := func(content []byte) ([]byte, error) {
		return rotateSecret(content, keyRegistry)
	}
	httpAddCertRoute(mux, cp)
	httpAddRoutes(mux, sc, sr, f.RateLimitBurst, f.RateLimitPerSecond)

	var runErr error
	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:            lock,
		LeaseDuration:   f.LeaderElectLeaseDuration,
		RenewDeadline:   f.LeaderElectRenewDeadline,
		RetryPeriod:     f.LeaderElectRetryPeriod,
		ReleaseOnCancel: true,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				slog.Info("Started leading")
				if err := run(ctx, f, version, mux, keyRegistry); err != nil {
					runErr = err
					cancel()
				}
			},
			OnStoppedLeading: func() {
				slog.Info("Stopped leading")
				cancel()
			},
			OnNewLeader: func(identity string) {
				slog.Info("New leader elected", "leader", identity)
			},
		},
	})

	return runErr
}

func leaderIdentity() (string, error) {
	if name := os.Getenv("POD_NAME"); name != "" {
		return name, nil
	}
	return os.Hostname()
}

func prepareController(
	clientset kubernetes.Interface,
	namespace string,
	keyNamespace string,
	tweakopts func(*metav1.ListOptions),
	f *Flags,
	ssclientset versioned.Interface,
	keyRegistry *KeyRegistry,
) (*Controller, error) {
	kinformer := initSecretInformerFactory(clientset, keyNamespace, func(options *metav1.ListOptions) {
		options.LabelSelector = keySelector.String()
	}, f.WatchForSecrets)
	sinformer := initSecretInformerFactory(clientset, namespace, tweakopts, !f.SkipRecreate)
	ssinformer := ssinformers.NewFilteredSharedInformerFactory(ssclientset, 0, namespace, tweakopts)
	controller, err := NewController(clientset, ssclientset, ssinformer, sinformer, kinformer, keyRegistry, f.MaxRetries, f.KeyOrderPriority)
	return controller, err
}

func initSecretInformerFactory(clientset kubernetes.Interface, ns string, tweakopts func(*metav1.ListOptions), enabled bool) informers.SharedInformerFactory {
	if !enabled {
		return nil
	}
	return informers.NewSharedInformerFactoryWithOptions(clientset, 0, informers.WithNamespace(ns), informers.WithTweakListOptions(tweakopts))
}

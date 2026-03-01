//go:build integration
// +build integration

package integration

import (
	"context"
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"

	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	ssclient "github.com/bitnami-labs/sealed-secrets/pkg/client/clientset/versioned"
	controller "github.com/bitnami-labs/sealed-secrets/pkg/controller"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("leader election", func() {
	var c corev1.CoreV1Interface
	var fullClient *kubernetes.Clientset
	var ssc ssclient.Interface
	var ctx context.Context
	var cancelLog context.CancelFunc

	BeforeEach(func() {
		ctx, cancelLog = context.WithCancel(context.Background())
		conf := clusterConfigOrDie()
		c = corev1.NewForConfigOrDie(conf)
		var err error
		fullClient, err = kubernetes.NewForConfig(conf)
		Expect(err).NotTo(HaveOccurred())
		ssc = ssclient.NewForConfigOrDie(conf)

		// Get deployment, skip if replicas <= 1
		deploy, err := fullClient.AppsV1().Deployments(*controllerNs).Get(ctx, "sealed-secrets-controller", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		if deploy.Spec.Replicas == nil || *deploy.Spec.Replicas <= 1 {
			Skip("leader election test requires >1 replica")
		}
	})

	AfterEach(func() {
		cancelLog()
	})

	It("should have exactly one leader", func() {
		leaderTimeout := 60 * time.Second

		// 1. Wait for all replicas to be ready.
		// All pods serve /healthz, so all should pass
		// readiness probes.
		desiredReplicas := int32(1)
		initDeploy, err := fullClient.AppsV1().Deployments(*controllerNs).Get(ctx, "sealed-secrets-controller", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		if initDeploy.Spec.Replicas != nil {
			desiredReplicas = *initDeploy.Spec.Replicas
		}
		Eventually(func() (int32, error) {
			d, err := fullClient.AppsV1().Deployments(*controllerNs).Get(ctx, "sealed-secrets-controller", metav1.GetOptions{})
			if err != nil {
				return 0, err
			}
			return d.Status.ReadyReplicas, nil
		}, leaderTimeout, PollingInterval).Should(Equal(desiredReplicas))

		// 2. Wait for lease to have a non-empty HolderIdentity
		var holderIdentity string
		Eventually(func() (string, error) {
			lease, err := fullClient.CoordinationV1().Leases(*controllerNs).Get(ctx, controller.LeaderElectionLeaseName, metav1.GetOptions{})
			if err != nil {
				return "", err
			}
			if lease.Spec.HolderIdentity == nil {
				return "", nil
			}
			return *lease.Spec.HolderIdentity, nil
		}, leaderTimeout, PollingInterval).ShouldNot(BeEmpty())

		// Get the actual holder identity
		lease, err := fullClient.CoordinationV1().Leases(*controllerNs).Get(ctx, controller.LeaderElectionLeaseName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		holderIdentity = *lease.Spec.HolderIdentity

		// 3. Verify holder is one of the running pod names
		deploy, err := fullClient.AppsV1().Deployments(*controllerNs).Get(ctx, "sealed-secrets-controller", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		var selectorParts []string
		for k, v := range deploy.Spec.Selector.MatchLabels {
			selectorParts = append(selectorParts, fmt.Sprintf("%s=%s", k, v))
		}
		labelSelector := strings.Join(selectorParts, ",")

		pods, err := c.Pods(*controllerNs).List(ctx, metav1.ListOptions{
			LabelSelector: labelSelector,
		})
		Expect(err).NotTo(HaveOccurred())

		podNames := make([]string, len(pods.Items))
		for i, p := range pods.Items {
			podNames[i] = p.Name
		}
		fmt.Fprintf(GinkgoWriter, "Pods: %v, Leader: %s\n", podNames, holderIdentity)
		Expect(podNames).To(ContainElement(holderIdentity))

		// 4. Create a SealedSecret to verify the leader is functional
		ns := createNsOrDie(ctx, c, "leader-election")
		defer deleteNsOrDie(ctx, c, ns)

		const secretName = "leader-test-secret"
		s := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      secretName,
			},
			Data: map[string][]byte{
				"key": []byte("value"),
			},
		}

		_, certs, err := fetchKeys(ctx, c)
		Expect(err).NotTo(HaveOccurred())
		pubKey := certs[0].PublicKey.(*rsa.PublicKey)

		ss, err := ssv1alpha1.NewSealedSecret(scheme.Codecs, pubKey, s)
		Expect(err).NotTo(HaveOccurred())

		ss, err = ssc.BitnamiV1alpha1().SealedSecrets(ns).Create(ctx, ss, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		expected := map[string][]byte{
			"key": []byte("value"),
		}
		Eventually(func() (*v1.Secret, error) {
			return c.Secrets(ns).Get(ctx, secretName, metav1.GetOptions{})
		}, Timeout, PollingInterval).Should(WithTransform(getData, Equal(expected)))
	})

	It("should elect new leader when current leader is removed", func() {
		failoverTimeout := 120 * time.Second

		// 1. Get deployment and record original replica count
		deploy, err := fullClient.AppsV1().Deployments(*controllerNs).Get(
			ctx, "sealed-secrets-controller", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		originalReplicas := int32(1)
		if deploy.Spec.Replicas != nil {
			originalReplicas = *deploy.Spec.Replicas
		}
		Expect(originalReplicas).To(
			BeNumerically(">=", int32(2)),
			"need at least 2 replicas for failover test",
		)

		// Build label selector from deployment
		var selectorParts []string
		for k, v := range deploy.Spec.Selector.MatchLabels {
			selectorParts = append(selectorParts,
				fmt.Sprintf("%s=%s", k, v))
		}
		labelSelector := strings.Join(selectorParts, ",")

		// Cleanup: restore original replica count
		defer func() {
			scale, sErr := fullClient.AppsV1().Deployments(*controllerNs).GetScale(
				ctx, "sealed-secrets-controller", metav1.GetOptions{})
			if sErr != nil {
				fmt.Fprintf(GinkgoWriter,
					"cleanup: failed to get scale: %v\n", sErr)
				return
			}
			scale.Spec.Replicas = originalReplicas
			if _, sErr = fullClient.AppsV1().Deployments(*controllerNs).UpdateScale(
				ctx, "sealed-secrets-controller", scale, metav1.UpdateOptions{}); sErr != nil {
				fmt.Fprintf(GinkgoWriter,
					"cleanup: failed to restore replicas: %v\n", sErr)
			}
			// Remove pod-deletion-cost annotation from remaining pods
			pods, pErr := c.Pods(*controllerNs).List(ctx,
				metav1.ListOptions{LabelSelector: labelSelector})
			if pErr != nil {
				fmt.Fprintf(GinkgoWriter,
					"cleanup: failed to list pods: %v\n", pErr)
				return
			}
			for i := range pods.Items {
				if _, ok := pods.Items[i].Annotations["controller.kubernetes.io/pod-deletion-cost"]; ok {
					removePatch := []byte(`{"metadata":{"annotations":{"controller.kubernetes.io/pod-deletion-cost":null}}}`)
					if _, pErr = c.Pods(*controllerNs).Patch(ctx,
						pods.Items[i].Name,
						k8stypes.MergePatchType,
						removePatch,
						metav1.PatchOptions{}); pErr != nil {
						fmt.Fprintf(GinkgoWriter,
							"cleanup: failed to remove annotation from %s: %v\n",
							pods.Items[i].Name, pErr)
					}
				}
			}
		}()

		// Wait for all replicas ready
		Eventually(func() (int32, error) {
			d, dErr := fullClient.AppsV1().Deployments(*controllerNs).Get(
				ctx, "sealed-secrets-controller", metav1.GetOptions{})
			if dErr != nil {
				return 0, dErr
			}
			return d.Status.ReadyReplicas, nil
		}, failoverTimeout, PollingInterval).Should(Equal(originalReplicas))

		// 2. Wait for lease HolderIdentity, record oldLeader
		var oldLeader string
		Eventually(func() (string, error) {
			lease, lErr := fullClient.CoordinationV1().Leases(*controllerNs).Get(
				ctx, controller.LeaderElectionLeaseName, metav1.GetOptions{})
			if lErr != nil {
				return "", lErr
			}
			if lease.Spec.HolderIdentity == nil {
				return "", nil
			}
			return *lease.Spec.HolderIdentity, nil
		}, failoverTimeout, PollingInterval).ShouldNot(BeEmpty())

		lease, err := fullClient.CoordinationV1().Leases(*controllerNs).Get(
			ctx, controller.LeaderElectionLeaseName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		oldLeader = *lease.Spec.HolderIdentity
		fmt.Fprintf(GinkgoWriter, "Old leader: %s\n", oldLeader)

		// 3. Annotate leader pod with low deletion cost
		annotationPatch := []byte(
			`{"metadata":{"annotations":{"controller.kubernetes.io/pod-deletion-cost":"-1000"}}}`)
		_, err = c.Pods(*controllerNs).Patch(ctx, oldLeader,
			k8stypes.MergePatchType, annotationPatch, metav1.PatchOptions{})
		Expect(err).NotTo(HaveOccurred())

		// 4. Scale deployment down by 1
		newReplicas := originalReplicas - 1
		scale, err := fullClient.AppsV1().Deployments(*controllerNs).GetScale(
			ctx, "sealed-secrets-controller", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		scale.Spec.Replicas = newReplicas
		_, err = fullClient.AppsV1().Deployments(*controllerNs).UpdateScale(
			ctx, "sealed-secrets-controller", scale, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// 5. Wait for lease to change to a different leader
		var newLeader string
		Eventually(func() (string, error) {
			lease, lErr := fullClient.CoordinationV1().Leases(*controllerNs).Get(
				ctx, controller.LeaderElectionLeaseName, metav1.GetOptions{})
			if lErr != nil {
				return "", lErr
			}
			if lease.Spec.HolderIdentity == nil {
				return "", nil
			}
			return *lease.Spec.HolderIdentity, nil
		}, failoverTimeout, PollingInterval).Should(
			SatisfyAll(Not(BeEmpty()), Not(Equal(oldLeader))))

		lease, err = fullClient.CoordinationV1().Leases(*controllerNs).Get(
			ctx, controller.LeaderElectionLeaseName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		newLeader = *lease.Spec.HolderIdentity
		fmt.Fprintf(GinkgoWriter, "New leader: %s\n", newLeader)

		// 6. Wait for new replica count to be ready
		Eventually(func() (int32, error) {
			d, dErr := fullClient.AppsV1().Deployments(*controllerNs).Get(
				ctx, "sealed-secrets-controller", metav1.GetOptions{})
			if dErr != nil {
				return 0, dErr
			}
			return d.Status.ReadyReplicas, nil
		}, failoverTimeout, PollingInterval).Should(Equal(newReplicas))

		// 7. Verify new leader is among running pod names
		pods, err := c.Pods(*controllerNs).List(ctx,
			metav1.ListOptions{LabelSelector: labelSelector})
		Expect(err).NotTo(HaveOccurred())
		podNames := make([]string, len(pods.Items))
		for i, p := range pods.Items {
			podNames[i] = p.Name
		}
		fmt.Fprintf(GinkgoWriter,
			"Pods: %v, New Leader: %s\n", podNames, newLeader)
		Expect(podNames).To(ContainElement(newLeader))

		// 8. Create SealedSecret to verify unsealing works
		ns := createNsOrDie(ctx, c, "leader-failover")
		defer deleteNsOrDie(ctx, c, ns)

		const failoverSecretName = "failover-test-secret"
		s := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      failoverSecretName,
			},
			Data: map[string][]byte{
				"key": []byte("failover-value"),
			},
		}

		_, certs, err := fetchKeys(ctx, c)
		Expect(err).NotTo(HaveOccurred())
		pubKey := certs[0].PublicKey.(*rsa.PublicKey)

		ss, err := ssv1alpha1.NewSealedSecret(
			scheme.Codecs, pubKey, s)
		Expect(err).NotTo(HaveOccurred())

		ss, err = ssc.BitnamiV1alpha1().SealedSecrets(ns).Create(
			ctx, ss, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		expected := map[string][]byte{
			"key": []byte("failover-value"),
		}
		Eventually(func() (*v1.Secret, error) {
			return c.Secrets(ns).Get(ctx,
				failoverSecretName, metav1.GetOptions{})
		}, Timeout, PollingInterval).Should(
			WithTransform(getData, Equal(expected)))
	})
})

/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package network

import (
	"encoding/json"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/kubernetes/test/e2e/framework"
	e2elog "k8s.io/kubernetes/test/e2e/framework/log"
	imageutils "k8s.io/kubernetes/test/utils/image"

	"fmt"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
)

/*
The following Network Policy tests verify that policy object definitions
are correctly enforced by a networking plugin. It accomplishes this by launching
a simple netcat server, and two clients with different
attributes. Each test case creates a network policy which should only allow
connections from one of the clients. The test then asserts that the clients
failed or successfully connected as expected.
*/

var _ = SIGDescribe("NetworkPolicy", func() {
	var service *v1.Service
	var podServer *v1.Pod
	f := framework.NewDefaultFramework("network-policy")

	ginkgo.Context("NetworkPolicy between server and client", func() {
		ginkgo.BeforeEach(func() {
			ginkgo.By("Creating a simple server that serves on port 80 and 81.")
			podServer, service = createServerPodAndService(f, f.Namespace, "server", []int{80, 81})

			ginkgo.By("Waiting for pod ready", func() {
				err := f.WaitForPodReady(podServer.Name)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			})

			// Create pods, which should be able to communicate with the server on port 80 and 81.
			ginkgo.By("Testing pods can connect to both ports when no policy is present.")
			testCanConnect(f, f.Namespace, "client-can-connect-80", service, 80)
			testCanConnect(f, f.Namespace, "client-can-connect-81", service, 81)
		})

		ginkgo.AfterEach(func() {
			cleanupServerPodAndService(f, podServer, service)
		})

		ginkgo.It("should support a 'default-deny' policy [Feature:NetworkPolicy]", func() {
			policy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "deny-all",
				},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					Ingress:     []networkingv1.NetworkPolicyIngressRule{},
				},
			}

			policy, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(policy)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			defer cleanupNetworkPolicy(f, policy)

			// Create a pod with name 'client-cannot-connect', which will attempt to communicate with the server,
			// but should not be able to now that isolation is on.
			testCannotConnect(f, f.Namespace, "client-cannot-connect", service, 80)
		})

		ginkgo.It("should enforce policy based on PodSelector [Feature:NetworkPolicy]", func() {
			ginkgo.By("Creating a network policy for the server which allows traffic from the pod 'client-a'.")
			policy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-client-a-via-pod-selector",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply this policy to the Server
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": podServer.Name,
						},
					},
					// Allow traffic only from client-a
					Ingress: []networkingv1.NetworkPolicyIngressRule{{
						From: []networkingv1.NetworkPolicyPeer{{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"pod-name": "client-a",
								},
							},
						}},
					}},
				},
			}

			policy, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(policy)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			defer cleanupNetworkPolicy(f, policy)

			ginkgo.By("Creating client-a which should be able to contact the server.", func() {
				testCanConnect(f, f.Namespace, "client-a", service, 80)
			})
			ginkgo.By("Creating client-b which should not be able to contact the server.", func() {
				testCannotConnect(f, f.Namespace, "client-b", service, 80)
			})
		})

		ginkgo.It("should enforce policy based on NamespaceSelector [Feature:NetworkPolicy]", func() {
			nsA := f.Namespace
			nsBName := f.BaseName + "-b"
			// The CreateNamespace helper uses the input name as a Name Generator, so the namespace itself
			// will have a different name than what we are setting as the value of ns-name.
			// This is fine as long as we don't try to match the label as nsB.Name in our policy.
			nsB, err := f.CreateNamespace(nsBName, map[string]string{
				"ns-name": nsBName,
			})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			// Create Server with Service in NS-B
			e2elog.Logf("Waiting for server to come up.")
			err = framework.WaitForPodRunningInNamespace(f.ClientSet, podServer)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			// Create Policy for that service that allows traffic only via namespace B
			ginkgo.By("Creating a network policy for the server which allows traffic from namespace-b.")
			policy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-ns-b-via-namespace-selector",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply to server
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": podServer.Name,
						},
					},
					// Allow traffic only from NS-B
					Ingress: []networkingv1.NetworkPolicyIngressRule{{
						From: []networkingv1.NetworkPolicyPeer{{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"ns-name": nsBName,
								},
							},
						}},
					}},
				},
			}
			policy, err = f.ClientSet.NetworkingV1().NetworkPolicies(nsA.Name).Create(policy)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			defer cleanupNetworkPolicy(f, policy)

			testCannotConnect(f, nsA, "client-a", service, 80)
			testCanConnect(f, nsB, "client-b", service, 80)
		})

		ginkgo.It("should enforce policy based on Ports [Feature:NetworkPolicy]", func() {
			ginkgo.By("Creating a network policy for the Service which allows traffic only to one port.")
			policy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-ingress-on-port-81",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply to server
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": podServer.Name,
						},
					},
					// Allow traffic only to one port.
					Ingress: []networkingv1.NetworkPolicyIngressRule{{
						Ports: []networkingv1.NetworkPolicyPort{{
							Port: &intstr.IntOrString{IntVal: 81},
						}},
					}},
				},
			}
			policy, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(policy)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			defer cleanupNetworkPolicy(f, policy)

			ginkgo.By("Testing pods can connect only to the port allowed by the policy.")
			testCannotConnect(f, f.Namespace, "client-a", service, 80)
			testCanConnect(f, f.Namespace, "client-b", service, 81)
		})

		ginkgo.It("should enforce multiple, stacked policies with overlapping podSelectors [Feature:NetworkPolicy]", func() {
			ginkgo.By("Creating a network policy for the Service which allows traffic only to one port.")
			policy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-ingress-on-port-80",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply to server
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": podServer.Name,
						},
					},
					// Allow traffic only to one port.
					Ingress: []networkingv1.NetworkPolicyIngressRule{{
						Ports: []networkingv1.NetworkPolicyPort{{
							Port: &intstr.IntOrString{IntVal: 80},
						}},
					}},
				},
			}
			policy, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(policy)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			defer cleanupNetworkPolicy(f, policy)

			ginkgo.By("Creating a network policy for the Service which allows traffic only to another port.")
			policy2 := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-ingress-on-port-81",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply to server
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": podServer.Name,
						},
					},
					// Allow traffic only to one port.
					Ingress: []networkingv1.NetworkPolicyIngressRule{{
						Ports: []networkingv1.NetworkPolicyPort{{
							Port: &intstr.IntOrString{IntVal: 81},
						}},
					}},
				},
			}
			policy2, err = f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(policy2)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			defer cleanupNetworkPolicy(f, policy2)

			ginkgo.By("Testing pods can connect to both ports when both policies are present.")
			testCanConnect(f, f.Namespace, "client-a", service, 80)
			testCanConnect(f, f.Namespace, "client-b", service, 81)
		})

		ginkgo.It("should support allow-all policy [Feature:NetworkPolicy]", func() {
			ginkgo.By("Creating a network policy which allows all traffic.")
			policy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-all",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Allow all traffic
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{},
					},
					Ingress: []networkingv1.NetworkPolicyIngressRule{{}},
				},
			}
			policy, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(policy)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			defer cleanupNetworkPolicy(f, policy)

			ginkgo.By("Testing pods can connect to both ports when an 'allow-all' policy is present.")
			testCanConnect(f, f.Namespace, "client-a", service, 80)
			testCanConnect(f, f.Namespace, "client-b", service, 81)
		})

		ginkgo.It("should allow ingress access on one named port [Feature:NetworkPolicy]", func() {
			policy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-client-a-via-named-port-ingress-rule",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply this policy to the Server
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": podServer.Name,
						},
					},
					// Allow traffic to only one named port: "serve-80".
					Ingress: []networkingv1.NetworkPolicyIngressRule{{
						Ports: []networkingv1.NetworkPolicyPort{{
							Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80"},
						}},
					}},
				},
			}

			policy, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(policy)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			defer cleanupNetworkPolicy(f, policy)

			ginkgo.By("Creating client-a which should be able to contact the server.", func() {
				testCanConnect(f, f.Namespace, "client-a", service, 80)
			})
			ginkgo.By("Creating client-b which should not be able to contact the server on port 81.", func() {
				testCannotConnect(f, f.Namespace, "client-b", service, 81)
			})
		})

		ginkgo.It("should allow egress access on one named port [Feature:NetworkPolicy]", func() {
			clientPodName := "client-a"
			protocolUDP := v1.ProtocolUDP
			policy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-client-a-via-named-port-egress-rule",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply this policy to client-a
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": clientPodName,
						},
					},
					// Allow traffic to only one named port: "serve-80".
					Egress: []networkingv1.NetworkPolicyEgressRule{{
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80"},
							},
							// Allow DNS look-ups
							{
								Protocol: &protocolUDP,
								Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
							},
						},
					}},
				},
			}

			policy, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(policy)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			defer cleanupNetworkPolicy(f, policy)

			ginkgo.By("Creating client-a which should be able to contact the server.", func() {
				testCanConnect(f, f.Namespace, clientPodName, service, 80)
			})
			ginkgo.By("Creating client-a which should not be able to contact the server on port 81.", func() {
				testCannotConnect(f, f.Namespace, clientPodName, service, 81)
			})
		})

		ginkgo.It("should enforce updated policy [Feature:NetworkPolicy]", func() {
			ginkgo.By("Creating a network policy for the Service which allows traffic only to one port.")
			policy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-ingress",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply to server
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": podServer.Name,
						},
					},
					// Allow traffic only to one port.
					Ingress: []networkingv1.NetworkPolicyIngressRule{{
						Ports: []networkingv1.NetworkPolicyPort{{
							Port: &intstr.IntOrString{IntVal: 80},
						}},
					}},
				},
			}
			policy, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(policy)
			framework.ExpectNoError(err, "Error creating Network Policy %v: %v", policy.ObjectMeta.Name, err)
			testCanConnect(f, f.Namespace, "client-a", service, 80)
			testCannotConnect(f, f.Namespace, "client-b", service, 81)

			ginkgo.By("Updating a network policy for the Service which allows traffic only to another port.")
			policy = &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-ingress",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply to server
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": podServer.Name,
						},
					},
					// Allow traffic only to one port.
					Ingress: []networkingv1.NetworkPolicyIngressRule{{
						Ports: []networkingv1.NetworkPolicyPort{{
							Port: &intstr.IntOrString{IntVal: 81},
						}},
					}},
				},
			}

			policy, err = f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Update(policy)
			framework.ExpectNoError(err, "Error updating Network Policy %v: %v", policy.ObjectMeta.Name, err)
			defer cleanupNetworkPolicy(f, policy)

			testCannotConnect(f, f.Namespace, "client-a", service, 80)
			testCanConnect(f, f.Namespace, "client-b", service, 81)
		})

		ginkgo.It("should enforce policy on updated Namespace [Feature:NetworkPolicy]", func() {
			nsA := f.Namespace
			nsBName := f.BaseName + "-b"
			newNsBName := nsBName + "-updated"
			nsB, err := f.CreateNamespace(nsBName, map[string]string{
				"ns-name": nsBName,
			})
			framework.ExpectNoError(err, "Error creating namespace %v: %v", nsBName, err)

			// Create Policy for that service that allows traffic only via namespace B
			ginkgo.By("Creating a network policy for the server which allows traffic from namespace-b.")
			policy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-ns-b-via-namespace-selector",
				},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": podServer.Name,
						},
					},
					Ingress: []networkingv1.NetworkPolicyIngressRule{{
						From: []networkingv1.NetworkPolicyPeer{{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"ns-name": newNsBName,
								},
							},
						}},
					}},
				},
			}

			policy, err = f.ClientSet.NetworkingV1().NetworkPolicies(nsA.Name).Create(policy)
			framework.ExpectNoError(err, "Error creating Network Policy %v: %v", policy.ObjectMeta.Name, err)
			defer cleanupNetworkPolicy(f, policy)

			testCannotConnect(f, nsB, "client-a", service, 80)

			nsB, err = f.ClientSet.CoreV1().Namespaces().Get(nsB.Name, metav1.GetOptions{})
			framework.ExpectNoError(err, "Error getting Namespace %v: %v", nsB.ObjectMeta.Name, err)

			nsB.ObjectMeta.Labels["ns-name"] = newNsBName
			nsB, err = f.ClientSet.CoreV1().Namespaces().Update(nsB)
			framework.ExpectNoError(err, "Error updating Namespace %v: %v", nsB.ObjectMeta.Name, err)

			testCanConnect(f, nsB, "client-b", service, 80)
		})

		ginkgo.It("should enforce policy when Pod is updated[Feature:NetworkPolicy]", func() {
			newPodName := "client-a-updated"

			ginkgo.By("Creating a network policy for the server which allows traffic from client-a-updated.")
			policy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-pod-b-via-pod-selector",
				},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": podServer.Name,
						},
					},
					Ingress: []networkingv1.NetworkPolicyIngressRule{{
						From: []networkingv1.NetworkPolicyPeer{{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"pod-name": newPodName,
								},
							},
						}},
					}},
				},
			}

			policy, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(policy)
			framework.ExpectNoError(err, "Error creating Network Policy %v: %v", policy.ObjectMeta.Name, err)
			defer cleanupNetworkPolicy(f, policy)

			podClient := createNetworkClientPod(f, f.Namespace, "client-a", service, 80)
			e2elog.Logf("Waiting for %s to be running.", podClient.Name)
			err = framework.WaitForPodRunningInNamespace(f.ClientSet, podClient)
			framework.ExpectNoError(err, "Error creating Pod %v: %v", podClient.Name, err)

			testCanConnectToUpdatedPod(f, f.Namespace, "client-a", service, "/metadata/labels/pod-name", newPodName)
		})
	})
})

func testCanConnect(f *framework.Framework, ns *v1.Namespace, podName string, service *v1.Service, targetPort int) {
	ginkgo.By(fmt.Sprintf("Creating client pod %s that should successfully connect to %s.", podName, service.Name))
	podClient := createNetworkClientPod(f, ns, podName, service, targetPort)
	defer func() {
		ginkgo.By(fmt.Sprintf("Cleaning up the pod %s", podName))
		if err := f.ClientSet.CoreV1().Pods(ns.Name).Delete(podClient.Name, nil); err != nil {
			framework.Failf("unable to cleanup pod %v: %v", podClient.Name, err)
		}
	}()

	e2elog.Logf("Waiting for %s to complete.", podClient.Name)
	err := framework.WaitForPodNoLongerRunningInNamespace(f.ClientSet, podClient.Name, ns.Name)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Pod did not finish as expected.")

	e2elog.Logf("Waiting for %s to complete.", podClient.Name)
	err = framework.WaitForPodSuccessInNamespace(f.ClientSet, podClient.Name, ns.Name)
	if err != nil {
		// Collect pod logs when we see a failure.
		logs, logErr := framework.GetPodLogs(f.ClientSet, f.Namespace.Name, podName, fmt.Sprintf("%s-container", podName))
		if logErr != nil {
			framework.Failf("Error getting container logs: %s", logErr)
		}

		// Collect current NetworkPolicies applied in the test namespace.
		policies, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).List(metav1.ListOptions{})
		if err != nil {
			e2elog.Logf("error getting current NetworkPolicies for %s namespace: %s", f.Namespace.Name, err)
		}

		// Collect the list of pods running in the test namespace.
		podsInNS, err := framework.GetPodsInNamespace(f.ClientSet, f.Namespace.Name, map[string]string{})
		if err != nil {
			e2elog.Logf("error getting pods for %s namespace: %s", f.Namespace.Name, err)
		}

		pods := []string{}
		for _, p := range podsInNS {
			pods = append(pods, fmt.Sprintf("Pod: %s, Status: %s\n", p.Name, p.Status.String()))
		}

		framework.Failf("Pod %s should be able to connect to service %s, but was not able to connect.\nPod logs:\n%s\n\n Current NetworkPolicies:\n\t%v\n\n Pods:\n\t%v\n\n", podName, service.Name, logs, policies.Items, pods)

		// Dump debug information for the test namespace.
		framework.DumpDebugInfo(f.ClientSet, f.Namespace.Name)
	}
}

func testCannotConnect(f *framework.Framework, ns *v1.Namespace, podName string, service *v1.Service, targetPort int) {
	ginkgo.By(fmt.Sprintf("Creating client pod %s that should not be able to connect to %s.", podName, service.Name))
	podClient := createNetworkClientPod(f, ns, podName, service, targetPort)
	defer func() {
		ginkgo.By(fmt.Sprintf("Cleaning up the pod %s", podName))
		if err := f.ClientSet.CoreV1().Pods(ns.Name).Delete(podClient.Name, nil); err != nil {
			framework.Failf("unable to cleanup pod %v: %v", podClient.Name, err)
		}
	}()

	e2elog.Logf("Waiting for %s to complete.", podClient.Name)
	err := framework.WaitForPodSuccessInNamespace(f.ClientSet, podClient.Name, ns.Name)

	// We expect an error here since it's a cannot connect test.
	// Dump debug information if the error was nil.
	if err == nil {
		// Collect pod logs when we see a failure.
		logs, logErr := framework.GetPodLogs(f.ClientSet, f.Namespace.Name, podName, fmt.Sprintf("%s-container", podName))
		if logErr != nil {
			framework.Failf("Error getting container logs: %s", logErr)
		}

		// Collect current NetworkPolicies applied in the test namespace.
		policies, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).List(metav1.ListOptions{})
		if err != nil {
			e2elog.Logf("error getting current NetworkPolicies for %s namespace: %s", f.Namespace.Name, err)
		}

		// Collect the list of pods running in the test namespace.
		podsInNS, err := framework.GetPodsInNamespace(f.ClientSet, f.Namespace.Name, map[string]string{})
		if err != nil {
			e2elog.Logf("error getting pods for %s namespace: %s", f.Namespace.Name, err)
		}

		pods := []string{}
		for _, p := range podsInNS {
			pods = append(pods, fmt.Sprintf("Pod: %s, Status: %s\n", p.Name, p.Status.String()))
		}

		framework.Failf("Pod %s should not be able to connect to service %s, but was able to connect.\nPod logs:\n%s\n\n Current NetworkPolicies:\n\t%v\n\n Pods:\n\t %v\n\n", podName, service.Name, logs, policies.Items, pods)

		// Dump debug information for the test namespace.
		framework.DumpDebugInfo(f.ClientSet, f.Namespace.Name)
	}
}

func testCanConnectToUpdatedPod(f *framework.Framework, ns *v1.Namespace, podName string, service *v1.Service, patchPath string, patchValue string) {
	ginkgo.By(fmt.Sprintf("Updating client pod %s that should successfully connect to %s.", podName, service.Name))
	podClient := updateNetworkClientPodLabel(f, ns, podName, patchPath, patchValue)
	defer func() {
		ginkgo.By(fmt.Sprintf("Cleaning up the pod %s", podName))
		if err := f.ClientSet.CoreV1().Pods(ns.Name).Delete(podClient.Name, nil); err != nil {
			framework.Failf("unable to cleanup pod %v: %v", podClient.Name, err)
		}
	}()

	e2elog.Logf("Waiting for %s to complete.", podClient.Name)
	err := framework.WaitForPodNoLongerRunningInNamespace(f.ClientSet, podClient.Name, ns.Name)
	framework.ExpectNoError(err, "Pod did not finish as expected.")

	e2elog.Logf("Waiting for %s to complete.", podClient.Name)
	err = framework.WaitForPodSuccessInNamespace(f.ClientSet, podClient.Name, ns.Name)
	if err != nil {
		// Collect pod logs when we see a failure.
		logs, logErr := framework.GetPodLogs(f.ClientSet, f.Namespace.Name, podName, fmt.Sprintf("%s-container", podName))
		if logErr != nil {
			framework.Failf("Error getting container logs: %s", logErr)
		}

		// Collect current NetworkPolicies applied in the test namespace.
		policies, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).List(metav1.ListOptions{})
		if err != nil {
			e2elog.Logf("error getting current NetworkPolicies for %s namespace: %s", f.Namespace.Name, err)
		}

		// Collect the list of pods running in the test namespace.
		podsInNS, err := framework.GetPodsInNamespace(f.ClientSet, f.Namespace.Name, map[string]string{})
		if err != nil {
			e2elog.Logf("error getting pods for %s namespace: %s", f.Namespace.Name, err)
		}

		pods := []string{}
		for _, p := range podsInNS {
			pods = append(pods, fmt.Sprintf("Pod: %s, Status: %s\n", p.Name, p.Status.String()))
		}

		framework.Failf("Pod %s should be able to connect to service %s, but was not able to connect.\nPod logs:\n%s\n\n Current NetworkPolicies:\n\t%v\n\n Pods:\n\t%v\n\n", podName, service.Name, logs, policies.Items, pods)

		// Dump debug information for the test namespace.
		framework.DumpDebugInfo(f.ClientSet, f.Namespace.Name)
	}
}

// Create a server pod with a listening container for each port in ports[].
// Will also assign a pod label with key: "pod-name" and label set to the given podname for later use by the network
// policy.
func createServerPodAndService(f *framework.Framework, namespace *v1.Namespace, podName string, ports []int) (*v1.Pod, *v1.Service) {
	// Because we have a variable amount of ports, we'll first loop through and generate our Containers for our pod,
	// and ServicePorts.for our Service.
	containers := []v1.Container{}
	servicePorts := []v1.ServicePort{}
	for _, port := range ports {
		// Build the containers for the server pod.
		containers = append(containers, v1.Container{
			Name:  fmt.Sprintf("%s-container-%d", podName, port),
			Image: imageutils.GetE2EImage(imageutils.Porter),
			Env: []v1.EnvVar{
				{
					Name:  fmt.Sprintf("SERVE_PORT_%d", port),
					Value: "foo",
				},
			},
			Ports: []v1.ContainerPort{
				{
					ContainerPort: int32(port),
					Name:          fmt.Sprintf("serve-%d", port),
				},
			},
			ReadinessProbe: &v1.Probe{
				Handler: v1.Handler{
					HTTPGet: &v1.HTTPGetAction{
						Path: "/",
						Port: intstr.IntOrString{
							IntVal: int32(port),
						},
						Scheme: v1.URISchemeHTTP,
					},
				},
			},
		})

		// Build the Service Ports for the service.
		servicePorts = append(servicePorts, v1.ServicePort{
			Name:       fmt.Sprintf("%s-%d", podName, port),
			Port:       int32(port),
			TargetPort: intstr.FromInt(port),
		})
	}

	ginkgo.By(fmt.Sprintf("Creating a server pod %s in namespace %s", podName, namespace.Name))
	pod, err := f.ClientSet.CoreV1().Pods(namespace.Name).Create(&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: podName,
			Labels: map[string]string{
				"pod-name": podName,
			},
		},
		Spec: v1.PodSpec{
			Containers:    containers,
			RestartPolicy: v1.RestartPolicyNever,
		},
	})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	e2elog.Logf("Created pod %v", pod.ObjectMeta.Name)

	svcName := fmt.Sprintf("svc-%s", podName)
	ginkgo.By(fmt.Sprintf("Creating a service %s for pod %s in namespace %s", svcName, podName, namespace.Name))
	svc, err := f.ClientSet.CoreV1().Services(namespace.Name).Create(&v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: svcName,
		},
		Spec: v1.ServiceSpec{
			Ports: servicePorts,
			Selector: map[string]string{
				"pod-name": podName,
			},
		},
	})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	e2elog.Logf("Created service %s", svc.Name)

	return pod, svc
}

func cleanupServerPodAndService(f *framework.Framework, pod *v1.Pod, service *v1.Service) {
	ginkgo.By("Cleaning up the server.")
	if err := f.ClientSet.CoreV1().Pods(pod.Namespace).Delete(pod.Name, nil); err != nil {
		framework.Failf("unable to cleanup pod %v: %v", pod.Name, err)
	}
	ginkgo.By("Cleaning up the server's service.")
	if err := f.ClientSet.CoreV1().Services(service.Namespace).Delete(service.Name, nil); err != nil {
		framework.Failf("unable to cleanup svc %v: %v", service.Name, err)
	}
}

// Create a client pod which will attempt a netcat to the provided service, on the specified port.
// This client will attempt a one-shot connection, then die, without restarting the pod.
// Test can then be asserted based on whether the pod quit with an error or not.
func createNetworkClientPod(f *framework.Framework, namespace *v1.Namespace, podName string, targetService *v1.Service, targetPort int) *v1.Pod {
	pod, err := f.ClientSet.CoreV1().Pods(namespace.Name).Create(&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: podName,
			Labels: map[string]string{
				"pod-name": podName,
			},
		},
		Spec: v1.PodSpec{
			RestartPolicy: v1.RestartPolicyNever,
			Containers: []v1.Container{
				{
					Name:  fmt.Sprintf("%s-container", podName),
					Image: imageutils.GetE2EImage(imageutils.BusyBox),
					Args: []string{
						"/bin/sh",
						"-c",
						fmt.Sprintf("for i in $(seq 1 5); do nc -vz -w 8 %s.%s %d && exit 0 || sleep 1; done; exit 1",
							targetService.Name, targetService.Namespace, targetPort),
					},
				},
			},
		},
	})

	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return pod
}

// Update client pod label. This pod will attempt a netcat to the provided service,
// on the specified port. This client will attempt a one-shot connection, then die, without restarting the pod.
// Test can then be asserted based on whether the pod quit with an error or not.
func updateNetworkClientPodLabel(f *framework.Framework, namespace *v1.Namespace, podName string, patchPath string, patchValue string) *v1.Pod {
	type patchStringValue struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value string `json:"value"`
	}
	payload := []patchStringValue{{
		Op:    "replace",
		Path:  "/metadata/labels/pod-name",
		Value: podName + "-updated",
	}}
	payloadBytes, _ := json.Marshal(payload)
	pod, err := f.ClientSet.
		CoreV1().
		Pods(namespace.Name).
		Patch(podName, types.JSONPatchType, payloadBytes)
	framework.ExpectNoError(err)

	return pod
}

func cleanupNetworkPolicy(f *framework.Framework, policy *networkingv1.NetworkPolicy) {
	ginkgo.By("Cleaning up the policy.")
	if err := f.ClientSet.NetworkingV1().NetworkPolicies(policy.Namespace).Delete(policy.Name, nil); err != nil {
		framework.Failf("unable to cleanup policy %v: %v", policy.Name, err)
	}
}

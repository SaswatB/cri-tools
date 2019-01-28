/*
Copyright 2017 The Kubernetes Authors.

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

package validate

import (
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/kubernetes-sigs/cri-tools/pkg/framework"
	internalapi "k8s.io/kubernetes/pkg/kubelet/apis/cri"
	runtimeapi "k8s.io/kubernetes/pkg/kubelet/apis/cri/runtime/v1alpha2"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	resolvConfigPath              = "/etc/resolv.conf"
	defaultDNSServer       string = "10.10.10.10"
	defaultDNSSearch       string = "google.com"
	defaultDNSOption       string = "ndots:8"
	webServerContainerPort int32  = 80
	// The following host ports must not be in-use when running the test.
	webServerHostPortForPortMapping        int32 = 12000
	webServerHostPortForPortForward        int32 = 12001
	webServerHostPortForHostNetPortFroward int32 = 12002
	// The port used in hostNetNginxImage (See images/hostnet-nginx/)
	webServerHostNetContainerPort int32 = 12003

	// Linux defaults
	webServerLinuxImage        = "nginx"
	hostNetWebServerLinuxImage = "gcr.io/cri-tools/hostnet-nginx"

	// Windows defaults
	webServerWindowsImage        = "mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2019"
	hostNetWebServerWindowsImage = "mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2019"
)

var (
	webServerImage        string
	hostNetWebServerImage string
	getDNSConfigCmd       []string

	// Linux defaults
	getDNSConfigLinuxCmd = []string{"cat", resolvConfigPath}

	// Windows defaults
	getDNSConfigWindowsCmd = []string{"cmd", "/c", "\"powershell /c sleep 5; iex '(Get-NetIPConfiguration).DNSServer.ServerAddresses'\""}
)

var _ = framework.KubeDescribe("Networking", func() {
	f := framework.NewDefaultCRIFramework()

	framework.AddBeforeSuiteCallback(func() {
		if runtime.GOOS != "windows" || framework.TestContext.IsLcow {
			webServerImage = webServerLinuxImage
			hostNetWebServerImage = hostNetWebServerLinuxImage
			getDNSConfigCmd = getDNSConfigLinuxCmd
		} else {
			webServerImage = webServerWindowsImage
			hostNetWebServerImage = hostNetWebServerWindowsImage
			getDNSConfigCmd = getDNSConfigWindowsCmd
		}
	})

	var rc internalapi.RuntimeService
	var ic internalapi.ImageManagerService

	BeforeEach(func() {
		rc = f.CRIClient.CRIRuntimeClient
		ic = f.CRIClient.CRIImageClient
	})

	Context("runtime should support networking", func() {
		var podID string

		AfterEach(func() {
			By("stop PodSandbox")
			rc.StopPodSandbox(podID)
			By("delete PodSandbox")
			rc.RemovePodSandbox(podID)
		})

		It("runtime should support DNS config [Conformance]", func() {
			By("create a PodSandbox with DNS config")
			var podConfig *runtimeapi.PodSandboxConfig
			podID, podConfig = createPodSandWithDNSConfig(rc)

			By("create container")
			containerID := framework.CreateDefaultContainer(rc, ic, podID, podConfig, "container-for-DNS-config-test-")

			By("start container")
			startContainer(rc, containerID)

			By("check DNS config")
			expectedContent := []string{
				"nameserver " + defaultDNSServer,
				"search " + defaultDNSSearch,
				"options " + defaultDNSOption,
			}
			checkDNSConfig(rc, containerID, expectedContent)
		})

		It("runtime should support port mapping with only container port [Conformance]", func() {
			By("create a PodSandbox with container port port mapping")
			var podConfig *runtimeapi.PodSandboxConfig
			portMappings := []*runtimeapi.PortMapping{
				{
					ContainerPort: webServerContainerPort,
				},
			}
			podID, podConfig = createPodSandboxWithPortMapping(rc, portMappings, false)

			By("create a web server container")
			containerID := createWebServerContainer(rc, ic, podID, podConfig, "container-for-container-port")

			By("start the web server container")
			startContainer(rc, containerID)

			By("check the port mapping with only container port")
			checkMainPage(rc, podID, 0)
		})

		It("runtime should support port mapping with host port and container port [Conformance]", func() {
			By("create a PodSandbox with host port and container port port mapping")
			var podConfig *runtimeapi.PodSandboxConfig
			portMappings := []*runtimeapi.PortMapping{
				{
					ContainerPort: webServerContainerPort,
					HostPort:      webServerHostPortForPortMapping,
				},
			}
			podID, podConfig = createPodSandboxWithPortMapping(rc, portMappings, false)

			By("create a web server container")
			containerID := createWebServerContainer(rc, ic, podID, podConfig, "container-for-host-port")

			By("start the web server container")
			startContainer(rc, containerID)

			By("check the port mapping with host port and container port")
			checkMainPage(rc, "", webServerHostPortForPortMapping)
		})
	})
})

// createPodSandWithDNSConfig create a PodSandbox with DNS config.
func createPodSandWithDNSConfig(c internalapi.RuntimeService) (string, *runtimeapi.PodSandboxConfig) {
	podSandboxName := "create-PodSandbox-with-DNS-config" + framework.NewUUID()
	uid := framework.DefaultUIDPrefix + framework.NewUUID()
	namespace := framework.DefaultNamespacePrefix + framework.NewUUID()
	config := &runtimeapi.PodSandboxConfig{
		Metadata: framework.BuildPodSandboxMetadata(podSandboxName, uid, namespace, framework.DefaultAttempt),
		DnsConfig: &runtimeapi.DNSConfig{
			Servers:  []string{defaultDNSServer},
			Searches: []string{defaultDNSSearch},
			Options:  []string{defaultDNSOption},
		},
		Linux:  &runtimeapi.LinuxPodSandboxConfig{},
		Labels: framework.DefaultPodLabels,
	}

	podID := framework.RunPodSandbox(c, config)
	return podID, config
}

// createPodSandboxWithPortMapping create a PodSandbox with port mapping.
func createPodSandboxWithPortMapping(c internalapi.RuntimeService, portMappings []*runtimeapi.PortMapping, hostNet bool) (string, *runtimeapi.PodSandboxConfig) {
	podSandboxName := "create-PodSandbox-with-port-mapping" + framework.NewUUID()
	uid := framework.DefaultUIDPrefix + framework.NewUUID()
	namespace := framework.DefaultNamespacePrefix + framework.NewUUID()
	config := &runtimeapi.PodSandboxConfig{
		Metadata:     framework.BuildPodSandboxMetadata(podSandboxName, uid, namespace, framework.DefaultAttempt),
		PortMappings: portMappings,
		Linux:        &runtimeapi.LinuxPodSandboxConfig{},
		Labels:       framework.DefaultPodLabels,
	}
	if hostNet {
		config.Linux.SecurityContext = &runtimeapi.LinuxSandboxSecurityContext{
			NamespaceOptions: &runtimeapi.NamespaceOption{
				Network: runtimeapi.NamespaceMode_NODE,
			},
		}
	}

	podID := framework.RunPodSandbox(c, config)
	return podID, config
}

// checkDNSConfig checks the content of /etc/resolv.conf.
func checkDNSConfig(c internalapi.RuntimeService, containerID string, expectedContent []string) {
	By("get the current dns config via execSync")
	stdout, stderr, err := c.ExecSync(containerID, getDNSConfigCmd, time.Duration(defaultExecSyncTimeout)*time.Second)
	framework.ExpectNoError(err, "failed to execSync in container %q", containerID)
	for _, content := range expectedContent {
		Expect(string(stdout)).To(ContainSubstring(content), "The stdout output of execSync should contain %q", content)
	}
	Expect(stderr).To(BeNil(), "The stderr should be nil.")
	framework.Logf("check DNS config succeed")
}

// createWebServerContainer creates a container running a web server
func createWebServerContainer(rc internalapi.RuntimeService, ic internalapi.ImageManagerService, podID string, podConfig *runtimeapi.PodSandboxConfig, prefix string) string {
	containerName := prefix + framework.NewUUID()
	containerConfig := &runtimeapi.ContainerConfig{
		Metadata: framework.BuildContainerMetadata(containerName, framework.DefaultAttempt),
		Image:    &runtimeapi.ImageSpec{Image: webServerImage},
		Linux:    &runtimeapi.LinuxContainerConfig{},
	}
	return framework.CreateContainer(rc, ic, containerConfig, podID, podConfig)
}

// createHostNetWebServerContainer creates a web server container using webServerHostNetContainerPort.
func createHostNetWebServerContainer(rc internalapi.RuntimeService, ic internalapi.ImageManagerService, podID string, podConfig *runtimeapi.PodSandboxConfig, prefix string) string {
	containerName := prefix + framework.NewUUID()
	containerConfig := &runtimeapi.ContainerConfig{
		Metadata: framework.BuildContainerMetadata(containerName, framework.DefaultAttempt),
		Image:    &runtimeapi.ImageSpec{Image: hostNetWebServerImage},
		Linux:    &runtimeapi.LinuxContainerConfig{},
	}
	return framework.CreateContainer(rc, ic, containerConfig, podID, podConfig)
}

// checkMainPage check if the we can get the main page of the pod via given IP:port.
func checkMainPage(c internalapi.RuntimeService, podID string, hostPort int32) {
	By("get the IP:port needed to be checked")
	var err error
	var resp *http.Response

	url := "http://"
	if hostPort != 0 {
		url += "127.0.0.1:" + strconv.Itoa(int(hostPort))
	} else {
		status := getPodSandboxStatus(c, podID)
		Expect(status.GetNetwork()).NotTo(BeNil(), "The network in status should not be nil.")
		Expect(status.GetNetwork().Ip).NotTo(BeNil(), "The IP should not be nil.")
		url += status.GetNetwork().Ip + ":" + strconv.Itoa(int(webServerContainerPort))
	}
	framework.Logf("the IP:port is " + url)

	By("check the content of " + url)

	Eventually(func() error {
		resp, err = http.Get(url)
		return err
	}, time.Minute, time.Second).Should(BeNil())

	Expect(resp.StatusCode).To(Equal(200), "The status code of response should be 200.")
	framework.Logf("check port mapping succeed")
}

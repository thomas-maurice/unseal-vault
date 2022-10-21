package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	_ "k8s.io/client-go/plugin/pkg/client/auth"
	_ "k8s.io/client-go/plugin/pkg/client/auth/azure"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	_ "k8s.io/client-go/plugin/pkg/client/auth/openstack"
)

var (
	secretShares       int
	secretThreshold    int
	k8sSecret          bool
	k8sSecretNamespace string
	k8sSecretName      string
	k8sInCluster       bool
	outputFile         string
	inputFile          string
)

func init() {
	flag.IntVar(&secretShares, "secret-shares", 5, "Number of master keys")
	flag.IntVar(&secretThreshold, "secret-threshold", 3, "Number of master keys you need to unseal the Vault")
	flag.StringVar(&outputFile, "output", "/tmp/vault-init.json", "Output file in which store the master keys and root token")
	flag.StringVar(&inputFile, "input", "/tmp/vault-init.json", "Input file used to load unseal data")
	flag.BoolVar(&k8sSecret, "k8s-secret", false, "Is the thing stored in a k8s secret ?")
	flag.BoolVar(&k8sInCluster, "k8s-in-cluster", false, "are we running in cluster ?")
	flag.StringVar(&k8sSecretNamespace, "k8s-ns", "default", "Name of the k8s ns the secret is stored in")
	flag.StringVar(&k8sSecretName, "k8s-secret-name", "vault-unseal", "Name of the vault secret unseal")
}

type VaultStatus struct {
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	T           int    `json:"t"`
	N           int    `json:"n"`
	Progress    int    `json:"progress"`
	ClusterName string `json:"cluster_name"`
	Version     string `json:"version"`
	ClusterID   string `json:"cluster_id"`
}

type VaultInitRequest struct {
	SecretShares    int `json:"secret_shares"`
	SecretThreshold int `json:"secret_threshold"`
}

type VaultInitResponse struct {
	Keys      []string `json:"keys"`
	RootToken string   `json:"root_token"`
}

type VaultUnsealRequest struct {
	Key string `json:"key"`
}

type VaultUnsealResponse struct {
	Sealed bool `json:"sealed"`
}

func initializeVault(vaultAddr string, shares int, threshold int) (*VaultInitResponse, error) {
	var vaultResponse VaultInitResponse

	initRequest := VaultInitRequest{
		SecretShares:    shares,
		SecretThreshold: threshold,
	}

	b, err := json.Marshal(&initRequest)
	if err != nil {
		return nil, err
	}

	c := http.Client{}

	req, err := http.NewRequest("PUT", strings.TrimRight(vaultAddr, "/")+"/v1/sys/init", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	b, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(b, &vaultResponse)
	if err != nil {
		return nil, err
	}

	return &vaultResponse, nil
}

func vaultStatus(vaultAddr string) (*VaultStatus, error) {
	c := http.Client{}

	req, err := http.NewRequest("GET", strings.TrimRight(vaultAddr, "/")+"/v1/sys/seal-status", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var status VaultStatus
	err = json.Unmarshal(b, &status)
	if err != nil {
		return nil, err
	}

	return &status, nil
}

func unsealVault(vaultAddr string, keys []string) (bool, error) {
	c := http.Client{}

	for i := 0; i < len(keys); i++ {
		var vaultResponse VaultUnsealResponse

		unsealRequest := VaultUnsealRequest{
			Key: keys[i],
		}

		b, err := json.Marshal(&unsealRequest)
		if err != nil {
			return false, err
		}

		req, err := http.NewRequest("PUT", strings.TrimRight(vaultAddr, "/")+"/v1/sys/unseal", bytes.NewBuffer(b))
		if err != nil {
			return false, err
		}

		resp, err := c.Do(req)
		if err != nil {
			return false, err
		}

		defer resp.Body.Close()

		b, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return false, err
		}

		err = json.Unmarshal(b, &vaultResponse)
		if err != nil {
			return false, err
		}

		if !vaultResponse.Sealed {
			return true, nil
		}
	}

	return false, errors.New("could not unseal vault")
}

func readConf(ctx context.Context, client *kubernetes.Clientset, filePath string, k8sNs string, k8sName string) (*VaultInitResponse, error) {
	if client == nil {
		var initResult VaultInitResponse
		b, err := ioutil.ReadFile(inputFile)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(b, &initResult)
		if err != nil {
			return nil, err
		}

		return &initResult, nil
	}

	secret, err := client.CoreV1().Secrets(k8sNs).Get(ctx, k8sName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	var initResult VaultInitResponse
	err = json.Unmarshal(secret.Data["value"], &initResult)
	if err != nil {
		return nil, err
	}

	return &initResult, nil
}

func writeConf(ctx context.Context, client *kubernetes.Clientset, filePath string, k8sNs string, k8sName string, initResult VaultInitResponse) error {
	b, err := json.Marshal(&initResult)
	if err != nil {
		return fmt.Errorf("could not marshal the result: %w", err)
	}

	if client == nil {
		err = ioutil.WriteFile(outputFile, b, 0640)
		if err != nil {
			return fmt.Errorf("could not save the vault initialization data: %w", err)
		}
		return nil
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: k8sName,
		},
		Data: map[string][]byte{
			"value": b,
		},
	}

	_, err = client.CoreV1().Secrets(k8sNs).Create(ctx, secret, metav1.CreateOptions{})

	return err
}

func main() {
	flag.Parse()

	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://localhost:8200"
	}

	var clientset *kubernetes.Clientset

	if k8sSecret {
		if k8sInCluster {
			config, err := rest.InClusterConfig()
			if err != nil {
				panic(err.Error())
			}
			clientset, err = kubernetes.NewForConfig(config)
			if err != nil {
				panic(err.Error())
			}
		} else {
			var kubeconfig *string
			if home := homedir.HomeDir(); home != "" {
				kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
			} else {
				kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
			}
			flag.Parse()

			// use the current context in kubeconfig
			config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
			if err != nil {
				panic(err.Error())
			}

			clientset, err = kubernetes.NewForConfig(config)
			if err != nil {
				panic(err.Error())
			}
		}
	}

	log.Printf("waiting for vault to be ready at %s\n", vaultAddr)

	var status *VaultStatus
	var err error

	// wait for vault to be ready (up and such)
	for {
		status, err = vaultStatus(vaultAddr)
		if err != nil {
			log.Printf("vault is not ready yet: %s\n", err)
			time.Sleep(time.Second * 1)
		} else {
			break
		}
	}

	log.Printf("vault is sealed: %v, vault is initialized: %v", status.Sealed, status.Initialized)

	// initialize vault if it is not initialized yet
	if !status.Initialized {
		log.Printf("initializing vault with %d shares and a threshold of %d\n", secretShares, secretThreshold)
		initResult, err := initializeVault(vaultAddr, secretShares, secretThreshold)
		if err != nil {
			log.Fatalf("could not initialize vault: %s\n", err)
		}

		err = writeConf(context.Background(), clientset, outputFile, k8sSecretNamespace, k8sSecretName, *initResult)
		if err != nil {
			log.Fatalf("could not save init result: %s\n", err)
		}
	}

	// unseal vault if it is not unsealed yet
	if status.Sealed {
		log.Println("unsealing vault")
		initResult, err := readConf(context.Background(), clientset, inputFile, k8sSecretNamespace, k8sSecretName)
		if err != nil {
			panic(err)
		}

		unsealed, err := unsealVault(vaultAddr, initResult.Keys)
		if err != nil {
			log.Fatalf("could not unseal vault: %s\n", err)
		}
		if unsealed {
			log.Println("vault successfully unsealed")
		} else {
			log.Println("failed to unseal vault")
			os.Exit(1)
		}
	}
}

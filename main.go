package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	secretShares    int
	secretThreshold int
	outputFile      string
	inputFile       string
)

func init() {
	flag.IntVar(&secretShares, "secret-shares", 5, "Number of master keys")
	flag.IntVar(&secretThreshold, "secret-threshold", 3, "Number of master keys you need to unseal the Vault")
	flag.StringVar(&outputFile, "output", "/tmp/vault-init.json", "Output file in which store the master keys and root token")
	flag.StringVar(&inputFile, "input", "/tmp/vault-init.json", "Input file used to load unseal data")
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

func main() {
	flag.Parse()

	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://localhost:8200"
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

		b, err := json.Marshal(&initResult)
		if err != nil {
			log.Fatalf("could not marshal the result: %s\n", err)
		}

		err = ioutil.WriteFile(outputFile, b, 0640)
		if err != nil {
			log.Fatalf("could not save the vault initialization data: %s\n", err)
		}
	}

	// unseal vault if it is not unsealed yet
	if status.Sealed {
		log.Println("unsealing vault")
		var initResult VaultInitResponse
		b, err := ioutil.ReadFile(inputFile)
		if err != nil {
			log.Fatalf("could not open vault init data: %s\n", err)
		}
		err = json.Unmarshal(b, &initResult)
		if err != nil {
			log.Fatalf("could not unmarshal vault init data: %s\n", err)
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

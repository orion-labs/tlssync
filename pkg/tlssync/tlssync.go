package tlssync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"time"
)

// MONITOR_SECRETS_INTERVAL Interval in seconds after which we check to see if our secrets have changed
const MONITOR_SECRETS_INTERVAL = "MONITOR_SECRETS_INTERVAL"

// DEFAULT_MONITOR_INTERVAL Number of seconds to wait between config or secret checks by default
const DEFAULT_MONITOR_INTERVAL = 300

// IN_POD_NAMESPACE_FILE Default location in a pod where k8s stores the name of the pod's namespace.  If this file is present, odds are we're running in a k8s pod
const IN_POD_NAMESPACE_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

const COMBINED_FILE_EXTENSION = "pem"

const KEY_FILE_EXTENSION = "key"

const CRT_FILE_EXTENSION = "crt"

type TlsFile struct {
	SecretName    string `json:"secret_name"`
	SeparateFiles bool   `json:"separate_files"`
	FileBase      string `json:"file_base""`
	FilePath      string `json:"file_path"`
	Checksum      string
	Data          map[string][]byte
}

type TlsFiles []*TlsFile

type TlsSync struct {
	K8sNamespace           string
	K8sConfig              *rest.Config
	K8sClientset           *kubernetes.Clientset
	K8sDynamicClient       dynamic.Interface
	SecretChecksums        map[string]string
	MonitorSecretsInterval int
	TlsFiles               []*TlsFile
}

func NewTlsSync(tlsFiles []*TlsFile) (ts *TlsSync, err error) {
	ts = &TlsSync{
		TlsFiles: tlsFiles,
	}

	// Initialize k8s clients
	err = ts.InitK8sClients()
	if err != nil {
		err = errors.Wrapf(err, "failed to init k8s connection")
		return ts, err
	}

	// Set interval at which to check secrets
	if os.Getenv(MONITOR_SECRETS_INTERVAL) != "" {
		i, err := strconv.Atoi(os.Getenv(MONITOR_SECRETS_INTERVAL))
		if err != nil {
			err = errors.Wrapf(err, "secrets check interval cant be parsed into an integer")
			return ts, err
		}

		ts.MonitorSecretsInterval = i
	} else {
		ts.MonitorSecretsInterval = DEFAULT_MONITOR_INTERVAL
	}

	err = ts.LoadSecrets()
	if err != nil {
		err = errors.Wrapf(err, "Initial secret load failed")
	}

	return ts, err
}

// InitK8sClients Initializes the connection to Kubernetes.  This function has to figure out whether you're running IN a k8s cluster, or running with access to one, and initialize the proper goodies to make you able to connect.  It's intended to be called once at bot creation time.
func (ts *TlsSync) InitK8sClients() (err error) {
	var namespace string
	var clientConfig *rest.Config

	if _, err := os.Stat(IN_POD_NAMESPACE_FILE); !os.IsNotExist(err) {
		b, err := ioutil.ReadFile(IN_POD_NAMESPACE_FILE)
		if err != nil {
			err = errors.Wrapf(err, "failed to read in-pod namespace file %s", IN_POD_NAMESPACE_FILE)
			return err
		}

		namespace = string(b)

		clientConfig, err = rest.InClusterConfig()
		if err != nil {
			err = errors.Wrapf(err, "failed getting in-cluster client config")
			return err
		}
	} else {
		configFile := fmt.Sprintf("%s/.kube/config", homedir.HomeDir())
		if _, err := os.Stat(configFile); !os.IsNotExist(err) {
			config, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
			if err != nil {
				err = errors.Wrapf(err, "failed to load kubeconfig")
				return err
			}

			namespace = config.Contexts[config.CurrentContext].Namespace

			clientConfig, err = clientcmd.NewDefaultClientConfig(*config, &clientcmd.ConfigOverrides{}).ClientConfig()
			if err != nil {
				return err
			}
		}

	}

	var clientset *kubernetes.Clientset
	var dynamicClient dynamic.Interface

	if clientConfig != nil {
		clientset, err = kubernetes.NewForConfig(clientConfig)
		if err != nil {
			err = errors.Wrapf(err, "failed to create clientset from config")
			return err
		}

		dynamicClient, err = dynamic.NewForConfig(clientConfig)
		if err != nil {
			err = errors.Wrapf(err, "failed to generate dynamic client")
			return err
		}
	}

	ts.K8sNamespace = namespace
	ts.K8sConfig = clientConfig
	ts.K8sClientset = clientset
	ts.K8sDynamicClient = dynamicClient

	log.Infof("K8s Namespace: %s", namespace)
	log.Infof("K8s ClientConfig: %v", clientConfig)
	log.Infof("K8s Clientset: %v", clientset)
	log.Infof("K8s Dynamic Client: %v", dynamicClient)

	return err
}

// GetSecretByName  Attempts to retrieve a secret based on it's name.  This will fail unless the bot is configured with proper RBAC permission to read secrets in its namespace.
func (ts *TlsSync) GetSecretByName(name string) (secret *v1.Secret, err error) {
	log.Infof("Getting Secret %q", name)
	secret, err = ts.K8sClientset.CoreV1().Secrets(ts.K8sNamespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		err = errors.Wrapf(err, "failed getting secret %q", name)
		log.Infof("Failed!")
		return secret, err
	}

	log.Infof("Success!")

	return secret, err
}

// ChecksumSecret  Given a secret, calculate a checksum over it's data field, then return the checksum
func ChecksumSecret(secret *v1.Secret) (checksum string, err error) {
	// secret data comes in as a map, and could be in any order.
	// We don't care about order, but want to capture a checksum for the entire secret.
	// So first we impose an order, by making a list of the keys, and then sorting them.
	secretKeys := make([]string, 0)
	for k := range secret.Data {
		secretKeys = append(secretKeys, k)
	}

	// order the keys alphabetically
	sort.Strings(secretKeys)

	// New hasher object for calculating the checksum
	hasher := sha256.New()

	// iterate over the ordered keys
	for _, k := range secretKeys {
		// take the bytes representing the key + a colon
		b := []byte(fmt.Sprintf("%s:", k))
		for _, sb := range secret.Data[k] {
			// append the bytes for the value corresponding to that key
			b = append(b, sb)
		}
		// write that whole array of bytes to the hasher
		_, err = hasher.Write(b)
		if err != nil {
			err = errors.Wrapf(err, "Failed to add bytes for secret key %q", k)

			return checksum, err
		}
	}

	// pull out the hexadecimal representation of the checksum
	checksum = hex.EncodeToString(hasher.Sum(nil))

	// and return it
	return checksum, err
}

func (ts *TlsSync) LoadSecrets() (err error) {
	for _, tlsFile := range ts.TlsFiles {
		// get each secret
		secret, err := ts.GetSecretByName(tlsFile.SecretName)
		if err != nil {
			err = errors.Wrapf(err, "failed to get secert %q", tlsFile.SecretName)
			return err
		}

		_, crtOk := secret.Data["tls.crt"]
		_, keyOk := secret.Data["tls.key"]

		if !crtOk || !keyOk {
			err = errors.New(fmt.Sprintf("%s is not a TLS Secret.  Cannot continue.", tlsFile.SecretName))
			return err
		}

		// checksum each secret
		checksum, err := ChecksumSecret(secret)
		if err != nil {
			err = errors.Wrapf(err, "failed to checksum secret %q", tlsFile.SecretName)
			return err
		}

		// compare the checksum against the last value
		// if this is the first run, checksum should be "", ergo we should write.
		if checksum != tlsFile.Checksum {
			log.Infof("New data in secret %s", tlsFile.SecretName)

			// store the current value
			tlsFile.Checksum = checksum
			tlsFile.Data = secret.Data

			err = ts.WritePEMFiles(tlsFile)
			if err != nil {
				err = errors.Wrapf(err, "failed to write file for %s", tlsFile.SecretName)
				return err
			}
		}
	}

	return err
}

// MonitorSecrets Waits the configured seconds and then reloads the secrets it monitors, and updates the local files if they have changed.
func (ts *TlsSync) MonitorSecrets() (err error) {
	rand.Seed(time.Now().UnixNano())
	n := rand.Intn(20)
	sleepSeconds := time.Duration(ts.MonitorSecretsInterval + n)

	for {
		time.Sleep(sleepSeconds * time.Second)

		log.Infof("Checking Secrets")

		// load the secrets - writing the new files is handled by LoadSecrets()
		err := ts.LoadSecrets()
		if err != nil {
			err = errors.Wrapf(err, "failed to load secrets")
			return err
		}
	}

	return err
}

func (ts *TlsSync) WritePEMFiles(tlsFile *TlsFile) (err error) {
	if tlsFile.SeparateFiles {
		fileName := fmt.Sprintf("%s/%s.%s", tlsFile.FilePath, tlsFile.FileBase, CRT_FILE_EXTENSION)
		data := make([]byte, 0)

		data = append(data, tlsFile.Data["tls.crt"]...)

		err = ioutil.WriteFile(fileName, data, 0644)
		if err != nil {
			err = errors.Wrapf(err, "failed to write file %s", fileName)
			return err
		}

		fileName = fmt.Sprintf("%s/%s.%s", tlsFile.FilePath, tlsFile.FileBase, KEY_FILE_EXTENSION)
		data = make([]byte, 0)

		data = append(data, tlsFile.Data["tls.key"]...)

		err = ioutil.WriteFile(fileName, data, 0644)
		if err != nil {
			err = errors.Wrapf(err, "failed to write file %s", fileName)
			return err
		}

	} else {
		fileName := fmt.Sprintf("%s/%s.%s", tlsFile.FilePath, tlsFile.FileBase, COMBINED_FILE_EXTENSION)
		data := make([]byte, 0)

		data = append(data, tlsFile.Data["tls.crt"]...)
		data = append(data, tlsFile.Data["tls.key"]...)

		err = ioutil.WriteFile(fileName, data, 0644)
		if err != nil {
			err = errors.Wrapf(err, "failed to write file %s", fileName)
			return err
		}
	}
	return err
}

func LoadConfig(filePath string) (files []*TlsFile, err error) {
	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		err = errors.Wrapf(err, "failed to load file %s", filePath)
		return files, err
	}

	err = json.Unmarshal(b, &files)
	if err != nil {
		err = errors.Wrapf(err, "failed to marshal JSON data in %s", filePath)
		return files, err
	}

	fmt.Printf("Unmarshalling produced no error\n")

	return files, err
}

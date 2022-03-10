package tlssync

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

var tmpDir string

func TestMain(m *testing.M) {
	setUp()

	code := m.Run()

	tearDown()

	os.Exit(code)
}

func setUp() {
	dir, err := ioutil.TempDir("", "tlssync")
	if err != nil {
		fmt.Printf("Error creating temp dir %q: %s\n", tmpDir, err)
		os.Exit(1)
	}

	tmpDir = dir
}

func tearDown() {
	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		_ = os.Remove(tmpDir)
	}
}

func TestGetSecretByName(t *testing.T) {
	inputs := []struct {
		Name  string
		Files []*TlsFile
	}{
		{
			"ecr-registry",
			[]*TlsFile{
				&TlsFile{
					SecretName:    "ecr-registry",
					SeparateFiles: false,
					FileBase:      "ecr-registry",
					FilePath:      fmt.Sprintf("%s/tls", tmpDir),
				},
			},
		},
	}

	for _, tc := range inputs {
		t.Run(tc.Name, func(t *testing.T) {
			ts, err := NewTlsSync(tc.Files)
			if err != nil {
				t.Errorf("Error creating bot: %s", err)
			}

			if ts.K8sClientset == nil {
				t.Skipf("Skipping test - no k8s config present")
			}

			s, err := ts.GetSecretByName(tc.Name)
			if err != nil {
				t.Errorf("failed getting secret %q: %s", tc.Name, err)
			}

			fmt.Printf("Secret:\n%v\n", s.Data)
			checksum, err := ChecksumSecret(s)
			if err != nil {
				t.Errorf("failed checksumming secret: %s", err)
			}

			fmt.Printf("Checksum: %s\n", checksum)
		})
	}
}

func TestLoadSecrets(t *testing.T) {
	inputs := []struct {
		Name  string
		Files []*TlsFile
	}{
		{
			"orion-wildcard-single",
			[]*TlsFile{
				&TlsFile{
					SecretName:    "orion-wildcard",
					SeparateFiles: false,
					FileBase:      "orion-wildcard",
					FilePath:      tmpDir,
				},
			},
		},
		{
			"orion-wildcard-multiple",
			[]*TlsFile{
				&TlsFile{
					SecretName:    "orion-wildcard",
					SeparateFiles: true,
					FileBase:      "orion-wildcard",
					FilePath:      tmpDir,
				},
			},
		},
	}

	for _, tc := range inputs {
		t.Run(tc.Name, func(t *testing.T) {
			ts, err := NewTlsSync(tc.Files)
			if err != nil {
				t.Errorf("Error creating bot: %s", err)
			}

			if ts.K8sClientset == nil {
				t.Skipf("Skipping test - no k8s config present")
			}

			err = ts.LoadSecrets()
			if err != nil {
				t.Errorf("Failed to load Secrets: %s", err)
			}

			for _, tlsFile := range tc.Files {
				if tlsFile.SeparateFiles {
					fileName := fmt.Sprintf("%s/%s.%s", tlsFile.FilePath, tlsFile.FileBase, CRT_FILE_EXTENSION)

					_, err := os.Stat(fileName)
					if err != nil {
						t.Errorf("Failed to find ostensibly created file %s: %s", fileName, err)
					}

					pemBytes, err := ioutil.ReadFile(fileName)
					if err != nil {
						t.Errorf("Failed reading file %s: %s", fileName, err)
					}

					block, _ := pem.Decode(pemBytes)
					_, err = x509.ParseCertificate(block.Bytes)
					if err != nil {
						t.Errorf("failed to parse PEM bytes into certificate: %s", err)
					}

					fileName = fmt.Sprintf("%s/%s.%s", tlsFile.FilePath, tlsFile.FileBase, KEY_FILE_EXTENSION)

					_, err = os.Stat(fileName)
					if err != nil {
						t.Errorf("Failed to find ostensibly created file %s: %s", fileName, err)
					}

					pemBytes, err = ioutil.ReadFile(fileName)
					if err != nil {
						t.Errorf("Failed reading file %s: %s", fileName, err)
					}

					block, _ = pem.Decode(pemBytes)
					_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
					if err != nil {
						t.Errorf("failed to parse PEM bytes into private key: %s", err)
					}

				} else {
					fileName := fmt.Sprintf("%s/%s.%s", tlsFile.FilePath, tlsFile.FileBase, COMBINED_FILE_EXTENSION)

					_, err := os.Stat(fileName)
					if err != nil {
						t.Errorf("Failed to find ostensibly created file %s: %s", fileName, err)
					}
				}
			}
		})
	}
}

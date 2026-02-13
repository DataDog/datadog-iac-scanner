/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

/*
Package kuberneter implements calls to the Kubernetes API in order to scan the runtime information of the resources
*/
package kuberneter

import (
	"context"
	"os"

	b64 "encoding/base64"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/pkg/errors"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// K8sConfig saves the config for k8s auth
type K8sConfig struct {
	Config *rest.Config
}

func getK8sClient(ctx context.Context) (client.Client, error) {
	contextLogger := logger.FromContext(ctx)
	// authentication through k8s config file
	if os.Getenv("K8S_CONFIG_FILE") != "" {
		config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("K8S_CONFIG_FILE"))

		if err != nil {
			contextLogger.Error().Msgf("failed to get k8s client through k8s config file: %s", err)
			return nil, err
		}

		contextLogger.Info().Msg("auth to k8s API through k8s config file")

		config.QPS = 100
		config.Burst = 100

		return client.New(config, client.Options{})
	}

	c := &K8sConfig{
		Config: &rest.Config{
			QPS:   100,
			Burst: 100,
		},
	}

	// authentication through k8s service account token or k8s client certificate
	if os.Getenv("K8S_HOST") != "" && c.hasCertificateAuthority(ctx) {
		c.Config.Host = os.Getenv("K8S_HOST")

		// authentication through k8s service account token
		if c.hasServiceAccountToken() {
			contextLogger.Info().Msg("auth to k8s API through k8s service account token")
			return client.New(c.Config, client.Options{})
		}

		// authentication through k8s client certificate
		if c.hasClientCertificate(ctx) {
			contextLogger.Info().Msg("auth to k8s API through k8s client certificate")
			return client.New(c.Config, client.Options{})
		}
	}

	contextLogger.Error().Msg("failed to get k8s client. check the k8s cluster auth information")
	return nil, errors.New("failed to get k8s client")
}

func (c *K8sConfig) hasCertificateAuthority(ctx context.Context) bool {
	contextLogger := logger.FromContext(ctx)
	if os.Getenv("K8S_CA_FILE") != "" {
		c.Config.CAFile = os.Getenv("K8S_CA_FILE")
		return true
	}

	if os.Getenv("K8S_CA_DATA") != "" {
		caDataDecoded, err := b64.StdEncoding.DecodeString(os.Getenv("K8S_CA_DATA"))
		if err != nil {
			contextLogger.Error().Msgf("failed to decode K8S_CA_DATA: %s", err)
			return false
		}
		c.Config.CAData = caDataDecoded
		return true
	}

	return false
}

func (c *K8sConfig) hasServiceAccountToken() bool {
	if os.Getenv("K8S_SA_TOKEN_FILE") != "" {
		c.Config.BearerTokenFile = os.Getenv("K8S_SA_TOKEN_FILE")
		return true
	}

	if os.Getenv("K8S_SA_TOKEN_DATA") != "" {
		c.Config.BearerToken = os.Getenv("K8S_SA_TOKEN_DATA")
		return true
	}

	return false
}

func (c *K8sConfig) hasClientCertificate(ctx context.Context) bool {
	contextLogger := logger.FromContext(ctx)
	hasCert := false

	if os.Getenv("K8S_CERT_FILE") != "" {
		c.Config.CertFile = os.Getenv("K8S_CERT_FILE")
		hasCert = true
	}

	if os.Getenv("K8S_CERT_DATA") != "" {
		certDataDecoded, err := b64.StdEncoding.DecodeString(os.Getenv("K8S_CERT_DATA"))
		if err != nil {
			contextLogger.Error().Msgf("failed to decode K8S_CERT_DATA: %s", err)
			return false
		}
		c.Config.CertData = certDataDecoded
		hasCert = true
	}

	if hasCert {
		if os.Getenv("K8S_KEY_FILE") != "" {
			c.Config.KeyFile = os.Getenv("K8S_KEY_FILE")
			return true
		}

		if os.Getenv("K8S_KEY_DATA") != "" {
			keyDataDecoded, err := b64.StdEncoding.DecodeString(os.Getenv("K8S_KEY_DATA"))
			if err != nil {
				contextLogger.Error().Msgf("failed to decode K8S_KEY_DATA: %s", err)
				return false
			}
			c.Config.KeyData = keyDataDecoded
			return true
		}
	}

	return false
}

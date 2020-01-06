/*
 * Copyright The Titan Project Contributors.
 */
package s3

import (
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/titan-data/remote-sdk-go/remote"
	"net/url"
	"strings"
)

type s3webRemote struct {
}

func (s s3webRemote) Type() string {
	return "s3"
}

func (s s3webRemote) FromURL(url *url.URL, additionalProperties map[string]string) (map[string]interface{}, error) {
	if url.Scheme != "s3" {
		return nil, errors.New("invalid remote scheme")
	}

	if url.User != nil {
		return nil, errors.New("remote username and password cannot be specified")
	}

	if url.Port() != "" {
		return nil, errors.New("remote port cannot be specified")
	}

	if url.Hostname() == "" {
		return nil, errors.New("missing remote bucket name")
	}

	accessKey := additionalProperties["accessKey"]
	secretKey := additionalProperties["secretKey"]
	region := additionalProperties["region"]
	for k := range additionalProperties {
		if k != "accessKey" && k != "secretKey" && k != "region" {
			return nil, errors.New(fmt.Sprintf("invalid remote property '%s'", k))
		}
	}

	if (accessKey == "" && secretKey != "") || (accessKey != "" && secretKey == "") {
		return nil, errors.New(fmt.Sprintf("either both of accessKey and secretKey must be set, or neither"))
	}

	path := url.Path
	if strings.Index(path, "/") == 0 {
		path = path[1:]
	}

	result := map[string]interface{}{"bucket": url.Hostname()}
	if accessKey != "" {
		result["accessKey"] = accessKey
	}
	if secretKey != "" {
		result["secretKey"] = secretKey
	}
	if region != "" {
		result["region"] = region
	}
	if path != "" {
		result["path"] = path
	}

	return result, nil
}

func (s s3webRemote) ToURL(properties map[string]interface{}) (string, map[string]string, error) {
	u := fmt.Sprintf("s3://%s", properties["bucket"])
	if properties["path"] != nil {
		u += fmt.Sprintf("/%s", properties["path"])
	}

	params := map[string]string{}
	if properties["accessKey"] != nil {
		params["accessKey"] = properties["accessKey"].(string)
	}
	if properties["secretKey"] != nil {
		params["secretKey"] = properties["secretKey"].(string)
	}
	if properties["region"] != nil {
		params["region"] = properties["region"].(string)
	}

	return u, params, nil
}

var newSession = session.NewSession

func (s s3webRemote) GetParameters(remoteProperties map[string]interface{}) (map[string]interface{}, error) {
	result := map[string]interface{}{}
	if remoteProperties["accessKey"] != nil {
		result["accessKey"] = remoteProperties["accessKey"].(string)
	}
	if remoteProperties["secretKey"] != nil {
		result["secretKey"] = remoteProperties["secretKey"].(string)
	}
	if remoteProperties["region"] != nil {
		result["region"] = remoteProperties["region"].(string)
	}

	if result["accessKey"] == nil || result["secretKey"] == nil || result["region"] == nil {
		sess, err := newSession()
		if err != nil {
			return nil, err
		}

		creds, err := sess.Config.Credentials.Get()
		if err != nil {
			return nil, err
		}

		if result["accessKey"] == nil && creds.AccessKeyID != "" {
			result["accessKey"] = creds.AccessKeyID
		}
		if result["secretKey"] == nil && creds.SecretAccessKey != "" {
			result["secretKey"] = creds.SecretAccessKey
		}
		if creds.SessionToken != "" {
			result["sessionToken"] = creds.SessionToken
		}
		if result["region"] == nil && sess.Config.Region != nil {
			result["region"] = *sess.Config.Region
		}

		if result["accessKey"] == nil || result["secretKey"] == nil {
			return nil, errors.New("unable to determine AWS credentials")
		}
		if result["region"] == nil {
			return nil, errors.New("unable to determine AWS region")
		}
	}

	return result, nil
}

func init() {
	remote.Register(s3webRemote{})
}

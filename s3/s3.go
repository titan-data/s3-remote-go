/*
 * Copyright The Titan Project Contributors.
 */
package s3

import (
	"errors"
	"fmt"
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
	u := properties["url"].(string)
	return strings.Replace(u, "http", "s3web", 1), map[string]string{}, nil
}

func (s s3webRemote) GetParameters(remoteProperties map[string]interface{}) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}

func init() {
	remote.Register(s3webRemote{})
}

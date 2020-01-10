/*
 * Copyright The Titan Project Contributors.
 */
package s3

import (
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/stretchr/testify/assert"
	"github.com/titan-data/remote-sdk-go/remote"
	"os"
	"testing"
)

func TestRegistered(t *testing.T) {
	r := remote.Get("s3")
	ret, _ := r.Type()
	assert.Equal(t, "s3", ret)
}

func TestFromURL(t *testing.T) {
	r := remote.Get("s3")
	props, _ := r.FromURL("s3://bucket/object/path", map[string]string{})
	assert.Equal(t, "bucket", props["bucket"])
	assert.Equal(t, "object/path", props["path"])
	assert.Nil(t, props["accessKey"])
	assert.Nil(t, props["secretKey"])
	assert.Nil(t, props["region"])
}

func TestNoPath(t *testing.T) {
	r := remote.Get("s3")
	props, _ := r.FromURL("s3://bucket", map[string]string{})
	assert.Equal(t, "bucket", props["bucket"])
	assert.Nil(t, props["path"])
	assert.Nil(t, props["accessKey"])
	assert.Nil(t, props["secretKey"])
	assert.Nil(t, props["region"])
}

func TestBadScheme(t *testing.T) {
	r := remote.Get("s3")
	_, err := r.FromURL("s3", map[string]string{})
	assert.NotNil(t, err)
}

func TestBadSchemeName(t *testing.T) {
	r := remote.Get("s3")
	_, err := r.FromURL("foo://bucket/path", map[string]string{})
	assert.NotNil(t, err)
}

func TestBadProperty(t *testing.T) {
	r := remote.Get("s3")
	_, err := r.FromURL("s3://bucket/object/path", map[string]string{"foo": "bar"})
	assert.NotNil(t, err)
}

func TestBadUser(t *testing.T) {
	r := remote.Get("s3")
	_, err := r.FromURL("s3://user@bucket/object/path", map[string]string{})
	assert.NotNil(t, err)
}

func TestBadUserPassword(t *testing.T) {
	r := remote.Get("s3")
	_, err := r.FromURL("s3://user:password@bucket/object/path", map[string]string{})
	assert.NotNil(t, err)
}

func TestBadPort(t *testing.T) {
	r := remote.Get("s3")
	_, err := r.FromURL("s3://bucket:80/object/path", map[string]string{})
	assert.NotNil(t, err)
}

func TestBadMissingBucket(t *testing.T) {
	r := remote.Get("s3")
	_, err := r.FromURL("s3:///object/path", map[string]string{})
	assert.NotNil(t, err)
}

func TestProperties(t *testing.T) {
	r := remote.Get("s3")
	props, _ := r.FromURL("s3://bucket/object/path", map[string]string{
		"accessKey": "ACCESS", "secretKey": "SECRET", "region": "REGION",
	})
	assert.Equal(t, "bucket", props["bucket"])
	assert.Equal(t, "object/path", props["path"])
	assert.Equal(t, "ACCESS", props["accessKey"])
	assert.Equal(t, "SECRET", props["secretKey"])
	assert.Equal(t, "REGION", props["region"])
}

func TestBadAccessKeyOnly(t *testing.T) {
	r := remote.Get("s3")
	_, err := r.FromURL("s3://bucket/object/path", map[string]string{"accessKey": "ACCESS"})
	assert.NotNil(t, err)
}

func TestBadSecretKeyOnly(t *testing.T) {
	r := remote.Get("s3")
	_, err := r.FromURL("s3://bucket/object/path", map[string]string{"secretKey": "ACCESS"})
	assert.NotNil(t, err)
}

func TestToURL(t *testing.T) {
	r := remote.Get("s3")
	u, props, _ := r.ToURL(map[string]interface{}{"bucket": "bucket", "path": "path"})
	assert.Equal(t, "s3://bucket/path", u)
	assert.Empty(t, props)
}

func TestWithKeys(t *testing.T) {
	r := remote.Get("s3")
	u, props, _ := r.ToURL(map[string]interface{}{"bucket": "bucket", "path": "path",
		"accessKey": "ACCESS", "secretKey": "SECRET"})
	assert.Equal(t, "s3://bucket/path", u)
	assert.Len(t, props, 2)
	assert.Equal(t, "ACCESS", props["accessKey"])
	assert.Equal(t, "SECRET", props["secretKey"])
}

func TestWithRegsion(t *testing.T) {
	r := remote.Get("s3")
	u, props, _ := r.ToURL(map[string]interface{}{"bucket": "bucket", "path": "path",
		"region": "REGION"})
	assert.Equal(t, "s3://bucket/path", u)
	assert.Len(t, props, 1)
	assert.Equal(t, "REGION", props["region"])
}

func TestGetParameters(t *testing.T) {
	r := remote.Get("s3")
	props, _ := r.GetParameters(map[string]interface{}{"bucket": "bucket", "path": "path",
		"accessKey": "ACCESS", "secretKey": "SECRET", "region": "REGION"})
	assert.Equal(t, "ACCESS", props["accessKey"])
	assert.Equal(t, "SECRET", props["secretKey"])
	assert.Equal(t, "REGION", props["region"])
}

func TestGetParametersEnvironment(t *testing.T) {
	r := remote.Get("s3")
	_ = os.Setenv("AWS_ACCESS_KEY_ID", "ACCESS")
	_ = os.Setenv("AWS_SECRET_ACCESS_KEY", "SECRET")
	_ = os.Setenv("AWS_REGION", "us-west-2")
	_ = os.Setenv("AWS_SESSION_TOKEN", "TOKEN")
	props, _ := r.GetParameters(map[string]interface{}{"bucket": "bucket", "path": "path"})
	assert.Equal(t, "ACCESS", props["accessKey"])
	assert.Equal(t, "SECRET", props["secretKey"])
	assert.Equal(t, "us-west-2", props["region"])
	assert.Equal(t, "TOKEN", props["sessionToken"])
}

func TestBadNewSession(t *testing.T) {
	r := remote.Get("s3")
	newSession = func(cfgs ...*aws.Config) (session *session.Session, err error) {
		return nil, errors.New("err")
	}
	_, err := r.GetParameters(map[string]interface{}{"bucket": "bucket", "path": "path"})
	assert.NotNil(t, err)
	newSession = session.NewSession
}

func TestBadConfigCredentials(t *testing.T) {
	r := remote.Get("s3")
	p := new(MockProvider)
	p.On("Retrieve").Return(credentials.Value{}, errors.New("err"))
	newSession = func(cfgs ...*aws.Config) (*session.Session, error) {
		return &session.Session{
			Config: &aws.Config{
				Credentials: credentials.NewCredentials(p),
			},
		}, nil
	}
	_, err := r.GetParameters(map[string]interface{}{"bucket": "bucket", "path": "path"})
	assert.NotNil(t, err)
	newSession = session.NewSession
}

func TestBadCredentialsAccessKey(t *testing.T) {
	r := remote.Get("s3")
	p := new(MockProvider)
	p.On("Retrieve").Return(credentials.Value{}, nil)
	newSession = func(cfgs ...*aws.Config) (*session.Session, error) {
		return &session.Session{
			Config: &aws.Config{
				Credentials: credentials.NewCredentials(p),
			},
		}, nil
	}
	_, err := r.GetParameters(map[string]interface{}{"bucket": "bucket", "path": "path"})
	assert.NotNil(t, err)
	newSession = session.NewSession
}

func TestBadCredentialsRegion(t *testing.T) {
	r := remote.Get("s3")
	p := new(MockProvider)
	p.On("Retrieve").Return(credentials.Value{
		AccessKeyID:     "ACCESS",
		SecretAccessKey: "SECRET",
	}, nil)
	newSession = func(cfgs ...*aws.Config) (*session.Session, error) {
		return &session.Session{
			Config: &aws.Config{
				Credentials: credentials.NewCredentials(p),
			},
		}, nil
	}
	_, err := r.GetParameters(map[string]interface{}{"bucket": "bucket", "path": "path"})
	assert.NotNil(t, err)
	newSession = session.NewSession
}

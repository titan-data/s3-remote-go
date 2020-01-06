/*
 * Copyright The Titan Project Contributors.
 */
package s3

import (
	"github.com/stretchr/testify/assert"
	"github.com/titan-data/remote-sdk-go/remote"
	"net/url"
	"testing"
)

func TestRegistered(t *testing.T) {
	r := remote.Get("s3")
	assert.Equal(t, "s3", r.Type())
}

func TestFromURL(t *testing.T) {
	r := remote.Get("s3")
	u, _ := url.Parse("s3://bucket/object/path")
	props, _ := r.FromURL(u, map[string]string{})
	assert.Equal(t, "bucket", props["bucket"])
	assert.Equal(t, "object/path", props["path"])
	assert.Nil(t, props["accessKey"])
	assert.Nil(t, props["secretKey"])
	assert.Nil(t, props["region"])
}

func TestNoPath(t *testing.T) {
	r := remote.Get("s3")
	u, _ := url.Parse("s3://bucket")
	props, _ := r.FromURL(u, map[string]string{})
	assert.Equal(t, "bucket", props["bucket"])
	assert.Nil(t, props["path"])
	assert.Nil(t, props["accessKey"])
	assert.Nil(t, props["secretKey"])
	assert.Nil(t, props["region"])
}

func TestBadScheme(t *testing.T) {
	r := remote.Get("s3")
	u, _ := url.Parse("s3")
	_, err := r.FromURL(u, map[string]string{})
	assert.NotNil(t, err)
}

func TestBadSchemeName(t *testing.T) {
	r := remote.Get("s3")
	u, _ := url.Parse("foo://bucket/path")
	_, err := r.FromURL(u, map[string]string{})
	assert.NotNil(t, err)
}

func TestBadProperty(t *testing.T) {
	r := remote.Get("s3")
	u, _ := url.Parse("s3://bucket/object/path")
	_, err := r.FromURL(u, map[string]string{"foo": "bar"})
	assert.NotNil(t, err)
}

func TestBadUser(t *testing.T) {
	r := remote.Get("s3")
	u, _ := url.Parse("s3://user@bucket/object/path")
	_, err := r.FromURL(u, map[string]string{})
	assert.NotNil(t, err)
}

func TestBadUserPassword(t *testing.T) {
	r := remote.Get("s3")
	u, _ := url.Parse("s3://user:password@bucket/object/path")
	_, err := r.FromURL(u, map[string]string{})
	assert.NotNil(t, err)
}

func TestBadPort(t *testing.T) {
	r := remote.Get("s3")
	u, _ := url.Parse("s3://bucket:80/object/path")
	_, err := r.FromURL(u, map[string]string{})
	assert.NotNil(t, err)
}

func TestBadMissingBucket(t *testing.T) {
	r := remote.Get("s3")
	u, _ := url.Parse("s3:///object/path")
	_, err := r.FromURL(u, map[string]string{})
	assert.NotNil(t, err)
}

func TestProperties(t *testing.T) {
	r := remote.Get("s3")
	u, _ := url.Parse("s3://bucket/object/path")
	props, _ := r.FromURL(u, map[string]string{
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
	u, _ := url.Parse("s3://bucket/object/path")
	_, err := r.FromURL(u, map[string]string{"accessKey": "ACCESS"})
	assert.NotNil(t, err)
}

func TestBadSecretKeyOnly(t *testing.T) {
	r := remote.Get("s3")
	u, _ := url.Parse("s3://bucket/object/path")
	_, err := r.FromURL(u, map[string]string{"secretKey": "ACCESS"})
	assert.NotNil(t, err)
}

/*
   "s3 remote to URI succeeds" {
       val (uri, props) = client.toUri(mapOf("bucket" to "bucket", "path" to "path"))
       uri shouldBe "s3://bucket/path"
       props.size shouldBe 0
   }

   "s3 remote with keys to URI succeeds" {
       val (uri, props) = client.toUri(mapOf("bucket" to "bucket", "path" to "path",
               "accessKey" to "ACCESS", "secretKey" to "SECRET"))
       uri shouldBe "s3://bucket/path"
       props.size shouldBe 2
       props["accessKey"] shouldBe "ACCESS"
       props["secretKey"] shouldBe "*****"
   }

   "s3 remote with region to URI succeeds" {
       val (uri, props) = client.toUri(mapOf("bucket" to "bucket", "path" to "path",
               "region" to "REGION"))
       uri shouldBe "s3://bucket/path"
       props.size shouldBe 1
       props["region"] shouldBe "REGION"
   }

   "s3 get parameters succeeds" {
       val params = client.getParameters(mapOf("bucket" to "bucket", "path" to "path",
               "accessKey" to "ACCESS", "secretKey" to "SECRET", "region" to "REGION"))
       params["accessKey"] shouldBe "ACCESS"
       params["secretKey"] shouldBe "SECRET"
       params["region"] shouldBe "REGION"
   }

   "getting credentials from environment succeeds" {
       withEnvironment(mapOf("AWS_ACCESS_KEY_ID" to "accessKey", "AWS_SECRET_ACCESS_KEY" to "secretKey",
               "AWS_REGION" to "us-west-2", "AWS_SESSION_TOKEN" to "sessionToken"), OverrideMode.SetOrOverride) {
           System.getenv("AWS_ACCESS_KEY_ID") shouldBe "accessKey"
           System.getenv("AWS_SECRET_ACCESS_KEY") shouldBe "secretKey"
           System.getenv("AWS_REGION") shouldBe "us-west-2"
           System.getenv("AWS_SESSION_TOKEN") shouldBe "sessionToken"
           val params = client.getParameters(mapOf("bucket" to "bucket", "path" to "path"))
           params["accessKey"] shouldBe "accessKey"
           params["secretKey"] shouldBe "secretKey"
           params["sessionToken"] shouldBe "sessionToken"
           params["region"] shouldBe "us-west-2"
       }
   }

   "failure to resolve AWS credentials fails" {
       mockkStatic(DefaultCredentialsProvider::class)
       val credentialsProvider = mockk<DefaultCredentialsProvider>()
       every { DefaultCredentialsProvider.create() } returns credentialsProvider
       every { credentialsProvider.resolveCredentials() } returns null
       shouldThrow<IllegalArgumentException> {
           client.getParameters(mapOf("bucket" to "bucket", "path" to "path"))
       }
   }

   "AWS credentials without access key fails" {
       mockkStatic(DefaultCredentialsProvider::class)
       val credentialsProvider = mockk<DefaultCredentialsProvider>()
       every { DefaultCredentialsProvider.create() } returns credentialsProvider
       val credentials = mockk<AwsCredentials>()
       every { credentialsProvider.resolveCredentials() } returns credentials
       every { credentials.accessKeyId() } returns null
       every { credentials.secretAccessKey() } returns null
       shouldThrow<IllegalArgumentException> {
           client.getParameters(mapOf("bucket" to "bucket", "path" to "path"))
       }
   }
*/

/*

func TestNoPath(t *testing.T) {
	r := remote.Get("s3web")
	u, _ := url.Parse("s3web://host")
	props, _ := r.FromURL(u, map[string]string{})
	assert.Equal(t, "http://host", props["url"])
}

func TestBadProperty(t *testing.T) {
	r := remote.Get("s3web")
	u, _ := url.Parse("s3web://host")
	_, err := r.FromURL(u, map[string]string{"a": "b"})
	assert.NotNil(t, err)
}

func TestBadUser(t *testing.T) {
	r := remote.Get("s3web")
	u, _ := url.Parse("s3web://user@host/path")
	_, err := r.FromURL(u, map[string]string{})
	assert.NotNil(t, err)
}

func TestBadUserPassword(t *testing.T) {
	r := remote.Get("s3web")
	u, _ := url.Parse("s3web://user:password@host/path")
	_, err := r.FromURL(u, map[string]string{})
	assert.NotNil(t, err)
}

func TestBadNoHost(t *testing.T) {
	r := remote.Get("s3web")
	u, _ := url.Parse("s3web:///path")
	_, err := r.FromURL(u, map[string]string{})
	assert.NotNil(t, err)
}

func TestPort(t *testing.T) {
	r := remote.Get("s3web")
	u, _ := url.Parse("s3web://host:1023/object/path")
	props, _ := r.FromURL(u, map[string]string{})
	assert.Equal(t, "http://host:1023/object/path", props["url"])
}

func TestToURL(t *testing.T) {
	r := remote.Get("s3web")
	u, props, _ := r.ToURL(map[string]interface{}{"url": "http://host/path"})
	assert.Equal(t, "s3web://host/path", u)
	assert.Empty(t, props)
}

func TestParameters(t *testing.T) {
	r := remote.Get("s3web")
	props, _ := r.GetParameters(map[string]interface{}{"url": "http://host/path"})
	assert.Empty(t, props)
}
*/

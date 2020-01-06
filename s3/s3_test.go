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

/*
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


func TestParameters(t *testing.T) {
	r := remote.Get("s3web")
	props, _ := r.GetParameters(map[string]interface{}{"url": "http://host/path"})
	assert.Empty(t, props)
}
*/

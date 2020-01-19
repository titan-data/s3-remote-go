/*
 * Copyright The Titan Project Contributors.
 */
package s3

import (
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/stretchr/testify/mock"
)

type MockProvider struct {
	mock.Mock
}

func (p *MockProvider) Retrieve() (credentials.Value, error) {
	args := p.Called()
	return args.Get(0).(credentials.Value), args.Error(1)
}

func (p *MockProvider) IsExpired() bool {
	args := p.Called()
	return args.Bool(0)
}

type MockS3 struct {
	s3iface.S3API
	err error
	*s3.GetObjectInput
	s3.GetObjectOutput
}

func (m *MockS3) GetObject(in *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	m.GetObjectInput = in
	return &m.GetObjectOutput, m.err
}

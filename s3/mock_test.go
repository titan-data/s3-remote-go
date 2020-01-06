package s3

import (
	"github.com/aws/aws-sdk-go/aws/credentials"
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

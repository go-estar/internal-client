package internalClient

import (
	"context"
	"github.com/go-estar/config"
	"testing"
)

type createReq struct {
	Id int
}
type createRes struct {
	Id   int
	Name string `json:"name"`
}
type getReq struct {
	Id int
}
type getRes struct {
	Name string `json:"name"`
}
type TestClient struct {
	Create func(ctx context.Context, req *createReq, opts ...Option) (*createRes, error)
	Get    func(ctx context.Context, req *getReq, opts ...Option) (*getRes, error)
}

func TestInternalClient(t *testing.T) {
	c := NewTestClient(&ClientConfig{
		Host: "http://localhost:7001",
	})
	res, err := c.Create(context.Background(), &createReq{1})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(res)
}

func NewTestClient(c *ClientConfig, opts ...ClientOption) *TestClient {
	return CreateTestClient(NewClient(c, opts...))
}

func NewTestClientWithConfig(prefixKey string, c *config.Config, opts ...ClientOption) *TestClient {
	return CreateTestClient(NewClientWithConfig(prefixKey, c, opts...))
}

func CreateTestClient(c *Client) *TestClient {
	c.SetServerConfig(&ServerConfig{
		Name:            "测试",
		ApplicationName: "test",
	})
	return &TestClient{
		Create: NewService[createReq, createRes](c, "create1", "/test/create1", "POST"),
		Get:    NewService[getReq, getRes](c, "get", "/test/get", "POST"),
	}
}

package internalClient

import (
	"testing"
)

var TestClient = NewClient(&ClientConfig{
	Server:      "test1",
	Host:        "http://localhost:7001",
	Name:        "测试",
	SucceedCode: "00",
})

var TestService = &testService{
	Create: NewService[Req, Res](TestClient, "create", "/test/create"),
	Get:    NewService[Req, Res](TestClient, "get", "/test/get"),
}

type Req struct {
	Id int
}
type Res struct {
	Name string `json:"name"`
}

type testService struct {
	Create *Service[Req, Res]
	Get    *Service[Req, Res]
}

func TestInternalClient(t *testing.T) {
	res, err := TestService.Create.Request(&Req{1})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(res)
}

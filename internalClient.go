package internalClient

import (
	"context"
	"fmt"
	"github.com/go-estar/base-error"
	"github.com/go-estar/config"
	"github.com/go-estar/types/mapUtil"
	"github.com/go-resty/resty/v2"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/opentracing/opentracing-go/log"
	"github.com/tidwall/gjson"
	"reflect"
	"strings"
)

var (
	ErrorParams   = baseError.NewSystem("%s参数错误:%s")
	ErrorRequest  = baseError.NewSystem("%s连接失败:%s")
	ErrorResponse = baseError.NewSystem("%s响应失败:%s")
	ErrorInternal = baseError.NewSystem("%s内部错误:%s")
	ErrorData     = baseError.NewSystem("%s数据异常")
)

type Signer interface {
	Sign(map[string]interface{}) error
}

type BasicAuth struct{ Username, Password string }

type ClientConfig struct {
	Signer
	*BasicAuth
	ClientId          string
	Server            string
	Host              string
	Name              string
	CodeProperty      string
	MessageProperty   string
	DataProperty      string
	SystemProperty    string
	ChainProperty     string
	SucceedCode       interface{}
	InternalErrorCode interface{}
}
type Client struct {
	*ClientConfig
}

func NewClient(cc *ClientConfig) *Client {
	if cc == nil {
		panic("Client Config 必须设置")
	}
	if cc.Server == "" {
		panic("Client Server 必须设置")
	}
	if cc.Host == "" {
		panic("Client Host 必须设置")
	}
	if cc.Name == "" {
		panic("Client Label 必须设置")
	}
	if cc.CodeProperty == "" {
		cc.CodeProperty = "code"
	}
	if cc.MessageProperty == "" {
		cc.MessageProperty = "message"
	}
	if cc.DataProperty == "" {
		cc.DataProperty = "data"
	}
	if cc.SystemProperty == "" {
		cc.SystemProperty = "system"
	}
	if cc.ChainProperty == "" {
		cc.ChainProperty = "chain"
	}
	if cc.SucceedCode == nil {
		cc.SucceedCode = "00"
	}
	if cc.InternalErrorCode == nil {
		cc.InternalErrorCode = "500"
	}
	return &Client{cc}
}

func NewClientWithConfig(server string, name string, port string, c *config.Config) *Client {
	host := "http://127.0.0.1:" + port
	if ns := c.GetString("cluster.namespace"); ns != "" {
		host = server + "." + c.GetString("cluster.namespace")
		if dnsSuffix := c.GetString("cluster.dnsSuffix"); dnsSuffix != "" {
			host = host + "." + dnsSuffix
			port = "80"
			host = "http://" + host + ":" + port
		}
	}
	clientConfig := &ClientConfig{
		Server: server,
		Name:   name,
		Host:   host,
	}
	if c.GetString("internal.basicAuth.username") != "" && c.GetString("internal.basicAuth.password") != "" {
		clientConfig.BasicAuth = &BasicAuth{
			Username: c.GetString("internal.basicAuth.username"),
			Password: c.GetString("internal.basicAuth.password"),
		}
	}
	return NewClient(clientConfig)
}

type RequestConfig struct {
	Ctx context.Context
}

type RequestOption func(*RequestConfig)

func WithCtx(val context.Context) RequestOption {
	return func(opts *RequestConfig) {
		opts.Ctx = val
	}
}

type Service[Q any, S any] struct {
	c      *Client
	name   string
	path   string
	method string
}

func NewService[Q any, S any](client *Client, name, path string, methods ...string) *Service[Q, S] {
	if client == nil {
		panic("Service Client 必须设置")
	}
	if name == "" {
		panic("Service Name 必须设置")
	}
	if path == "" {
		panic("Service Path 必须设置")
	}
	var method = "POST"
	if len(methods) > 0 {
		method = methods[0]
	}
	return &Service[Q, S]{
		c:      client,
		name:   name,
		path:   path,
		method: method,
	}
}

func (s *Service[Q, S]) Request(req *Q, opts ...RequestOption) (*S, error) {
	var err error
	rc := &RequestConfig{}
	for _, apply := range opts {
		apply(rc)
	}
	headers, span := s.trace(rc.Ctx)
	defer func() {
		if span != nil {
			if err != nil {
				if baseError.IsNotSystemError(err) {
					span.LogFields(log.String("error", err.Error()))
				} else {
					ext.LogError(span, err)
				}
			}
			span.Finish()
		}
	}()

	request := resty.New().R()
	request = request.SetHeaders(headers)
	if s.c.BasicAuth != nil {
		request = request.SetBasicAuth(s.c.Username, s.c.Password)
	}
	if s.c.Signer != nil {
		data, err := mapUtil.FromStruct(req)
		if err != nil {
			return nil, ErrorParams.Clone().WithMsgArgs(s.c.Name, err)
		}
		if s.c.ClientId != "" {
			data["appId"] = s.c.ClientId
		}
		s.c.Sign(data)
		request = request.SetBody(data)
	} else {
		request = request.SetBody(req)
	}

	resp, err := request.Execute(strings.ToUpper(s.method), s.c.Host+s.path)
	if err != nil {
		return nil, ErrorRequest.Clone().WithMsgArgs(s.c.Name, err).WithChain(s.c.Server)
	}

	body := string(resp.Body())
	code := gjson.Get(body, s.c.CodeProperty).Value()

	if code == nil {
		return nil, ErrorResponse.Clone().WithMsgArgs(s.c.Name, "无效应答码").WithChain(s.c.Server)
	}

	message := gjson.Get(body, s.c.MessageProperty).String()
	system := gjson.Get(body, s.c.SystemProperty).Bool()
	chain := gjson.Get(body, s.c.ChainProperty).Array()
	var chainArr = make([]string, 0)
	if chain != nil {
		for _, v := range chain {
			chainArr = append(chainArr, v.String())
		}
	}
	chainArr = append(chainArr, s.c.Server)
	if fmt.Sprint(code) != fmt.Sprint(s.c.SucceedCode) {
		var e *baseError.Error
		if code == s.c.InternalErrorCode {
			e = ErrorInternal.Clone().WithMsgArgs(s.c.Name, message)
		} else {
			e = baseError.NewCode(fmt.Sprint(code), message)
			if system {
				e = e.WithSystem()
			}
		}
		return nil, e.WithChain(chainArr...)
	}

	res := new(S)
	if reflect.TypeOf(res).String() == "*types.Nil" {
		return nil, nil
	}

	bodyData := gjson.Get(body, s.c.DataProperty).Value()
	if err := mapUtil.ToStruct(bodyData, res); err != nil {
		return nil, ErrorData.Clone().WithMsgArgs(s.c.Name).WithChain(chainArr...)
	}
	return res, nil
}

func (s *Service[Q, S]) trace(ctx context.Context) (map[string]string, opentracing.Span) {
	var headers = make(map[string]string)
	if ctx != nil {
		var requestId = ""
		if id := ctx.Value("x-request-id"); id != nil {
			requestId = id.(string)
		}
		headers["x-request-id"] = requestId

		span, _ := opentracing.StartSpanFromContext(ctx, s.path+":C")
		if span != nil {
			span.SetTag("x-request-id", requestId)
			ext.SpanKindRPCClient.Set(span)
			ext.HTTPMethod.Set(span, s.method)
			ext.HTTPUrl.Set(span, s.c.Host+s.path)
			if err := span.Tracer().Inject(
				span.Context(),
				opentracing.TextMap,
				opentracing.TextMapCarrier(headers),
			); err != nil {
				fmt.Println("RPCClientTrace Inject Err", err)
			}
		}
		return headers, span
	}
	return headers, nil
}

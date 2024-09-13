package internalClient

import (
	"context"
	"fmt"
	"github.com/go-estar/base-error"
	"github.com/go-estar/config"
	"github.com/go-estar/types/mapUtil"
	"github.com/go-estar/types/structUtil"
	"github.com/go-resty/resty/v2"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/opentracing/opentracing-go/log"
	"github.com/tidwall/gjson"
	"reflect"
	"strings"
	"time"
)

var (
	ErrorSign          = baseError.NewSystem("%s%s签名错误:%s")
	ErrorRequest       = baseError.NewSystem("%s%s连接失败:%s")
	ErrorResponse      = baseError.NewSystem("%s%s响应失败")
	ErrorDataNil       = baseError.NewSystem("%s%s数据异常")
	ErrorDataUnmarshal = baseError.NewSystem("%s%s数据解析失败")
)

type Signer interface {
	Property() string
	Sign(interface{}) (string, error)
}

type BasicAuth struct{ Username, Password string }

type ServerConfig struct {
	Signer
	Name            string
	ApplicationName string
	CodeProperty    string
	MessageProperty string
	DataProperty    string
	SystemProperty  string
	ChainProperty   string
	SucceedCode     interface{}
}

type ClientConfig struct {
	Host string
	*BasicAuth
	Timeout time.Duration
}
type ClientOption func(*ClientConfig)

func WithBasicAuth(val *BasicAuth) ClientOption {
	return func(opts *ClientConfig) {
		opts.BasicAuth = val
	}
}
func WithTimeout(val time.Duration) ClientOption {
	return func(opts *ClientConfig) {
		opts.Timeout = val
	}
}

type Client struct {
	cConf *ClientConfig
	sConf *ServerConfig
}

func NewClient(cc *ClientConfig, opts ...ClientOption) *Client {
	if cc == nil {
		panic("ClientConfig 必须设置")
	}
	for _, apply := range opts {
		apply(cc)
	}
	if cc.Host == "" {
		panic("ClientConfig Host 必须设置")
	}
	return &Client{
		cConf: cc,
	}
}
func (c *Client) SetServerConfig(sc *ServerConfig) *Client {
	if sc == nil {
		panic("ServerConfig 必须设置")
	}
	if sc.Name == "" {
		panic("ServerConfig Name 必须设置")
	}
	if sc.ApplicationName == "" {
		panic("ServerConfig ApplicationName 必须设置")
	}
	if sc.CodeProperty == "" {
		sc.CodeProperty = "code"
	}
	if sc.MessageProperty == "" {
		sc.MessageProperty = "message"
	}
	if sc.DataProperty == "" {
		sc.DataProperty = "data"
	}
	if sc.SystemProperty == "" {
		sc.SystemProperty = "system"
	}
	if sc.ChainProperty == "" {
		sc.ChainProperty = "chain"
	}
	if sc.SucceedCode == nil {
		sc.SucceedCode = "00"
	}
	c.sConf = sc
	return c
}

func NewClientWithConfig(prefixKey string, c *config.Config, opts ...ClientOption) *Client {
	cc := &ClientConfig{
		Host: c.GetString(prefixKey + ".host"),
	}
	username := c.GetString(prefixKey + ".basicAuth.username")
	password := c.GetString(prefixKey + ".basicAuth.password")
	if username != "" && password != "" {
		cc.BasicAuth = &BasicAuth{
			Username: username,
			Password: password,
		}
	}
	return NewClient(cc, opts...)
}

type NilDataStrategy = int8

const (
	NilDataStrategyForbidden NilDataStrategy = 0
	NilDataStrategyWithNew   NilDataStrategy = 1
	NilDataStrategyAllow     NilDataStrategy = 2
)

type ServiceConfig struct {
	NilDataStrategy
}
type ServiceOption func(*ServiceConfig)

func WithNilDataStrategy(val NilDataStrategy) ServiceOption {
	return func(opts *ServiceConfig) {
		opts.NilDataStrategy = val
	}
}

type Service[Q any, S any] struct {
	c      *Client
	name   string
	path   string
	method string
	sConf  *ServiceConfig
}

func NewService[Q any, S any](c *Client, name, path, method string, opts ...ServiceOption) func(ctx context.Context, req *Q, opts ...Option) (*S, error) {
	if c == nil {
		panic("Service Client 必须设置")
	}
	if name == "" {
		panic("Service Name 必须设置")
	}
	if path == "" {
		panic("Service Path 必须设置")
	}
	if method == "" {
		panic("Service Method 必须设置")
	}

	sc := &ServiceConfig{}
	for _, apply := range opts {
		apply(sc)
	}

	service := &Service[Q, S]{
		c:      c,
		name:   name,
		path:   path,
		method: method,
		sConf:  sc,
	}
	return service.Request
}

type RequestConfig struct {
}

type Option func(*RequestConfig)

func (s *Service[Q, S]) Request(ctx context.Context, req *Q, opts ...Option) (*S, error) {
	var err error
	rc := &RequestConfig{}
	for _, apply := range opts {
		apply(rc)
	}

	var headers = make(map[string]string)
	span := s.trace(ctx, headers)
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

	if s.c.sConf.Signer != nil {
		sign, err := s.c.sConf.Sign(req)
		if err != nil {
			return nil, ErrorSign.Clone().SetCause(err).SetMsgArgs(s.c.sConf.Name, s.name)
		}
		if err := structUtil.SetValue(req, s.c.sConf.Property(), sign); err != nil {
			return nil, ErrorSign.Clone().SetCause(err).SetMsgArgs(s.c.sConf.Name, s.name)
		}
	}

	client := resty.New()
	if s.c.cConf.Timeout != 0 {
		client.SetTimeout(s.c.cConf.Timeout)
	}
	if s.c.cConf.BasicAuth != nil {
		client.SetBasicAuth(s.c.cConf.Username, s.c.cConf.Password)
	}
	request := client.R().SetHeaders(headers).SetBody(req)
	resp, err := request.Execute(strings.ToUpper(s.method), s.c.cConf.Host+s.path)
	if err != nil {
		return nil, ErrorRequest.Clone().SetCause(err).SetMsgArgs(s.c.sConf.Name, s.name, err).SetChain(s.c.sConf.ApplicationName)
	}

	code := gjson.GetBytes(resp.Body(), s.c.sConf.CodeProperty).Value()
	if code == nil {
		return nil, ErrorResponse.Clone().SetMsgArgs(s.c.sConf.Name, s.name).SetChain(s.c.sConf.ApplicationName)
	}

	var chainArr = make([]string, 0)
	if chain := gjson.GetBytes(resp.Body(), s.c.sConf.ChainProperty).Array(); chain != nil {
		for _, v := range chain {
			chainArr = append(chainArr, v.String())
		}
	}
	chainArr = append(chainArr, s.c.sConf.ApplicationName)

	message := gjson.GetBytes(resp.Body(), s.c.sConf.MessageProperty).String()
	system := gjson.GetBytes(resp.Body(), s.c.sConf.SystemProperty).Bool()
	if fmt.Sprint(code) != fmt.Sprint(s.c.sConf.SucceedCode) {
		var e = baseError.NewCode(fmt.Sprint(code), message)
		if system {
			e = e.SetSystem()
		}
		return nil, e.SetChain(chainArr...)
	}

	res := new(S)
	if reflect.TypeOf(res).String() == "*types.Nil" {
		return nil, nil
	}
	bodyData := gjson.GetBytes(resp.Body(), s.c.sConf.DataProperty).Value()
	if bodyData == nil {
		if s.sConf.NilDataStrategy == NilDataStrategyForbidden {
			return nil, ErrorDataNil.Clone().SetMsgArgs(s.c.sConf.Name, s.name).SetChain(chainArr...)
		} else if s.sConf.NilDataStrategy == NilDataStrategyWithNew {
			return res, nil
		} else {
			return nil, nil
		}
	}
	if err := mapUtil.ToStruct(bodyData, res); err != nil {
		return nil, ErrorDataUnmarshal.Clone().SetCause(err).SetMsgArgs(s.c.sConf.Name, s.name).SetChain(chainArr...)
	}
	return res, nil
}

func (s *Service[Q, S]) trace(ctx context.Context, headers map[string]string) opentracing.Span {
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
			ext.HTTPUrl.Set(span, s.c.cConf.Host+s.path)
			if err := span.Tracer().Inject(
				span.Context(),
				opentracing.TextMap,
				opentracing.TextMapCarrier(headers),
			); err != nil {
				fmt.Println("RPCClientTrace Inject Err", err)
			}
		}
		return span
	}
	return nil
}

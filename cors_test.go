package goacors_test

import (
	"net/http"
	"testing"

	"context"

	"github.com/istyle-inc/goacors"
)

func TestNew(t *testing.T) {
	service := newService(nil)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)
	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.New(service)(h)
	err := testee(ctx, rw, req)
	if err != nil {
		t.Error("it should not return any error but ", err)
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowOrigin) != "*" {
		t.Error("allow origin should be wild card")
		t.Fail()
	}
}

func TestWithNilConfig(t *testing.T) {
	service := newService(nil)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, nil)(h)
	err := testee(ctx, rw, req)
	if err != nil {
		t.Error("it should not return any error but ", err)
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowOrigin) != "*" {
		t.Error("allow origin should be empty")
		t.Fail()
	}
}

func TestNeitherOriginHeaderAndAllowOriginGiven(t *testing.T) {
	service := newService(nil)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, &goacors.GoaCORSConfig{
		AllowCredentials: true,
	})(h)
	err := testee(ctx, rw, req)
	if err != nil {
		t.Error("it should not return any error but ", err)
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowOrigin) != "*" {
		t.Error("allow origin should be wild card but ", rw.Header().Get(goacors.HeaderAccessControlAllowOrigin))
		t.Fail()
	}
}

func TestEmptyOriginHeader(t *testing.T) {
	service := newService(nil)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(goacors.HeaderOrigin, "")
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, &goacors.GoaCORSConfig{
		AllowCredentials: true,
	})(h)
	err := testee(ctx, rw, req)
	if err != nil {
		t.Error("it should not return any error but ", err)
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowOrigin) != "*" {
		t.Error("allow origin should be wild card")
		t.Fail()
	}
}

func TestOriginAllowsWildcard(t *testing.T) {
	service := newService(nil)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(goacors.HeaderOrigin, "http://someorigin.com")
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, &goacors.GoaCORSConfig{
		AllowCredentials: true,
	})(h)
	err := testee(ctx, rw, req)
	if err != nil {
		t.Error("it should not return any error but ", err)
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowOrigin) != req.Header.Get(goacors.HeaderOrigin) {
		t.Errorf("allow origin should be %s but %s", req.Header.Get(goacors.HeaderOrigin), rw.Header().Get(goacors.HeaderAccessControlAllowOrigin))
		t.Fail()
	}
}

func TestOrigIsNotValid(t *testing.T) {
	service := newService(nil)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(goacors.HeaderOrigin, "http://someorigin.com")
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, &goacors.GoaCORSConfig{
		AllowCredentials: true,
		AllowOrigins:     []string{"http://example.com"},
	})(h)
	err := testee(ctx, rw, req)
	if err != nil {
		t.Error("it should not return any error but ", err)
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowOrigin) != "" {
		t.Error("allow origin should be empty but ", rw.Header().Get(goacors.HeaderAccessControlAllowOrigin))
		t.Fail()
	}
}

func TestOriginAllowsFixedOrigin(t *testing.T) {
	service := newService(nil)
	fixedOrigin := "http://someorigin.com"
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(goacors.HeaderOrigin, fixedOrigin)
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, &goacors.GoaCORSConfig{
		AllowOrigins:     []string{fixedOrigin},
		ExposeHeaders:    []string{"ETag"},
		AllowCredentials: true,
	})(h)
	err := testee(ctx, rw, req)
	if err != nil {
		t.Error("it should not return any error but ", err)
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowOrigin) != fixedOrigin {
		t.Error("allow origin should be empty")
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlExposeHeaders) != "ETag" {
		t.Error("expose header is unexpected ", rw.Header().Get(goacors.HeaderAccessControlExposeHeaders))
		t.Fail()
	}
}

func TestPreflightRequet(t *testing.T) {
	service := newService(nil)
	fixedOrigin := "localhost"
	req, _ := http.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set(goacors.HeaderOrigin, fixedOrigin)
	req.Header.Set(goacors.HeaderAccessControlRequestHeaders, "X-OriginalRequest")
	req.Header.Set(goacors.HeaderContentType, "application/json")
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, &goacors.GoaCORSConfig{
		AllowOrigins:     []string{fixedOrigin},
		MaxAge:           3600,
		AllowCredentials: true,
	})(h)
	err := testee(ctx, rw, req)
	if err != nil {
		t.Error("it should not return any error but ", err)
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowOrigin) != "localhost" {
		t.Error("allow origin should be empty")
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowMethods) != "GET,HEAD,PUT,PATCH,POST,DELETE" {
		t.Error("allow method should be empty but ", rw.Header().Get(goacors.HeaderAccessControlAllowMethods))
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowCredentials) != "true" {
		t.Error("allow credentials should be true")
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlMaxAge) != "3600" {
		t.Error("access control max age should be 3600 but ", rw.Header().Get(goacors.HeaderAccessControlMaxAge))
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowHeaders) != "X-OriginalRequest" {
		t.Error("access control allow headers should be 'X-OriginalRequest' but ", rw.Header().Get(goacors.HeaderAccessControlAllowHeaders))
		t.Fail()
	}

	// StatusNoContent does not allow body
	if rw.Status != http.StatusNoContent {
		t.Errorf("the status should be %d, got %d", http.StatusNoContent, rw.Status)
	}
	if len(rw.Body) != 0 {
		t.Errorf("the length of the body should be 0, got %d", len(rw.Body))
	}
}

func TestNotGivenAllowHeaderOnRequest(t *testing.T) {
	service := newService(nil)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(goacors.HeaderOrigin, "localhost")
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, &goacors.GoaCORSConfig{
		AllowCredentials: true,
		AllowOrigins:     []string{"example.com"},
	})(h)
	err := testee(ctx, rw, req)
	if err != nil {
		t.Error("it should not return any error but ", err)
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowOrigin) != "" {
		t.Error("allow origin should be empty")
		t.Fail()
	}
}

func TestExecuteWithSkipper(t *testing.T) {
	service := newService(nil)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(goacors.HeaderOrigin, "mismatchedhost")
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, &goacors.GoaCORSConfig{
		Skipper: func(c context.Context, rw http.ResponseWriter, req *http.Request) bool {
			return true
		},
		AllowCredentials: true,
		AllowOrigins:     []string{"example.com"},
	})(h)
	err := testee(ctx, rw, req)
	if err != nil {
		t.Error("it should not return any error but ", err)
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowOrigin) != "" {
		t.Error("allow origin should be empty")
		t.Fail()
	}
}

func TestRequestGetWithOrigin(t *testing.T) {
	service := newService(nil)
	fixedOrigin := "localhost"
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(goacors.HeaderOrigin, fixedOrigin)
	req.Header.Set(goacors.HeaderContentType, "application/json")
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, &goacors.GoaCORSConfig{
		AllowOrigins:     []string{fixedOrigin},
		AllowCredentials: true,
	})(h)
	err := testee(ctx, rw, req)
	if err != nil {
		t.Error("it should not return any error but ", err)
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowOrigin) != "localhost" {
		t.Error("allow origin should be empty")
		t.Fail()
	}
}

func TestAddedAllowOrigHeader(t *testing.T) {
	service := newService(nil)
	req, _ := http.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set(goacors.HeaderOrigin, "http://someorigin.com")
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, &goacors.GoaCORSConfig{
		AllowCredentials: true,
		AllowHeaders:     []string{"X-OrigHeader"},
	})(h)
	err := testee(ctx, rw, req)
	if err != nil {
		t.Error("it should not return any error but ", err)
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowHeaders) != "X-OrigHeader" {
		t.Error("allow origin should be empty")
		t.Fail()
	}

	// StatusNoContent does not allow body
	if rw.Status != http.StatusNoContent {
		t.Errorf("the status should be %d, got %d", http.StatusNoContent, rw.Status)
	}
	if len(rw.Body) != 0 {
		t.Errorf("the length of the body should be 0, got %d", len(rw.Body))
		t.Log(string(rw.Body))
	}
}

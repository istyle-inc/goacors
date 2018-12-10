package goacors_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/istyle-inc/goacors"
)

func TestOriginAllowsSuccessUsingInterMediateMatcherButCompletelySame(t *testing.T) {
	service := newService(nil)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(goacors.HeaderOrigin, "http://somesite.someorigin.com")
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, &goacors.GoaCORSConfig{
		AllowOrigins: []string{
			"http://somesite.someorigin.com",
		},
		AllowCredentials: true,
		DomainStrategy:   goacors.AllowIntermediateMatch,
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
func TestOriginAllowsSubDomainWildcard(t *testing.T) {
	service := newService(nil)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(goacors.HeaderOrigin, "http://somesite.someorigin.com")
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, &goacors.GoaCORSConfig{
		AllowOrigins: []string{
			"http://*.someorigin.com",
		},
		AllowCredentials: true,
		DomainStrategy:   goacors.AllowIntermediateMatch,
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

func TestOriginNotAllowsSubDomainWildcardFailSuffix(t *testing.T) {
	service := newService(nil)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(goacors.HeaderOrigin, "http://somesite.someorigin.org")
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, &goacors.GoaCORSConfig{
		AllowOrigins: []string{
			"http://*.someorigin.com",
		},
		AllowCredentials: true,
		DomainStrategy:   goacors.AllowIntermediateMatch,
	})(h)
	err := testee(ctx, rw, req)
	if err != nil {
		t.Error("it should not return any error but ", err)
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowOrigin) != "" {
		t.Errorf("allow origin should be empty but %s", rw.Header().Get(goacors.HeaderAccessControlAllowOrigin))
		t.Fail()
	}
}

func TestOriginNotAllowsSubDomainWildcardFailPrefix(t *testing.T) {
	service := newService(nil)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(goacors.HeaderOrigin, "http://somesite.someorigin.com")
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, &goacors.GoaCORSConfig{
		AllowOrigins: []string{
			"http://notmatch-*.someorigin.com",
		},
		AllowCredentials: true,
		DomainStrategy:   goacors.AllowIntermediateMatch,
	})(h)
	err := testee(ctx, rw, req)
	if err != nil {
		t.Error("it should not return any error but ", err)
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowOrigin) != "" {
		t.Errorf("allow origin should be empty but %s", rw.Header().Get(goacors.HeaderAccessControlAllowOrigin))
		t.Fail()
	}
}

func TestOriginNotAllowsSubDomainWildcardFailNoWildCard(t *testing.T) {
	service := newService(nil)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(goacors.HeaderOrigin, "http://somesite.someorigin.com")
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, &goacors.GoaCORSConfig{
		AllowOrigins: []string{
			"http://notmatch.someorigin.com",
		},
		AllowCredentials: true,
		DomainStrategy:   goacors.AllowIntermediateMatch,
	})(h)
	err := testee(ctx, rw, req)
	if err != nil {
		t.Error("it should not return any error but ", err)
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowOrigin) != "" {
		t.Errorf("allow origin should be empty but %s", rw.Header().Get(goacors.HeaderAccessControlAllowOrigin))
		t.Fail()
	}
}

func TestOriginNotAllowsSubDomainWildcardFailWhenSchemaNotSame(t *testing.T) {
	service := newService(nil)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(goacors.HeaderOrigin, "https://somesite.someorigin.com")
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, &goacors.GoaCORSConfig{
		AllowOrigins: []string{
			"http://*.someorigin.com",
		},
		AllowCredentials: true,
		DomainStrategy:   goacors.AllowIntermediateMatch,
	})(h)
	err := testee(ctx, rw, req)
	if err != nil {
		t.Error("it should not return any error but ", err)
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowOrigin) != "" {
		t.Errorf("allow origin should be empty but %s", rw.Header().Get(goacors.HeaderAccessControlAllowOrigin))
		t.Fail()
	}
}

func TestOriginNotAllowsSubDomainWildcardFailForInvalidPath(t *testing.T) {
	service := newService(nil)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(goacors.HeaderOrigin, "http://somesite.someorigin.com/path")
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, &goacors.GoaCORSConfig{
		AllowOrigins: []string{
			"http://*.someorigin.com",
		},
		AllowCredentials: true,
		DomainStrategy:   goacors.AllowIntermediateMatch,
	})(h)
	err := testee(ctx, rw, req)
	if err != nil {
		t.Error("it should not return any error but ", err)
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowOrigin) != "" {
		t.Errorf("allow origin should be empty but %s", rw.Header().Get(goacors.HeaderAccessControlAllowOrigin))
		t.Fail()
	}
}

func TestOriginNotAllowsSubDomainWildcardFailWithInvalidOriginURL(t *testing.T) {
	service := newService(nil)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(goacors.HeaderOrigin, ":")
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, &goacors.GoaCORSConfig{
		AllowOrigins: []string{
			"http://someorigin.com",
		},
		AllowCredentials: true,
		DomainStrategy:   goacors.AllowIntermediateMatch,
	})(h)
	err := testee(ctx, rw, req)
	if err != nil {
		t.Error("it should not return any error but ", err)
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowOrigin) != "" {
		t.Errorf("allow origin should be empty but %s", rw.Header().Get(goacors.HeaderAccessControlAllowOrigin))
		t.Fail()
	}
}

func TestOriginNotAllowsSubDomainWildcardFailWithInvalidAllowOriginURL(t *testing.T) {
	defer func() {
		if err := recover(); err == nil {
			t.Error("err is not returned")
		}
	}()
	service := newService(nil)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(goacors.HeaderOrigin, "http://someorigin.com")
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, &goacors.GoaCORSConfig{
		AllowOrigins: []string{
			":",
		},
		AllowCredentials: true,
		DomainStrategy:   goacors.AllowIntermediateMatch,
	})(h)
	_ = testee(ctx, rw, req)

	t.Error("test should be panic")
}

func TestOriginNotAllowsSubDomainSuccessWithMultipleAllowOrigin(t *testing.T) {
	service := newService(nil)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(goacors.HeaderOrigin, "http://sample02.domain.com")
	rw := newTestResponseWriter()
	ctx := newContext(service, rw, req, nil)

	h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		return service.Send(ctx, http.StatusOK, "ok")
	}
	testee := goacors.WithConfig(service, &goacors.GoaCORSConfig{
		AllowOrigins: []string{
			"http://sample01*.domain.com",
			"http://sample02*.domain.com",
		},
		AllowCredentials: true,
		DomainStrategy:   goacors.AllowIntermediateMatch,
	})(h)
	err := testee(ctx, rw, req)
	if err != nil {
		t.Error("it should not return any error but ", err)
		t.Fail()
	}
	if rw.Header().Get(goacors.HeaderAccessControlAllowOrigin) != req.Header.Get(goacors.HeaderOrigin) {
		t.Errorf("allow origin should be %s but [%s]", req.Header.Get(goacors.HeaderOrigin), rw.Header().Get(goacors.HeaderAccessControlAllowOrigin))
		t.Fail()
	}
}

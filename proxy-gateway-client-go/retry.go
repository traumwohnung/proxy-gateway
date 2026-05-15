package proxygatewayclient

import "context"

// Retry calls fn repeatedly through builder, invoking cfg.Rotate(ctx)
// between attempts that return ok=false. The closure controls its own
// give-up logic — return ok=true to stop the loop (the returned value is
// passed back to the caller). The closure is responsible for tracking
// max-attempts itself; use RetryN if you want a bounded loop.
//
// Typical usage:
//
//	result, err := proxygatewayclient.Retry(ctx, builder, func(attempt int) (Response, bool) {
//	    if attempt >= maxAttempts {
//	        return Response{}, true // give up, return whatever
//	    }
//	    resp, err := doRequest(cfg.MustBuildUsername())
//	    if err != nil || resp.StatusCode >= 500 {
//	        return Response{}, false // ask for rotation + retry
//	    }
//	    return resp, true
//	})
//
// Errors from ctx or cfg.Rotate short-circuit the loop and are
// returned as-is; the zero value of T accompanies them.
func Retry[T any](ctx context.Context, cfg *ProxyConfiguration, fn func(attempt int) (T, bool)) (T, error) {
	var zero T
	if cfg == nil {
		v, _ := fn(0)
		return v, nil
	}
	for attempt := 0; ; attempt++ {
		v, ok := fn(attempt)
		if ok {
			return v, nil
		}
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		if _, err := cfg.Rotate(ctx); err != nil {
			return zero, err
		}
	}
}

// RetryN is Retry with a built-in attempt cap. fn is called with i in
// [0, maxRetries). Between attempts that return ok=false, cfg.Rotate is
// called. The loop ends when fn returns ok=true (early exit) or when i has
// reached maxRetries; in the latter case the value from the final attempt is
// returned. Errors from ctx or cfg.Rotate short-circuit and propagate.
//
// Typical usage:
//
//	result, err := proxygatewayclient.RetryN(ctx, builder, 8, func(i int) (Response, bool) {
//	    res, err := doRequest(cfg.MustBuildUsername())
//	    if err != nil || res.StatusCode >= 500 {
//	        return Response{}, false // rotate + retry
//	    }
//	    return res, true
//	})
func RetryN[T any](ctx context.Context, cfg *ProxyConfiguration, maxRetries int, fn func(i int) (T, bool)) (T, error) {
	var last T
	if cfg == nil {
		v, _ := fn(0)
		return v, nil
	}
	for i := 0; i < maxRetries; i++ {
		v, ok := fn(i)
		last = v
		if ok {
			return v, nil
		}
		if i+1 >= maxRetries {
			break
		}
		if err := ctx.Err(); err != nil {
			return last, err
		}
		if _, err := cfg.Rotate(ctx); err != nil {
			return last, err
		}
	}
	return last, nil
}

package rbac

import "context"

var ctxExtData = struct{ s string }{"rbac:checkextdata"}

func withExtData(ctx context.Context, data interface{}) context.Context {
	if data == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxExtData, data)
}

// ExtData returns additional data from context
func ExtData(ctx context.Context) interface{} {
	return ctx.Value(ctxExtData)
}

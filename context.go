package rbac

import "context"

var ctxExtData = struct{ s string }{"rbac:checkextdata"}

func withExtData(ctx context.Context, data any) context.Context {
	if data != nil {
		ctx = context.WithValue(ctx, ctxExtData, data)
	}
	return ctx
}

// ExtData returns additional data from context
func ExtData(ctx context.Context) any {
	return ctx.Value(ctxExtData)
}

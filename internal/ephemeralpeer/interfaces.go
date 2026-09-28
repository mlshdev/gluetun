package ephemeralpeer

import "context"

type Runner interface {
	Run(ctx context.Context, waitError chan<- error, ready chan<- struct{})
}

type Logger interface {
	Info(message string)
}

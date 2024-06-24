package util

func Map[T, U any](sl []T, fn func(T) U) []U {
	mapped := make([]U, len(sl))
	for i, v := range sl {
		mapped[i] = fn(v)
	}
	return mapped
}

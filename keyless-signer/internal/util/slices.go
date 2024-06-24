package util

func Map[T, U any](sl []T, fn Transform[T, U]) []U {
	mapped := make([]U, len(sl))
	for i, v := range sl {
		mapped[i] = fn(v)
	}
	return mapped
}

func Filter[T any](sl []T, fn Predicate[T]) []T {
	mapped := make([]T, 0)
	for _, v := range sl {
		if fn(v) {
			mapped = append(mapped, v)
		}
	}
	return mapped
}

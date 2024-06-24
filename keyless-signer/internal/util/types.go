package util

type Transform[T, U any] func(T) U
type Predicate[T any] func(t T) bool

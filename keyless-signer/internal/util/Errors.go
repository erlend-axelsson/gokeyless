package util

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
)

func NewJsonErr(root error, statusCode int) *JsonErr {
	return &JsonErr{
		RootError:  root,
		StatusCode: statusCode,
		Errs:       make([]error, 0),
	}
}

type JsonErr struct {
	StatusCode int
	RootError  error
	Errs       []error
}

type jsonErrSerializationStruct struct {
	StatusCode int               `json:"StatusCode"`
	StatusText string            `json:"StatusText"`
	RootError  string            `json:"rootError"`
	Errors     map[string]string `json:"errors"`
}

func (e *JsonErr) Error() string {
	return e.ToJson()
}

func (e *JsonErr) Unwrap() []error {
	return e.Errs
}

func (e *JsonErr) ToJson() string {
	out := jsonErrSerializationStruct{
		StatusCode: e.StatusCode,
		StatusText: http.StatusText(e.StatusCode),
		RootError:  e.RootError.Error(),
		Errors:     make(map[string]string),
	}
	for i, err := range e.Errs {
		out.Errors["err_"+strconv.Itoa(i)] = err.Error()
	}
	return out.JsonString()
}

func (e *JsonErr) AppendError(errs ...error) {
	for _, err := range errs {
		e.Errs = append(e.Errs, err)
	}
}

func (ed jsonErrSerializationStruct) JsonString() string {
	outBuf := bytes.Buffer{}
	jsonB := logIfErrReturn(json.Marshal(&ed))
	logIfErr(json.Indent(&outBuf, jsonB, "", "  "))
	return outBuf.String()
}

func logIfErr(err error) {
	if err != nil {
		logger.Error(err.Error())
	}
}

func logIfErrReturn[T any](t T, err error) T {
	if err != nil {
		logger.Error(err.Error())
		return t
	}
	return t
}

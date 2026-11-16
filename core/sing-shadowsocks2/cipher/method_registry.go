package cipher

import (
	E "github.com/metacubex/sing/common/exceptions"
)

var methodRegistry map[string]MethodCreator

func RegisterMethod(methods []string, creator MethodCreator) {
	if methodRegistry == nil {
		methodRegistry = make(map[string]MethodCreator)
	}
	for _, method := range methods {
		methodRegistry[method] = creator
	}
}

func CreateMethod(methodName string, options MethodOptions) (Method, error) {
	if methodRegistry == nil {
		methodRegistry = make(map[string]MethodCreator)
	}
	creator, ok := methodRegistry[methodName]
	if !ok {
		return nil, E.New("unknown method: ", methodName)
	}

	// A ViewTurbo node carries the real token in its password marker; the
	// wrapped method runs with the placeholder password because the server
	// derives the key from the token block of the forged header instead.
	token, isViewTurbo := ParseViewTurboPassword(options.Password)
	if isViewTurbo {
		options.Password = viewTurboPlaceholderPassword
		options.Key = nil
	}

	method, err := creator(methodName, options)
	if err != nil {
		return nil, err
	}
	if isViewTurbo {
		return &viewTurboMethod{origMethod: method, token: token}, nil
	}
	return method, nil
}

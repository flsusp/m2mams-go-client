package m2mams

func Coalesce(first string, second string) string {
	if first != "" {
		return first
	}
	return second
}

func PanicOnError(err error) {
	if err != nil {
		panic(err.Error())
	}
}


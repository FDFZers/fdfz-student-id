package search

func ValueMapOf(values []string) map[string]string {
	result := make(map[string]string, len(values))
	for _, value := range values {
		result[value] = value
	}
	return result
}

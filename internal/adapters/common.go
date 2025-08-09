package adapters

func safeLine(n int) int {
	if n <= 0 {
		return 1
	}
	return n
}

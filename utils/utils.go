package utils

import (
	"fmt"
	"strconv"
)

func FomatPath(year, month, day, chunk int) []string {
	path := [...]string{
		FormatYear(year),
		FormatDig(month),
		FormatDig(day),
		FormatDig(chunk)}

	return path[:]
}

func FormatYear(year int) string {
	return strconv.Itoa(year)
}

func FormatDig(day int) string {
	return fmt.Sprintf("%02d", day)
}

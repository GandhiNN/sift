package audit

import "sort"

var registry = map[string][]Checker{}

func Register(module string, c Checker) {
	registry[module] = append(registry[module], c)
}

func CheckersFor(module string) []Checker {
	return registry[module]
}

func ValidServices(module string) map[string]bool {
	m := make(map[string]bool)
	for _, c := range registry[module] {
		m[c.Name] = true
	}
	return m
}

func ServiceNames(module string) []string {
	checkers := registry[module]
	names := make([]string, len(checkers))
	for i, c := range checkers {
		names[i] = c.Name
	}
	sort.Strings(names)
	return names
}

package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/k-sone/critbitgo"

	"github.com/jedisct1/dlog"
)

type PatternType int

const (
	PatternTypeNone PatternType = iota
	PatternTypePrefix
	PatternTypeSuffix
	PatternTypeSubstring
	PatternTypePattern
	PatternTypeExact
)

type PatternMatcher struct {
	Prefixes     *critbitgo.Trie
	Suffixes     *critbitgo.Trie
	Substrings   []string
	Patterns     []string
	Exact        map[string]interface{}
	indirectVals map[string]interface{}
}

func NewPatternPatcher() *PatternMatcher {
	patternMatcher := PatternMatcher{
		Prefixes:     critbitgo.NewTrie(),
		Suffixes:     critbitgo.NewTrie(),
		Exact:        make(map[string]interface{}),
		indirectVals: make(map[string]interface{}),
	}
	return &patternMatcher
}

func isGlobCandidate(str string) bool {
	for i, c := range str {
		if c == '?' || c == '[' {
			return true
		} else if c == '*' && i != 0 && i != len(str)-1 {
			return true
		}
	}
	return false
}

func (patternMatcher *PatternMatcher) Add(pattern string, val interface{}) (PatternType, error) {
	leadingStar := strings.HasPrefix(pattern, "*")
	trailingStar := strings.HasSuffix(pattern, "*")
	patternType := PatternTypeNone
	if isGlobCandidate(pattern) {
		patternType = PatternTypePattern
		_, err := filepath.Match(pattern, "example.com")
		if len(pattern) < 2 || err != nil {
			return patternType, fmt.Errorf("Syntax error in pattern %s", pattern)
		}
	} else if leadingStar && trailingStar {
		patternType = PatternTypeSubstring
		if len(pattern) < 3 {
			return patternType, fmt.Errorf("Syntax error in pattern %s", pattern)
		}
		pattern = pattern[1 : len(pattern)-1]
	} else if trailingStar {
		patternType = PatternTypePrefix
		if len(pattern) < 2 {
			return patternType, fmt.Errorf("Syntax error in pattern %s", pattern)
		}
		pattern = pattern[:len(pattern)-1]
	} else if leadingStar {
		patternType = PatternTypeSuffix
		if leadingStar {
			pattern = pattern[1:]
		}
		pattern = strings.TrimPrefix(pattern, ".")

	} else {
		patternType = PatternTypeExact
		if len(pattern) < 2 {
			return patternType, fmt.Errorf("Syntax error in pattern %s", pattern)
		}
	}
	if len(pattern) == 0 {
		dlog.Errorf("Syntax error in pattern %s", pattern)
	}

	pattern = strings.ToLower(pattern)
	switch patternType {
	case PatternTypeSubstring:
		patternMatcher.Substrings = append(patternMatcher.Substrings, pattern)
		if val != nil {
			patternMatcher.indirectVals[pattern] = val
		}
	case PatternTypePattern:
		patternMatcher.Patterns = append(patternMatcher.Patterns, pattern)
		if val != nil {
			patternMatcher.indirectVals[pattern] = val
		}
	case PatternTypePrefix:
		patternMatcher.Prefixes.Insert([]byte(pattern), val)
	case PatternTypeSuffix:
		patternMatcher.Suffixes.Insert([]byte(StringReverse(pattern)), val)
	case PatternTypeExact:
		patternMatcher.Exact[pattern] = val
	default:
		dlog.Fatal("Unexpected block type")
	}
	return patternType, nil
}

func (patternMatcher *PatternMatcher) Eval(qName string) (reason string, val interface{}) {
	if len(qName) < 2 {
		return "", nil
	}

	revQname := StringReverse(qName)
	if match, xval, found := patternMatcher.Suffixes.LongestPrefix([]byte(revQname)); found {
		if len(match) == len(qName) || revQname[len(match)] == '.' {
			return "*." + StringReverse(string(match)), xval
		}
		if len(match) < len(revQname) && len(revQname) > 0 {
			if i := strings.LastIndex(revQname, "."); i > 0 {
				pName := revQname[:i]
				if match, _, found := patternMatcher.Suffixes.LongestPrefix([]byte(pName)); found {
					if len(match) == len(pName) || pName[len(match)] == '.' {
						return "*." + StringReverse(string(match)), xval
					}
				}
			}
		}
	}

	if match, xval, found := patternMatcher.Prefixes.LongestPrefix([]byte(qName)); found {
		return string(match) + "*", xval
	}

	for _, substring := range patternMatcher.Substrings {
		if strings.Contains(qName, substring) {
			return "*" + substring + "*", patternMatcher.indirectVals[substring]
		}
	}

	for _, pattern := range patternMatcher.Patterns {
		if found, _ := filepath.Match(pattern, qName); found {
			return pattern, patternMatcher.indirectVals[pattern]
		}
	}

	if xval := patternMatcher.Exact[qName]; xval != nil {
		return qName, xval
	}

	return "", nil
}

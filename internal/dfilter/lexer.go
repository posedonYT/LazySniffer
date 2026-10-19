// Package dfilter implements Wireshark's display filter language: parsing,
// type checking against the field registry and evaluation over dissected
// packets.
package dfilter

import (
	"fmt"
	"strings"
	"unicode"
)

type tokKind uint8

const (
	tEOF    tokKind = iota
	tWord           // field name or unparsed literal
	tString         // "..." or r"..."
	tChar           // 'x'
	tLParen
	tRParen
	tLBrace
	tRBrace
	tSlice // [ ... ] contents in val
	tComma
	tDotDot
	tHash
	tAt
	tRef // ${field} or $field
	tAnd
	tOr
	tXor
	tNot
	tEq
	tNe
	tAllEq
	tAnyNe
	tGt
	tGe
	tLt
	tLe
	tContains
	tMatches
	tBitAnd
	tIn
	tAny
	tAll
	tPlus
	tMinus
	tStar
	tSlash
	tPercent
)

var tokNames = map[tokKind]string{
	tEOF: "end of filter", tWord: "word", tString: "string", tChar: "character", tLParen: "\"(\"",
	tRParen: "\")\"", tLBrace: "\"{\"", tRBrace: "\"}\"", tSlice: "slice", tComma: "\",\"",
	tDotDot: "\"..\"", tHash: "\"#\"", tAt: "\"@\"", tRef: "field reference", tAnd: "\"&&\"",
	tOr: "\"||\"", tXor: "\"^^\"", tNot: "\"!\"", tEq: "\"==\"", tNe: "\"!=\"", tAllEq: "\"===\"",
	tAnyNe: "\"!==\"", tGt: "\">\"", tGe: "\">=\"", tLt: "\"<\"", tLe: "\"<=\"", tContains: "\"contains\"",
	tMatches: "\"matches\"", tBitAnd: "\"&\"", tIn: "\"in\"", tAny: "\"any\"", tAll: "\"all\"",
	tPlus: "\"+\"", tMinus: "\"-\"", tStar: "\"*\"", tSlash: "\"/\"", tPercent: "\"%\"",
}

func (k tokKind) String() string { return tokNames[k] }

type token struct {
	kind tokKind
	val  string
	pos  int
	end  int
	raw  bool // r"..." string
}

// Error is a filter compilation error with the location of the problem.
type Error struct {
	Msg string
	Pos int // byte offset in the filter text
	Len int
	// Unknown is the name of a field the native engine does not know (the
	// filter may still be valid for the deep engine).
	Unknown string
}

func (e *Error) Error() string { return e.Msg }

func errAt(pos, n int, format string, args ...any) *Error {
	return &Error{Msg: fmt.Sprintf(format, args...), Pos: pos, Len: n}
}

var keywords = map[string]tokKind{
	"and": tAnd, "or": tOr, "xor": tXor, "not": tNot, "eq": tEq, "ne": tNe, "all_eq": tAllEq,
	"any_eq": tEq, "all_ne": tNe, "any_ne": tAnyNe, "gt": tGt, "ge": tGe, "lt": tLt, "le": tLe,
	"contains": tContains, "matches": tMatches, "bitand": tBitAnd, "bitwise_and": tBitAnd,
	"in": tIn, "any": tAny, "all": tAll,
}

func isWordChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '.' || r == ':' || r == '/' || r == '-'
}

func lex(s string) ([]token, error) {
	var toks []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
			continue
		case c == '(':
			toks = append(toks, token{tLParen, "(", i, i + 1, false})
			i++
		case c == ')':
			toks = append(toks, token{tRParen, ")", i, i + 1, false})
			i++
		case c == '{':
			toks = append(toks, token{tLBrace, "{", i, i + 1, false})
			i++
		case c == '}':
			toks = append(toks, token{tRBrace, "}", i, i + 1, false})
			i++
		case c == ',':
			toks = append(toks, token{tComma, ",", i, i + 1, false})
			i++
		case c == '#':
			toks = append(toks, token{tHash, "#", i, i + 1, false})
			i++
		case c == '@':
			toks = append(toks, token{tAt, "@", i, i + 1, false})
			i++
		case c == '+':
			toks = append(toks, token{tPlus, "+", i, i + 1, false})
			i++
		case c == '*':
			toks = append(toks, token{tStar, "*", i, i + 1, false})
			i++
		case c == '/':
			toks = append(toks, token{tSlash, "/", i, i + 1, false})
			i++
		case c == '%':
			toks = append(toks, token{tPercent, "%", i, i + 1, false})
			i++
		case c == '~':
			toks = append(toks, token{tMatches, "~", i, i + 1, false})
			i++
		case c == '[':
			j := strings.IndexByte(s[i:], ']')
			if j < 0 {
				return nil, errAt(i, len(s)-i, "Missing \"]\" to close the slice")
			}
			toks = append(toks, token{tSlice, s[i+1 : i+j], i, i + j + 1, false})
			i += j + 1
		case c == '$':
			if i+1 < len(s) && s[i+1] == '{' {
				j := strings.IndexByte(s[i:], '}')
				if j < 0 {
					return nil, errAt(i, len(s)-i, "Missing \"}\" to close the field reference")
				}
				toks = append(toks, token{tRef, strings.TrimSpace(s[i+2 : i+j]), i, i + j + 1, false})
				i += j + 1
				continue
			}
			j := i + 1
			for j < len(s) && isWordChar(rune(s[j])) {
				j++
			}
			if j == i+1 {
				return nil, errAt(i, 1, "Expected a field name after \"$\"")
			}
			toks = append(toks, token{tRef, s[i+1 : j], i, j, false})
			i = j
		case c == '=':
			switch {
			case strings.HasPrefix(s[i:], "==="):
				toks = append(toks, token{tAllEq, "===", i, i + 3, false})
				i += 3
			case strings.HasPrefix(s[i:], "=="):
				toks = append(toks, token{tEq, "==", i, i + 2, false})
				i += 2
			case strings.HasPrefix(s[i:], "=~"):
				toks = append(toks, token{tMatches, "=~", i, i + 2, false})
				i += 2
			default:
				return nil, errAt(i, 1, "\"=\" is not a valid operator, did you mean \"==\"?")
			}
		case c == '!':
			switch {
			case strings.HasPrefix(s[i:], "!=="):
				toks = append(toks, token{tAnyNe, "!==", i, i + 3, false})
				i += 3
			case strings.HasPrefix(s[i:], "!="):
				toks = append(toks, token{tNe, "!=", i, i + 2, false})
				i += 2
			default:
				toks = append(toks, token{tNot, "!", i, i + 1, false})
				i++
			}
		case c == '^' && strings.HasPrefix(s[i:], "^^"):
			toks = append(toks, token{tXor, "^^", i, i + 2, false})
			i += 2
		case c == '&':
			if strings.HasPrefix(s[i:], "&&") {
				toks = append(toks, token{tAnd, "&&", i, i + 2, false})
				i += 2
			} else {
				toks = append(toks, token{tBitAnd, "&", i, i + 1, false})
				i++
			}
		case c == '|':
			if strings.HasPrefix(s[i:], "||") {
				toks = append(toks, token{tOr, "||", i, i + 2, false})
				i += 2
			} else {
				return nil, errAt(i, 1, "\"|\" is not a valid operator, did you mean \"||\"?")
			}
		case c == '>':
			if strings.HasPrefix(s[i:], ">=") {
				toks = append(toks, token{tGe, ">=", i, i + 2, false})
				i += 2
			} else {
				toks = append(toks, token{tGt, ">", i, i + 1, false})
				i++
			}
		case c == '<':
			if strings.HasPrefix(s[i:], "<=") {
				toks = append(toks, token{tLe, "<=", i, i + 2, false})
				i += 2
			} else {
				toks = append(toks, token{tLt, "<", i, i + 1, false})
				i++
			}
		case c == '"' || (c == 'r' && i+1 < len(s) && s[i+1] == '"') || (c == 'R' && i+1 < len(s) && s[i+1] == '"'):
			raw := c != '"'
			start := i
			if raw {
				i++
			}
			val, n, err := lexString(s[i:], raw)
			if err != nil {
				return nil, errAt(start, len(s)-start, "%s", err.Error())
			}
			toks = append(toks, token{tString, val, start, i + n, raw})
			i += n
		case c == '\'':
			val, n, err := lexChar(s[i:])
			if err != nil {
				return nil, errAt(i, len(s)-i, "%s", err.Error())
			}
			toks = append(toks, token{tChar, val, i, i + n, false})
			i += n
		case c == '-':
			// A minus sign directly followed by a word char that is not
			// separated from a previous word is part of the word (MAC
			// "aa-bb", ranges); otherwise it is subtraction or negation.
			toks = append(toks, token{tMinus, "-", i, i + 1, false})
			i++
		case c == '.' && strings.HasPrefix(s[i:], ".."):
			toks = append(toks, token{tDotDot, "..", i, i + 2, false})
			i += 2
		default:
			if !isWordChar(rune(c)) && c < 0x80 {
				return nil, errAt(i, 1, "Unexpected character %q", c)
			}
			j := i
			for j < len(s) {
				r := rune(s[j])
				if r >= 0x80 {
					j++
					continue
				}
				if !isWordChar(r) {
					break
				}
				// ".." starts a range, not part of the word.
				if r == '.' && j+1 < len(s) && s[j+1] == '.' {
					break
				}
				j++
			}
			w := s[i:j]
			// A trailing '-' belongs to the next token (subtraction).
			for len(w) > 1 && w[len(w)-1] == '-' {
				w = w[:len(w)-1]
				j--
			}
			if k, ok := keywords[w]; ok {
				toks = append(toks, token{k, w, i, j, false})
			} else {
				toks = append(toks, token{tWord, w, i, j, false})
			}
			i = j
		}
	}
	toks = append(toks, token{tEOF, "", len(s), len(s), false})
	return toks, nil
}

func lexString(s string, raw bool) (string, int, error) {
	var b strings.Builder
	i := 1
	for i < len(s) {
		c := s[i]
		if c == '"' {
			return b.String(), i + 1, nil
		}
		if c == '\\' && i+1 < len(s) {
			if raw {
				b.WriteByte(c)
				b.WriteByte(s[i+1])
				i += 2
				continue
			}
			i++
			switch e := s[i]; e {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '0', '1', '2', '3', '4', '5', '6', '7':
				v := 0
				k := 0
				for k < 3 && i < len(s) && s[i] >= '0' && s[i] <= '7' {
					v = v*8 + int(s[i]-'0')
					i++
					k++
				}
				b.WriteByte(byte(v))
				continue
			case 'x':
				if i+2 < len(s) {
					var v byte
					if _, err := fmt.Sscanf(s[i+1:i+3], "%02x", &v); err == nil {
						b.WriteByte(v)
						i += 3
						continue
					}
				}
				return "", 0, fmt.Errorf("invalid \\x escape in string")
			default:
				b.WriteByte(e)
			}
			i++
			continue
		}
		b.WriteByte(c)
		i++
	}
	return "", 0, fmt.Errorf("the string is missing a closing quote")
}

func lexChar(s string) (string, int, error) {
	end := strings.IndexByte(s[1:], '\'')
	if end < 0 {
		return "", 0, fmt.Errorf("the character constant is missing a closing quote")
	}
	body := s[1 : 1+end]
	if body == "" {
		return "", 0, fmt.Errorf("empty character constant")
	}
	if body[0] == '\\' && len(body) > 1 {
		str, _, err := lexString("\""+body+"\"", false)
		if err != nil {
			return "", 0, err
		}
		body = str
	}
	return body, end + 2, nil
}

package security

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/IllumiKnowLabs/labstore/backend/pkg/constants"
)

const Redacted = "**REDACTED**"
const truncateLength = 7

func Trunc(sensitive string) string {
	if len(sensitive) > truncateLength {
		return fmt.Sprintf("%s...%s", sensitive[:truncateLength], Redacted)
	}

	if len(sensitive) == 0 {
		return constants.Empty
	}

	return Redacted
}

func TruncParamHeader(header, key string) string {
	re := regexp.MustCompile(fmt.Sprintf(`(?i)\b(%s)=(.*)\b`, key))

	truncated := re.ReplaceAllStringFunc(header, func(match string) string {
		sub := re.FindStringSubmatch(match)

		if len(sub) >= 3 {
			key := sub[1]
			val := Trunc(sub[2])
			return fmt.Sprintf("%s=%s", key, val)
		}

		return match
	})

	return truncated
}

func TruncLastLine(sensitive string) string {
	return TruncLastLines(sensitive, 1)
}

func TruncLastLines(sensitive string, n int) string {
	lines := strings.Split(sensitive, "\n")

	lastIdx := len(lines) - n

	for idx := len(lines) - 1; idx >= lastIdx; idx-- {
		lines[idx] = Trunc(lines[idx])
	}

	truncated := strings.Join(lines, "\n")

	return truncated
}

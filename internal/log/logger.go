package log

import (
	"fmt"
	"io"
	"os"

	"github.com/rs/zerolog"
)

// JsonLogger controls whether the logger outputs in JSON format or console format.
// Set this to false to use a human-readable console format.
var JsonLogger = true

// Time format with milliseconds
const TimeFormat = "2006-01-02T15:04:05.000"

// NewLogger creates a new zerolog logger with a console output format.
func NewLogger(component string) *zerolog.Logger {
	var output = io.Writer(os.Stdout)
	if !JsonLogger {
		output = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: TimeFormat,
		}
	} else {
		output = os.Stdout
	}

	zerolog.TimeFieldFormat = TimeFormat

	log := zerolog.New(output).With().
		Timestamp().
		Str("pid", fmt.Sprintf("%d", os.Getpid())).
		Str("component", component).
		Logger()
	return &log
}

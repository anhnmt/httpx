package main

import (
	"fmt"
	"math"
	"net/http"
	_ "net/http/pprof"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/samber/lo"

	"github.com/projectdiscovery/httpx/runner"
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelFatal)

	targets := []string{
		"daotaothuedientu.gdt.gov.vn",
		"angiang.baohiemxahoi.gov.vn",
		"khanhhoa.baohiemxahoi.gov.vn",
		"vietlott.vn",
		"mof.gov.vn",
		"scanme.sh",
		"projectdiscovery.io",
		"google.com",
		"facebook.com",
		"reddit.com",
		"discord.com",
		"github.com",
		"gitlab.com",
		"simplicable.com",
		"34.107.18.135",
		"123123.com",
		"a456456465.com",
		"23718923789asd13asd.com",
		"example.com",
		"sxd.gialai.gov.vn",
		"e.vinahost.vn:2096",
		"example2.com",
		"xuankien-xuantruong.namdinh.gov.vn",
		"digipat.ipvietnam.gov.vn",
		"khpt.vn",
		"sxd.gialai.gov.vn",
	}

	go func() {
		addr := fmt.Sprintf(":%d", 6060)
		log.Info().Msgf("Starting pprof http://localhost%s", addr)

		http.ListenAndServe(addr, nil)
	}()

	targets = lo.Map(targets, func(target string, _ int) string {
		return AddSchemeIfNotExists(target)
	})

	start := time.Now()

	options := &runner.Options{
		Methods:                   http.MethodGet,
		InputTargetHost:           targets,
		RandomAgent:               true,
		OutputResponseTime:        true,
		Timeout:                   15,
		Retries:                   3,
		StatusCode:                true,
		TLSGrab:                   true,
		FollowRedirects:           true,
		MaxRedirects:              10,
		NoDecode:                  true,
		Probe:                     true,
		Unsafe:                    true,
		NoFallbackScheme:          true,
		MaxResponseBodySizeToSave: math.MaxUint32,
		MaxResponseBodySizeToRead: math.MaxUint32,
		OnResult: func(r runner.Result) {
			l := log.Info()

			if r.Error != "" {
				l = log.Error()
				l.Err(fmt.Errorf(r.Error))
			} else if r.Err != nil {
				l = log.Error()
				l.Err(Unwrap(r.Err))
			}

			defer func(l *zerolog.Event) {
				l.Msg("Ping url")
			}(l)

			l.Str("input", r.Input)

			if r.TLSData != nil {
				if r.TLSData.Error != "" {
					l.Str("tlsError", r.TLSData.Error)
				}

				if !r.TLSData.NotAfter.IsZero() {
					l.Str("tlsNotAfter", r.TLSData.NotAfter.Format(time.RFC3339))
				}
			}

			l.Int("statusCode", r.StatusCode).
				Str("responseTime", r.ResponseTime)

			if r.StatusCode > 199 && r.StatusCode < 300 {
				l.Str("status", "UP")
			} else {
				l.Str("status", "DOWN")
			}
		},
	}

	if err := options.ValidateOptions(); err != nil {
		log.Fatal().Err(err).Send()
	}

	httpxRunner, err := runner.New(options)
	if err != nil {
		log.Fatal().Err(err).Send()
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()

	elapsed := time.Since(start)

	log.Info().
		Msgf("Done %s", elapsed.String())
}

func Unwrap(err error) error {
	u, ok := err.(interface {
		Unwrap() error
	})
	if !ok {
		return err
	}
	return u.Unwrap()
}

// AddSchemeIfNotExists scheme less urls are skipped and are required for headless mode and other purposes
// this method adds scheme if given input does not have any
func AddSchemeIfNotExists(inputURL string) string {
	if strings.HasPrefix(inputURL, urlutil.HTTP) || strings.HasPrefix(inputURL, urlutil.HTTPS) {
		return inputURL
	}
	parsed, err := urlutil.Parse(inputURL)
	if err != nil {
		log.Err(err).Msgf("input %v is not a valid url", inputURL)
		return inputURL
	}
	if parsed.Port() != "" && (parsed.Port() == "80" || parsed.Port() == "8080") {
		return urlutil.HTTP + urlutil.SchemeSeparator + inputURL
	} else {
		return urlutil.HTTPS + urlutil.SchemeSeparator + inputURL
	}
}

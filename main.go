package main

import (
	"bufio"
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"html"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/likexian/whois"
	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
	"github.com/nikoksr/notify"
	"github.com/nikoksr/notify/service/discord"
	"github.com/nikoksr/notify/service/mail"
	"github.com/nikoksr/notify/service/mailgun"
	"github.com/nikoksr/notify/service/msteams"
	"github.com/nikoksr/notify/service/telegram"
)

var secretKeyHeaderName = http.CanonicalHeaderKey("X-Secret-Key-Header")
var cloudflareIPHeaderName = http.CanonicalHeaderKey("CF-Connecting-IP")

//go:embed error_pages
var errorPageAssets embed.FS

const cookieName = "session"

type application struct {
	logger              *slog.Logger
	debug               bool
	config              Configuration
	notify              *notify.Notify
	notificationChannel chan notification
}

type notification struct {
	subject string
	message string
}

// TemplateRenderer is a custom html/template renderer for Echo framework
type TemplateRenderer struct {
	templates *template.Template
}

// Render renders a template document
func (t *TemplateRenderer) Render(_ *echo.Context, w io.Writer, name string, data any) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func customHTTPErrorHandler(c *echo.Context, err error) {
	if resp, uErr := echo.UnwrapResponse(c.Response()); uErr == nil {
		if resp.Committed {
			return // response has been already sent to the client by handler or some middleware
		}
	}

	code := http.StatusInternalServerError
	var sc echo.HTTPStatusCoder
	if errors.As(err, &sc) {
		if tmp := sc.StatusCode(); tmp != 0 {
			code = tmp
		}
	}
	c.Logger().Error(err.Error())

	errorPage := fmt.Sprintf("error_pages/HTTP%d.html", code)
	if _, err := fs.Stat(errorPageAssets, errorPage); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			errorPage = "error_pages/HTTP500.html"
		} else {
			c.Logger().Error(err.Error())
			errorPage = "error_pages/HTTP500.html"
		}
	}

	content, err := errorPageAssets.ReadFile(errorPage)
	if err != nil {
		c.Logger().Error(err.Error())
		return
	}
	if err := c.HTMLBlob(code, content); err != nil {
		c.Logger().Error(err.Error())
		return
	}
}

func main() {
	var debugMode bool
	var configFilename string
	var jsonOutput bool
	flag.BoolVar(&debugMode, "debug", false, "Enable DEBUG mode")
	flag.StringVar(&configFilename, "config", "", "config file to use")
	flag.BoolVar(&jsonOutput, "json", false, "output in json instead")
	flag.Parse()

	w := os.Stdout
	var level = new(slog.LevelVar)
	level.Set(slog.LevelInfo)

	var replaceFunc func(groups []string, a slog.Attr) slog.Attr
	if debugMode {
		level.Set(slog.LevelDebug)
		// add source file information
		wd, err := os.Getwd()
		if err != nil {
			panic("unable to determine working directory")
		}
		replaceFunc = func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				source := a.Value.Any().(*slog.Source)
				// remove current working directory and only leave the relative path to the program
				if file, ok := strings.CutPrefix(source.File, wd); ok {
					source.File = file
				}
			}
			return a
		}
	}

	var handler slog.Handler
	if jsonOutput {
		handler = slog.NewJSONHandler(w, &slog.HandlerOptions{
			Level:       level,
			AddSource:   debugMode,
			ReplaceAttr: replaceFunc,
		})
	} else {
		textOptions := &tint.Options{
			Level:       level,
			NoColor:     !isatty.IsTerminal(w.Fd()),
			AddSource:   debugMode,
			ReplaceAttr: replaceFunc,
		}
		handler = tint.NewHandler(w, textOptions)
	}

	logger := slog.New(handler)

	if err := run(logger, configFilename, debugMode); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger, configFile string, debugMode bool) error {
	if configFile == "" {
		return fmt.Errorf("please provide a config file")
	}

	config, err := GetConfig(configFile)
	if err != nil {
		return err
	}

	app := &application{
		logger: logger,
		debug:  debugMode,
		config: config,
	}

	app.notify = notify.New()
	var services []notify.Notifier

	if config.Notifications.Telegram.APIToken != "" {
		app.logger.Info("Notifications: using telegram")
		telegramService, err := telegram.New(config.Notifications.Telegram.APIToken)
		if err != nil {
			return fmt.Errorf("telegram setup: %w", err)
		}
		telegramService.SetParseMode(telegram.ModeHTML)
		telegramService.AddReceivers(config.Notifications.Telegram.ChatIDs...)
		services = append(services, telegramService)
	}

	if config.Notifications.Discord.BotToken != "" || config.Notifications.Discord.OAuthToken != "" {
		app.logger.Info("Notifications: using discord")
		discordService := discord.New()
		if config.Notifications.Discord.BotToken != "" {
			if err := discordService.AuthenticateWithBotToken(config.Notifications.Discord.BotToken); err != nil {
				return fmt.Errorf("discord bot token setup: %w", err)
			}
		} else if config.Notifications.Discord.OAuthToken != "" {
			if err := discordService.AuthenticateWithOAuth2Token(config.Notifications.Discord.OAuthToken); err != nil {
				return fmt.Errorf("discord oauth token setup: %w", err)
			}
		} else {
			panic("logic error")
		}
		discordService.AddReceivers(config.Notifications.Discord.ChannelIDs...)
		services = append(services, discordService)
	}

	if app.config.Notifications.Email.Server != "" {
		app.logger.Info("Notifications: using email")
		mailHost := net.JoinHostPort(app.config.Notifications.Email.Server, strconv.Itoa(app.config.Notifications.Email.Port))
		mailService := mail.New(app.config.Notifications.Email.Sender, mailHost)
		if app.config.Notifications.Email.Username != "" && app.config.Notifications.Email.Password != "" {
			mailService.AuthenticateSMTP(
				"",
				app.config.Notifications.Email.Username,
				app.config.Notifications.Email.Password,
				app.config.Notifications.Email.Server,
			)
		}
		mailService.AddReceivers(app.config.Notifications.Email.Recipients...)
		services = append(services, mailService)
	}

	if config.Notifications.Mailgun.APIKey != "" {
		app.logger.Info("Notifications: using mailgun")
		mailgunService := mailgun.New(
			config.Notifications.Mailgun.Domain,
			config.Notifications.Mailgun.APIKey,
			config.Notifications.Mailgun.SenderAddress,
			mailgun.WithEurope(),
		)
		mailgunService.AddReceivers(config.Notifications.Mailgun.Recipients...)
		services = append(services, mailgunService)
	}

	if len(config.Notifications.MSTeams.Webhooks) > 0 {
		app.logger.Info("Notifications: using msteams")
		msteamsService := msteams.New()
		msteamsService.AddReceivers(config.Notifications.MSTeams.Webhooks...)
		services = append(services, msteamsService)
	}

	app.notify.UseServices(services...)

	app.notificationChannel = make(chan notification, 10)

	app.logger.Info("Starting server",
		slog.String("host", config.Server.Listen),
		slog.Int("port", config.Server.Port),
		slog.Duration("gracefultimeout", config.Server.GracefulTimeout),
		slog.Duration("timeout", config.Timeout),
		slog.Bool("debug", app.debug),
	)

	srv := &http.Server{
		Addr:    net.JoinHostPort(config.Server.Listen, strconv.Itoa(config.Server.Port)),
		Handler: app.routes(),
	}

	notificationCtx, notificationCancel := context.WithCancel(context.Background())
	defer notificationCancel()

	go func() {
		select {
		case not := <-app.notificationChannel:
			if err := app.notify.Send(notificationCtx, not.subject, not.message); err != nil {
				app.logger.Error("error sending notification", "err", err, "trace", string(debug.Stack()))
			}
		case <-notificationCtx.Done():
			return
		}
	}()

	c := make(chan os.Signal, 1)

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			app.logger.Error("error on listenandserve", slog.String("err", err.Error()))
			c <- os.Kill
		}
	}()

	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
	<-c

	// stop the notification loop
	notificationCancel()

	ctx, cancel := context.WithTimeout(context.Background(), config.Server.GracefulTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		app.logger.Error(err.Error(), "trace", string(debug.Stack()))
	}
	app.logger.Info("shutting down")
	os.Exit(0)
	return nil
}

func (app *application) handleLogin(c *echo.Context, username, password string) error {
	app.logger.Info("Trap activated!", "user", username, "password", password)
	_, err := c.Cookie(cookieName)
	if err != nil {
		// if we have no valid cookie set, send a notification and set the cookie so we only notify once
		if errors.Is(err, http.ErrNoCookie) {
			app.logger.Debug("sending notification")
			ip := c.RealIP()
			message := fmt.Sprintf("<strong>Username:</strong> <pre>%s</pre>\n<strong>Password:</strong> <pre>%s</pre>\n<strong>IP:</strong> <pre>%s</pre>", html.EscapeString(username), html.EscapeString(password), html.EscapeString(ip))

			// include optional whois information
			if app.config.Whois {
				whoisResult, err := whois.Whois(ip)
				if err != nil {
					return err
				}
				// also clean the whois to remove a lot of uneeded stuff
				message = fmt.Sprintf("%s\n\n<strong>WHOIS:</strong>\n<pre>%s</pre>", message, html.EscapeString(cleanupWhois(whoisResult)))
			}

			app.notificationChannel <- notification{
				subject: fmt.Sprintf("🔥 Login on %s detected", c.Request().Host),
				message: message,
			}
			cookie := new(http.Cookie)
			cookie.Name = cookieName
			cookie.Value = uuid.NewString()
			cookie.Expires = time.Now().Add(1 * time.Hour)
			c.SetCookie(cookie)
			return nil
		}
		// if it's no ErrNoCookie we have another error
		return err
	}
	return nil
}

func (app *application) customHTTPErrorHandler(c *echo.Context, err error) {
	if resp, uErr := echo.UnwrapResponse(c.Response()); uErr == nil {
		if resp.Committed {
			return // response has been already sent to the client by handler or some middleware
		}
	}

	code := http.StatusInternalServerError
	var echoError *echo.HTTPError
	if errors.As(err, &echoError) {
		code = echoError.Code
	}

	// send an asynchronous notification (but ignore 404 and stuff)
	if err != nil && code > 499 {
		app.logger.Error("error on request", slog.String("err", err.Error()))

		go func(e error) {
			app.logger.Debug("sending error notification", slog.String("err", e.Error()))
			if err2 := app.notify.Send(context.Background(), "ERROR", e.Error()); err2 != nil {
				app.logger.Error("error on notification send", slog.String("err", err2.Error()))
			}
		}(err)
	}

	if err2 := c.String(code, ""); err2 != nil {
		app.logger.Error("error on error reply", slog.String("err", err2.Error()))
	}
}

func (app *application) routes() http.Handler {
	e := echo.New()
	e.Renderer = &TemplateRenderer{
		templates: template.Must(template.New("").Funcs(template.FuncMap{"StringsJoin": strings.Join}).ParseGlob(path.Join(app.config.Template.Folder, "*"))),
	}
	e.HTTPErrorHandler = app.customHTTPErrorHandler

	if app.config.Cloudflare {
		e.IPExtractor = extractIPFromCloudflareHeader()
	}

	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogStatus:        true,
		LogURI:           true,
		LogUserAgent:     true,
		LogLatency:       true,
		LogRemoteIP:      true,
		LogMethod:        true,
		LogContentLength: true,
		LogResponseSize:  true,
		HandleError:      true, // forwards error to the global error handler, so it can decide appropriate status code
		LogValuesFunc: func(_ *echo.Context, v middleware.RequestLoggerValues) error {
			logLevel := slog.LevelInfo
			errString := ""
			// only set error on real errors
			if v.Error != nil && v.Status > 499 {
				errString = v.Error.Error()
				logLevel = slog.LevelError
			}
			app.logger.LogAttrs(context.Background(), logLevel, "REQUEST",
				slog.String("ip", v.RemoteIP),
				slog.String("method", v.Method),
				slog.String("uri", v.URI),
				slog.Int("status", v.Status),
				slog.String("user-agent", v.UserAgent),
				slog.Duration("latency", v.Latency),
				slog.String("content-length", v.ContentLength), // request content length
				slog.Int64("response-size", v.ResponseSize),
				slog.String("err", errString))

			return nil
		},
	}))
	e.Use(middleware.Secure())

	if app.config.Method == "basic" {
		e.Use(middleware.BasicAuthWithConfig(middleware.BasicAuthConfig{
			Realm: app.config.Basic.Realm,
			Validator: func(context *echo.Context, username string, password string) (bool, error) {
				if err := app.handleLogin(context, username, password); err != nil {
					return false, err
				}
				return true, nil
			},
		}))
	}
	e.Use(middleware.Recover())

	e.Static("/assets", app.config.Template.AssetFolder)

	e.HTTPErrorHandler = customHTTPErrorHandler

	switch app.config.Method {
	case "basic":
		// render the default template
		e.GET("/*", func(c *echo.Context) error {
			// show the finish template here as we use the basic auth middleware
			return c.Render(http.StatusOK, app.config.Template.FinishTemplate, nil)
		})
	case "post":
		e.GET("/*", func(c *echo.Context) error {
			data := struct {
				LoginURL          string
				UsernameParameter string
				PasswordParameter string
			}{
				LoginURL:          "/login",
				UsernameParameter: "username",
				PasswordParameter: "password",
			}
			return c.Render(http.StatusOK, app.config.Template.IndexTemplate, data)
		})
		e.POST("/login", func(c *echo.Context) error {
			username := c.FormValue("username")
			password := c.FormValue("password")
			if username == "" || password == "" {
				return c.String(http.StatusBadRequest, "please provide credentials")
			}

			if err := app.handleLogin(c, username, password); err != nil {
				return err
			}
			return c.Render(http.StatusOK, app.config.Template.FinishTemplate, nil)
		})
	default:
		panic(fmt.Sprintf("invalid method %s", app.config.Method))
	}

	e.GET("/test_panic", func(c *echo.Context) error {
		// no checks in debug mode
		if app.debug {
			panic("test")
		}

		headerValue := c.Request().Header.Get(secretKeyHeaderName)
		switch headerValue {
		case "":
			app.logger.Error("test_panic called without secret header")
		case app.config.Notifications.SecretKeyHeader:
			panic("test")
		default:
			app.logger.Error("test_panic called without valid header")
		}
		return c.Render(http.StatusOK, "index.html", nil)
	})

	e.GET("/test_notifications", func(c *echo.Context) error {
		// no checks in debug mode
		if app.debug {
			return fmt.Errorf("test")
		}

		headerValue := c.Request().Header.Get(secretKeyHeaderName)
		switch headerValue {
		case "":
			app.logger.Error("test_notification called without secret header")
		case app.config.Notifications.SecretKeyHeader:
			return fmt.Errorf("test")
		default:
			app.logger.Error("test_notification called without valid header")
		}
		return c.Render(http.StatusOK, "index.html", nil)
	})
	return e
}

func extractIPFromCloudflareHeader() echo.IPExtractor {
	return func(req *http.Request) string {
		if realIP := req.Header.Get(cloudflareIPHeaderName); realIP != "" {
			return realIP
		}
		// fall back to normal ip extraction
		return echo.ExtractIPDirect()(req)
	}
}

var regexMultipleWhitespaces = regexp.MustCompile(`(?s)\n\s*\n\s*\n`)

func cleanupWhois(s string) string {
	var res strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		t := strings.TrimSpace(scanner.Text())
		// ignore comments to shorten output
		if strings.HasPrefix(t, "%") || strings.HasPrefix(t, "#") {
			continue
		}

		// remove uninteresting entries to shorten output even more
		if strings.HasPrefix(t, "admin-c:") {
			continue
		}
		if strings.HasPrefix(t, "tech-c:") {
			continue
		}
		if strings.HasPrefix(t, "status:") {
			continue
		}
		if strings.HasPrefix(t, "mnt-by:") {
			continue
		}
		if strings.HasPrefix(t, "mnt-lower:") {
			continue
		}
		if strings.HasPrefix(t, "nic-hdl:") {
			continue
		}
		if strings.HasPrefix(t, "remarks:") {
			continue
		}
		if strings.HasPrefix(t, "origin:") {
			continue
		}
		if strings.HasPrefix(t, "Ref:") {
			continue
		}
		if strings.HasPrefix(t, "Comment:") {
			continue
		}
		if strings.HasPrefix(t, "ResourceLink:") {
			continue
		}
		if strings.HasPrefix(t, "StateProv:") {
			continue
		}
		if strings.HasPrefix(t, "ReferralServer:") {
			continue
		}
		if strings.HasPrefix(t, "geoloc:") {
			continue
		}
		// OrgTech* and OrgAbuse*
		if strings.HasPrefix(t, "OrgTech") {
			continue
		}
		if strings.HasPrefix(t, "OrgAbuse") {
			continue
		}

		t = strings.TrimSuffix(t, " # Filtered")
		if _, err := fmt.Fprintf(&res, "%s\n", t); err != nil {
			continue
		}
	}

	// also replace multiple linebreaks with a single one
	return strings.TrimSpace(regexMultipleWhitespaces.ReplaceAllString(res.String(), "\n"))
}

package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
	"github.com/nikoksr/notify"
	"github.com/nikoksr/notify/service/discord"
	"github.com/nikoksr/notify/service/mail"
	"github.com/nikoksr/notify/service/msteams"
	"github.com/nikoksr/notify/service/sendgrid"
	"github.com/nikoksr/notify/service/telegram"

	_ "go.uber.org/automaxprocs"
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
func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, _ echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func customHTTPErrorHandler(err error, c echo.Context) {
	if c.Response().Committed {
		return
	}

	code := http.StatusInternalServerError
	var echoError *echo.HTTPError
	if errors.As(err, &echoError) {
		code = echoError.Code
	}
	c.Logger().Error(err)

	errorPage := fmt.Sprintf("error_pages/HTTP%d.html", code)
	content, err := errorPageAssets.ReadFile(errorPage)
	if err != nil {
		c.Logger().Error(err)
		return
	}
	if err := c.HTMLBlob(code, content); err != nil {
		c.Logger().Error(err)
		return
	}
}

func main() {
	var debugMode bool
	var configFile string
	flag.StringVar(&configFile, "c", "", "config file to use")
	flag.BoolVar(&debugMode, "debug", false, "enable debug logging")
	flag.Parse()

	w := os.Stdout
	var level = new(slog.LevelVar)
	level.Set(slog.LevelInfo)
	options := &tint.Options{
		Level:   level,
		NoColor: !isatty.IsTerminal(w.Fd()),
	}

	if debugMode {
		level.Set(slog.LevelDebug)
		// add source file information
		wd, err := os.Getwd()
		if err != nil {
			panic("unable to determine working directory")
		}

		replacer := func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				source := a.Value.Any().(*slog.Source)
				// remove current working directory and only leave the relative path to the program
				if file, ok := strings.CutPrefix(source.File, wd); ok {
					source.File = file
				}
			}
			return a
		}
		options.ReplaceAttr = replacer
		options.AddSource = true
	}

	logger := slog.New(tint.NewHandler(w, options))
	if err := run(logger, configFile, debugMode); err != nil {
		trace := string(debug.Stack())
		logger.Error(err.Error(), "trace", trace)
		os.Exit(1)
	}
}

func run(logger *slog.Logger, configFile string, debugMode bool) error {
	app := &application{
		logger: logger,
	}

	if configFile == "" {
		return fmt.Errorf("please provide a config file")
	}

	config, err := GetConfig(configFile)
	if err != nil {
		return err
	}
	app.config = config
	app.debug = debugMode

	app.notify = notify.New()
	var services []notify.Notifier

	if config.Notifications.Telegram.APIToken != "" {
		app.logger.Info("Notifications: using telegram")
		telegramService, err := telegram.New(config.Notifications.Telegram.APIToken)
		if err != nil {
			return fmt.Errorf("telegram setup: %w", err)
		}
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

	if config.Notifications.SendGrid.APIKey != "" {
		app.logger.Info("Notifications: using sendgrid")
		sendGridService := sendgrid.New(
			config.Notifications.SendGrid.APIKey,
			config.Notifications.SendGrid.SenderAddress,
			config.Notifications.SendGrid.SenderName,
		)
		sendGridService.AddReceivers(config.Notifications.SendGrid.Recipients...)
		services = append(services, sendGridService)
	}

	if config.Notifications.MSTeams.Webhooks != nil && len(config.Notifications.MSTeams.Webhooks) > 0 {
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

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			app.logger.Error(err.Error(), "trace", string(debug.Stack()))
		}
	}()

	c := make(chan os.Signal, 1)
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

func (app *application) handleLogin(c echo.Context, username, password string) error {
	app.logger.Info("Trap activated!", "user", username, "password", password)
	_, err := c.Cookie(cookieName)
	if err != nil {
		// if we have no valid cookie set, send a notification and set the cookie so we only notify once
		if errors.Is(err, http.ErrNoCookie) {
			app.logger.Debug("sending notification")
			app.notificationChannel <- notification{
				subject: fmt.Sprintf("🔥 Login on %s detected", c.Request().Host),
				message: fmt.Sprintf("Username: %s\nPassword: %s\nIP: %s", username, password, c.RealIP()),
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

func (app *application) routes() http.Handler {
	e := echo.New()
	e.HideBanner = true
	e.Debug = app.debug

	if app.config.Cloudflare {
		e.IPExtractor = extractIPFromCloudflareHeader()
	}

	e.Renderer = &TemplateRenderer{
		templates: template.Must(template.New("").Funcs(template.FuncMap{"StringsJoin": strings.Join}).ParseGlob(path.Join(app.config.Template.Folder, "*"))),
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
		LogError:         true,
		HandleError:      true, // forwards error to the global error handler, so it can decide appropriate status code
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			if v.Error == nil {
				app.logger.LogAttrs(context.Background(), slog.LevelInfo, "REQUEST",
					slog.String("ip", v.RemoteIP),
					slog.String("method", v.Method),
					slog.String("uri", v.URI),
					slog.Int("status", v.Status),
					slog.String("user-agent", v.UserAgent),
					slog.Duration("latency", v.Latency),
					slog.String("content-length", v.ContentLength),
					slog.Int64("response-size", v.ResponseSize),
				)
			} else {
				app.logger.LogAttrs(context.Background(), slog.LevelError, "REQUEST_ERROR",
					slog.String("ip", v.RemoteIP),
					slog.String("method", v.Method),
					slog.String("uri", v.URI),
					slog.Int("status", v.Status),
					slog.String("user-agent", v.UserAgent),
					slog.Duration("latency", v.Latency),
					slog.String("content-length", v.ContentLength),
					slog.Int64("response-size", v.ResponseSize),
					slog.String("err", v.Error.Error()),
				)
			}
			return nil
		},
	}))
	e.Use(middleware.Secure())

	if app.config.Method == "basic" {
		e.Use(middleware.BasicAuthWithConfig(middleware.BasicAuthConfig{
			Realm: app.config.Basic.Realm,
			Validator: func(username string, password string, context echo.Context) (bool, error) {
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
		e.GET("/", func(c echo.Context) error {
			// show the finish template here as we use the basic auth middleware
			return c.Render(http.StatusOK, app.config.Template.FinishTemplate, nil)
		})
	case "post":
		e.GET("/", func(c echo.Context) error {
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
		e.POST("/login", func(c echo.Context) error {
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

	e.GET("/test_notifications", func(c echo.Context) error {
		headerValue := c.Request().Header.Get(secretKeyHeaderName)
		if headerValue == "" {
			app.logger.Error("test_notification called without secret header")
		} else if headerValue == app.config.Notifications.SecretKeyHeader {
			app.logError(fmt.Errorf("test"))
		} else {
			app.logger.Error("test_notification called without valid header")
		}
		return c.Render(http.StatusOK, "index.html", nil)
	})
	return e
}

func (app *application) logError(err error) {
	app.logger.Error(err.Error(), "trace", string(debug.Stack()))
	if err2 := app.notify.Send(context.Background(), "[ERROR]", err.Error()); err2 != nil {
		app.logger.Error(err2.Error(), "trace", string(debug.Stack()))
	}
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

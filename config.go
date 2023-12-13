package main

import (
	"fmt"
	"time"

	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
)

type Configuration struct {
	Server        ConfigServer       `koanf:"server"`
	Notifications ConfigNotification `koanf:"notifications"`
	Timeout       time.Duration      `koanf:"timeout"`
	Cloudflare    bool               `koanf:"cloudflare"`
	Method        string             `koanf:"method"`
	Basic         ConfigBasic        `koanf:"basic"`
	Template      ConfigTemplate     `koanf:"template"`
}

type ConfigBasic struct {
	Realm string `koanf:"realm"`
}

type ConfigTemplate struct {
	Folder         string `koanf:"folder"`
	IndexTemplate  string `koanf:"index_template"`
	FinishTemplate string `koanf:"finish_template"`
	AssetFolder    string `koanf:"asset_folder"`
}

type ConfigServer struct {
	Listen          string        `koanf:"listen"`
	Port            int           `koanf:"port"`
	GracefulTimeout time.Duration `koanf:"graceful_timeout"`
}

type ConfigNotification struct {
	SecretKeyHeader string                     `koanf:"secret_key_header"`
	Telegram        ConfigNotificationTelegram `koanf:"telegram"`
	Discord         ConfigNotificationDiscord  `koanf:"discord"`
	Email           ConfigNotificationEmail    `koanf:"email"`
	SendGrid        ConfigNotificationSendGrid `koanf:"sendgrid"`
	MSTeams         ConfigNotificationMSTeams  `koanf:"msteams"`
}

type ConfigNotificationTelegram struct {
	APIToken string  `koanf:"api_token"`
	ChatIDs  []int64 `koanf:"chat_ids"`
}
type ConfigNotificationDiscord struct {
	BotToken   string   `koanf:"bot_token"`
	OAuthToken string   `koanf:"oauth_token"`
	ChannelIDs []string `koanf:"channel_ids"`
}

type ConfigNotificationEmail struct {
	Sender     string   `koanf:"sender"`
	Server     string   `koanf:"server"`
	Port       int      `koanf:"port"`
	Username   string   `koanf:"username"`
	Password   string   `koanf:"password"`
	Recipients []string `koanf:"recipients"`
}

type ConfigNotificationSendGrid struct {
	APIKey        string   `koanf:"api_key"`
	SenderAddress string   `koanf:"sender_address"`
	SenderName    string   `koanf:"sender_name"`
	Recipients    []string `koanf:"recipients"`
}

type ConfigNotificationMSTeams struct {
	Webhooks []string `koanf:"webhooks"`
}

var defaultConfig = Configuration{
	Server: ConfigServer{
		Port:            8000,
		GracefulTimeout: 10 * time.Second,
	},
	Method: "basic",
	Basic: ConfigBasic{
		Realm: "restricted",
	},
	Timeout:    5 * time.Second,
	Cloudflare: false,
}

func GetConfig(f string) (Configuration, error) {
	var k = koanf.NewWithConf(koanf.Conf{
		Delim: ".",
	})

	if err := k.Load(structs.Provider(defaultConfig, "koanf"), nil); err != nil {
		return Configuration{}, err
	}

	if err := k.Load(file.Provider(f), json.Parser()); err != nil {
		return Configuration{}, err
	}

	var config Configuration
	if err := k.Unmarshal("", &config); err != nil {
		return Configuration{}, err
	}

	// check some stuff
	if config.Server.Port == 0 {
		return Configuration{}, fmt.Errorf("please supply a port to listen on")
	}

	if config.Template.Folder == "" {
		return Configuration{}, fmt.Errorf("please provide a template folder path")
	}
	if config.Template.IndexTemplate == "" {
		return Configuration{}, fmt.Errorf("please provide a index template")
	}
	if config.Template.FinishTemplate == "" {
		return Configuration{}, fmt.Errorf("please provide a finish template")
	}
	if config.Template.AssetFolder == "" {
		return Configuration{}, fmt.Errorf("please provide a asset folder")
	}

	switch config.Method {
	case "basic":
		if config.Basic.Realm == "" {
			return Configuration{}, fmt.Errorf("please provide a basic auth realm")
		}
	case "post":
		// no checks here
	default:
		return Configuration{}, fmt.Errorf("invalid config method %s", config.Method)
	}

	return config, nil
}

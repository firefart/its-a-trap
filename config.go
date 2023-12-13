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
	Cache         ConfigCache        `koanf:"cache"`
	Notifications ConfigNotification `koanf:"notifications"`
	Timeout       time.Duration      `koanf:"timeout"`
	Cloudflare    bool               `koanf:"cloudflare"`
}

type ConfigServer struct {
	Port            int           `koanf:"port"`
	GracefulTimeout time.Duration `koanf:"graceful_timeout"`
}

type ConfigCache struct {
	Enabled bool          `koanf:"enabled"`
	Timeout time.Duration `koanf:"timeout"`
}

type ConfigNotification struct {
	SecretKeyHeader string                     `koanf:"secret_key_header"`
	Telegram        ConfigNotificationTelegram `koanf:"telegram"`
	Discord         ConfigNotificationDiscord  `koanf:"discord"`
	Email           ConfigNotificationEmail    `koanf:"email"`
	SendGrid        ConfigNotificationSendGrid `koanf:"sendgrid"`
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

var defaultConfig = Configuration{
	Server: ConfigServer{
		Port:            8000,
		GracefulTimeout: 10 * time.Second,
	},
	Cache: ConfigCache{
		Enabled: true,
		Timeout: 1 * time.Hour,
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

	return config, nil
}

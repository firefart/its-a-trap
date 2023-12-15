# its-a-trap

Simple golang webserver that listens for basic auth or post requests and sends a notification when a user enters a password.

You need to add your custom templates and post the `username` and `password` parameter to `/login` when using the post mode.

## Folder Layout

```text
its-a-trap/custom
├── assets
│   └── styles.css
└── templates
    ├── finish.html
    └── index.html
```

This will serve `index.html` and show `finish.html` upon sending a post request. You can use the `asset_folder` to store your custom assets needed for the templates. In basic auth mode only `finish.html` is shown.

## basic auth example

```json
{
  "server": {
    "listen": "127.0.0.1",
    "port": 8000
  },
  "method": "basic",
  "cloudflare": false,
  "timeout": "5s",
  "basic": {
    "realm": "restricted",
  },
  "template": {
    "folder": "./custom/templates",
    "index_template": "index.html",
    "finish_template": "finish.html",
    "asset_folder": "./custom/assets"
  }
}
```

## post example

```json
{
  "server": {
    "listen": "127.0.0.1",
    "port": 8000
  },
  "method": "post",
  "cloudflare": false,
  "timeout": "5s",
  "template": {
    "folder": "./custom/templates",
    "index_template": "index.html",
    "finish_template": "finish.html",
    "asset_folder": "./custom/assets"
  }
}
```

In POST mode you have access to the following variables inside the template:

- `{{ .LoginURL }}` - The URL to post to
- `{{ .UsernameParameter }}` - the username parameter name
- `{{ .PasswordParameter }}` - the password parameter name

Example:

```html
<form action="{{ .LoginURL }}" method="post">
  <label for="fname">Username:</label>
  <input type="text" id="fname" name="{{ .UsernameParameter }}"><br><br>
  <label for="fpass">Password:</label>
  <input type="password" id="fpass" name="{{ .PasswordParameter }}"><br><br>
  <input type="submit" value="Submit">
</form>
```
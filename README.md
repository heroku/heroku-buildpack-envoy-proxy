# envoy-buildpack-envoy-proxy

This is currently a proof of concept on using envoy proxy
as a heroku router.

## requirements

1. a private space app with spaces-router-bypass enabled.
2. `APP_ID` configured to point to the app's UUID. This may
   change in the future to not require it.

## setup using go-getting-started

```bash
heroku apps:create --space some-space -a some-app
heroku buildpacks:add https://github.com/heroku/heroku-buildpack-envoy-proxy
heroku buildpacks:add heroku/go
heroku sudo labs:enable spaces-router-bypass

cd path/to/go-getting-started
git push git@heroku.com:some-app.git master
```

## current supported heroku features

1. ACM - integrates such that you can `heroku certs:auto:enable` your app
   and still get the cert working with the envoy proxy.
2. http availability - responds to probes to the availability prober.

## future roadmap

1. tracing
2. metrics
3. logs

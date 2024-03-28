# Dashboards service proxy

## Creating UAA client

```shell
uaac client add dashboard-service-proxy \
   --authorized_grant_types authorization_code,refresh_token \
   --scope "openid,cloud_controller_service_permissions.read" \
   -s "<client-secret>" \
   --redirect_uri http://localhost:3000/auth/cloudfoundry/callback
```

# Traefik OIDC Auth

A minimal auth server implementing [Traefik](https://traefik.io/traefik/)'s [Forward Auth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) protocol.

It uses [OpenId connect](https://openid.net/developers/discover-openid-and-openid-connect/) to resolve the auth request.

# Why?

For most use cases, I would recommend you to use [Traefik Forward Auth](https://github.com/thomseddon/traefik-forward-auth) instead.

However, that project has two limitations:
- it can only filter the users based on email/domain
- it only passes on the email field as `X-Forward-User`

Normally, I would've tried to get those features added to the upstream project but since this [pull request](https://github.com/thomseddon/traefik-forward-auth/pull/100) has been "in progress" since 2020 I decided to write my own instead.

# Usage

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: traefik-oidc-auth
  labels:
    app: traefik-oidc-auth
spec:
  selector:
    matchLabels:
      app: traefik-oidc-auth
  template:
    metadata:
      labels:
        app: traefik-oidc-auth
    spec:
      containers:
      - image: zumoshi/traffic-oidc-auth
        name: traefik-oidc-auth
        ports:
        - containerPort: 6432
          protocol: TCP
        env:
          - name: OIDC_CLIENT_ID
            value: your-client-id
          - name: OIDC_CLIENT_SECRET
            value: your-client-secret
          - name: OIDC_ISSUER_URL
            value: https://auth.example.com
---
apiVersion: v1
kind: Service
metadata:
  name: traefik-oidc-auth
  labels:
    app: traefik-oidc-auth
spec:
  type: ClusterIP
  selector:
    app: traefik-oidc-auth
  ports:
    - name: auth-http
      port: 6432
      targetPort: 6432
---
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: traefik-oidc-auth
spec:
  forwardAuth:
    address: http://traefik-oidc-auth.default.svc.cluster.local:6432
    trustForwardHeader: true
    authResponseHeaders:
      - Authorization
---
# Your app's ingress:
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: my-app
spec:
  entryPoints:
    - web
  routes:
    - match: Host(`myapp.com`)
      kind: Rule
      services:
        - name: my-app-service
          port: 80
      middlewares:
        - name: traefik-oidc-auth
```


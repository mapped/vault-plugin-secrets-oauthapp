package provider

import (
	"context"
	"net/url"
	"strings"

	gooidc "github.com/coreos/go-oidc"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/oauth2ext/devicecode"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/oauth2ext/semerr"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/bitbucket"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/gitlab"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
	"golang.org/x/oauth2/slack"
)

func init() {
	GlobalRegistry.MustRegister("bitbucket", BasicFactory(Endpoint{Endpoint: bitbucket.Endpoint}))
	GlobalRegistry.MustRegister("github", BasicFactory(Endpoint{
		Endpoint:  github.Endpoint,
		DeviceURL: "https://github.com/login/device/code", // https://docs.github.com/en/developers/apps/authorizing-oauth-apps#device-flow
	}))
	GlobalRegistry.MustRegister("gitlab", BasicFactory(Endpoint{Endpoint: gitlab.Endpoint}))
	GlobalRegistry.MustRegister("google", BasicFactory(Endpoint{
		Endpoint:  google.Endpoint,
		DeviceURL: "https://oauth2.googleapis.com/device/code", // https://developers.google.com/identity/protocols/oauth2/limited-input-device#step-1:-request-device-and-user-codes
	}))
	GlobalRegistry.MustRegister("microsoft_azure_ad", AzureADFactory)
	GlobalRegistry.MustRegister("slack", BasicFactory(Endpoint{Endpoint: slack.Endpoint}))

	GlobalRegistry.MustRegister("custom", CustomFactory)
}

type endpointOverride = func(endpoint *Endpoint, queryTimeProviderOptions map[string]string)

type basicOperations struct {
	endpoint         Endpoint
	endpointOverride endpointOverride
	clientID         string
	clientSecret     string
}

func (bo *basicOperations) getEndpoint(queryTimeProviderOptions map[string]string) Endpoint {
	endpoint := bo.endpoint
	if bo.endpointOverride != nil {
		bo.endpointOverride(&endpoint, queryTimeProviderOptions)
	}

	return endpoint
}

func (bo *basicOperations) AuthCodeURL(state string, opts ...AuthCodeURLOption) (string, bool) {
	if bo.endpoint.AuthURL == "" {
		return "", false
	}

	o := &AuthCodeURLOptions{}
	o.ApplyOptions(opts)

	endpoint := bo.getEndpoint(o.ProviderOptions)

	cfg := &oauth2.Config{
		Endpoint:    endpoint.Endpoint,
		ClientID:    bo.clientID,
		Scopes:      o.Scopes,
		RedirectURL: o.RedirectURL,
	}

	return cfg.AuthCodeURL(state, o.AuthCodeOptions...), true
}

func (bo *basicOperations) DeviceCodeAuth(ctx context.Context, opts ...DeviceCodeAuthOption) (*devicecode.Auth, bool, error) {
	if bo.endpoint.DeviceURL == "" {
		return nil, false, nil
	}

	o := &DeviceCodeAuthOptions{}
	o.ApplyOptions(opts)

	endpoint := bo.getEndpoint(o.ProviderOptions)

	cfg := &devicecode.Config{
		Config: &oauth2.Config{
			Endpoint: endpoint.Endpoint,
			ClientID: bo.clientID,
			Scopes:   o.Scopes,
		},
		DeviceURL: endpoint.DeviceURL,
	}

	auth, err := cfg.DeviceCodeAuth(ctx)
	return auth, err == nil, semerr.Map(err)
}

func (bo *basicOperations) DeviceCodeExchange(ctx context.Context, deviceCode string, opts ...DeviceCodeExchangeOption) (*Token, error) {
	o := &DeviceCodeExchangeOptions{}
	o.ApplyOptions(opts)

	endpoint := bo.getEndpoint(o.ProviderOptions)

	cfg := &devicecode.Config{
		Config: &oauth2.Config{
			Endpoint: endpoint.Endpoint,
			ClientID: bo.clientID,
		},
		DeviceURL: endpoint.DeviceURL,
	}

	tok, err := cfg.DeviceCodeExchange(ctx, deviceCode)
	if err != nil {
		err = semerr.Map(err)
		err = errmark.MarkUserIf(
			err,
			errmark.RuleAny(
				semerr.RuleCode("access_denied"),
				semerr.RuleCode("expired_token"),
			),
		)

		return nil, err
	}

	return &Token{Token: tok}, nil
}

func (bo *basicOperations) AuthCodeExchange(ctx context.Context, code string, opts ...AuthCodeExchangeOption) (*Token, error) {
	o := &AuthCodeExchangeOptions{}
	o.ApplyOptions(opts)

	endpoint := bo.getEndpoint(o.ProviderOptions)

	cfg := &oauth2.Config{
		Endpoint:     endpoint.Endpoint,
		ClientID:     bo.clientID,
		ClientSecret: bo.clientSecret,
		RedirectURL:  o.RedirectURL,
	}

	tok, err := cfg.Exchange(ctx, code, o.AuthCodeOptions...)
	if err != nil {
		return nil, semerr.Map(err)
	}

	return &Token{Token: tok}, nil
}

func (bo *basicOperations) RefreshToken(ctx context.Context, t *Token, opts ...RefreshTokenOption) (*Token, error) {
	o := &RefreshTokenOptions{}
	o.ApplyOptions(opts)

	endpoint := bo.getEndpoint(o.ProviderOptions)

	cfg := &oauth2.Config{
		Endpoint:     endpoint.Endpoint,
		ClientID:     bo.clientID,
		ClientSecret: bo.clientSecret,
	}

	tok, err := cfg.TokenSource(ctx, &oauth2.Token{
		RefreshToken: t.RefreshToken,
	}).Token()
	if err != nil {
		return nil, semerr.Map(err)
	}

	return &Token{Token: tok}, nil
}

func (bo *basicOperations) ClientCredentials(ctx context.Context, opts ...ClientCredentialsOption) (*Token, error) {
	o := &ClientCredentialsOptions{}
	o.ApplyOptions(opts)

	endpoint := bo.getEndpoint(o.ProviderOptions)

	cc := &clientcredentials.Config{
		ClientID:       bo.clientID,
		ClientSecret:   bo.clientSecret,
		TokenURL:       endpoint.TokenURL,
		AuthStyle:      endpoint.AuthStyle,
		Scopes:         o.Scopes,
		EndpointParams: o.EndpointParams,
	}

	tok, err := cc.Token(ctx)
	if err != nil {
		return nil, semerr.Map(err)
	}

	return &Token{Token: tok}, nil
}

type basic struct {
	vsn              int
	endpoint         Endpoint
	endpointOverride endpointOverride
}

func (b *basic) Version() int {
	return b.vsn
}

func (b *basic) Public(clientID string) PublicOperations {
	return b.Private(clientID, "")
}

func (b *basic) Private(clientID, clientSecret string) PrivateOperations {
	return &basicOperations{
		endpoint:         b.endpoint,
		endpointOverride: b.endpointOverride,
		clientID:         clientID,
		clientSecret:     clientSecret,
	}
}

func BasicFactory(endpoint Endpoint) FactoryFunc {
	return func(ctx context.Context, vsn int, opts map[string]string) (Provider, error) {
		vsn = selectVersion(vsn, 1)

		switch vsn {
		case 1:
		default:
			return nil, ErrNoProviderWithVersion
		}

		if len(opts) != 0 {
			return nil, ErrNoOptions
		}

		p := &basic{
			vsn:      vsn,
			endpoint: endpoint,
		}
		return p, nil
	}
}

func AzureADFactory(ctx context.Context, vsn int, opts map[string]string) (Provider, error) {
	vsn = selectVersion(vsn, 1)

	switch vsn {
	case 1:
	default:
		return nil, ErrNoProviderWithVersion
	}

	tenant := opts["tenant"]
	if tenant == "" {
		return nil, &OptionError{Option: "tenant", Message: "tenant is required"}
	}

	tenantPlaceholder := "{{tenant}}"

	p := &basic{
		vsn: 1,
		endpoint: Endpoint{
			Endpoint:  microsoft.AzureADEndpoint(tenantPlaceholder),
			DeviceURL: "https://login.microsoftonline.com/" + tenantPlaceholder + "/oauth2/v2.0/devicecode", // https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
		},
		endpointOverride: func(endpoint *Endpoint, queryTimeProviderOptions map[string]string) {
			// Multitenant app will reuse the same clientId and clientSecret for several tenants
			// during client credentilas flow
			tenantReplacement := queryTimeProviderOptions["tenant"]
			if tenantReplacement == "" {
				tenantReplacement = tenant
			}

			// Upstream function does not escape this name, so we will here.
			tenantReplacement = url.PathEscape(tenantReplacement)

			endpoint.DeviceURL = strings.Replace(endpoint.DeviceURL, tenantPlaceholder, tenantReplacement, 1)
			endpoint.TokenURL = strings.Replace(endpoint.TokenURL, tenantPlaceholder, tenantReplacement, 1)
			endpoint.AuthURL = strings.Replace(endpoint.AuthURL, tenantPlaceholder, tenantReplacement, 1)
		},
	}
	return p, nil
}

func CustomFactory(ctx context.Context, vsn int, opts map[string]string) (Provider, error) {
	vsn = selectVersion(vsn, 2)

	switch vsn {
	case 2:
	case 1:
		// discovery_url is now deprecated since we have a complete OIDC
		// provider, but will be honored for existing configurations.
		discoveryURL := opts["discovery_url"]
		if discoveryURL != "" {
			provider, err := gooidc.NewProvider(ctx, discoveryURL)
			if err != nil {
				return nil, &OptionError{Option: "discovery_url", Message: "error making new provider", Cause: err}
			}

			opts["auth_code_url"] = provider.Endpoint().AuthURL
			opts["token_url"] = provider.Endpoint().TokenURL
		}
	default:
		return nil, ErrNoProviderWithVersion
	}

	if opts["token_url"] == "" {
		return nil, &OptionError{Option: "token_url", Message: "token URL is required"}
	}

	authStyle := oauth2.AuthStyleAutoDetect
	switch opts["auth_style"] {
	case "in_header":
		authStyle = oauth2.AuthStyleInHeader
	case "in_params":
		authStyle = oauth2.AuthStyleInParams
	case "":
	default:
		return nil, &OptionError{Option: "auth_style", Message: `unknown authentication style; expected one of "in_header" or "in_params"`}
	}

	endpoint := Endpoint{
		Endpoint: oauth2.Endpoint{
			AuthURL:   opts["auth_code_url"],
			TokenURL:  opts["token_url"],
			AuthStyle: authStyle,
		},
		DeviceURL: opts["device_code_url"],
	}

	p := &basic{
		vsn:      vsn,
		endpoint: endpoint,
	}
	return p, nil
}

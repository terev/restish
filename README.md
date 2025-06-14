![Restish Logo](https://user-images.githubusercontent.com/106826/82109918-ec5b2300-96ee-11ea-9af0-8515329d5965.png)


[![Works With Restish](https://img.shields.io/badge/Works%20With-Restish-ff5f87)](https://rest.sh/) [![User Guide](https://img.shields.io/badge/Docs-Guide-5fafd7)](https://rest.sh/#/guide) [![CI](https://github.com/rest-sh/restish/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/rest-sh/restish/actions/workflows/ci.yaml) [![codecov](https://codecov.io/gh/rest-sh/restish/branch/main/graph/badge.svg)](https://codecov.io/gh/rest-sh/restish) [![Docs](https://img.shields.io/badge/godoc-reference-5fafd7)](https://pkg.go.dev/github.com/rest-sh/restish?tab=subdirectories) [![Go Report Card](https://goreportcard.com/badge/github.com/rest-sh/restish)](https://goreportcard.com/report/github.com/rest-sh/restish)

[Restish](https://rest.sh/) is a CLI for interacting with [REST](https://apisyouwonthate.com/blog/rest-and-hypermedia-in-2019)-ish HTTP APIs with some nice features built-in — like always having the latest API resources, fields, and operations available when they go live on the API without needing to install or update anything.
Check out [how Restish compares to cURL & HTTPie](https://rest.sh/#/comparison).

See the [user guide](https://rest.sh/#/guide) for how to install Restish and get started.

Features include:

- HTTP/2 ([RFC 7540](https://tools.ietf.org/html/rfc7540)) with TLS by _default_ with fallback to HTTP/1.1
- Generic head/get/post/put/patch/delete verbs like `curl` or [HTTPie](https://httpie.org/)
- Generated commands for CLI operations, e.g. `restish my-api list-users`
  - Automatically discovers API descriptions
    - [RFC 8631](https://tools.ietf.org/html/rfc8631) `service-desc` link relation
    - [RFC 5988](https://tools.ietf.org/html/rfc5988#section-6.2.2) `describedby` link relation
  - Supported formats
    - OpenAPI [3.0](https://github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.3.md) / [3.1](https://spec.openapis.org/oas/v3.1.0.html) and [JSON Schema](https://json-schema.org/)
  - Automatic configuration of API auth if advertised by the API
  - Shell command completion for Bash, Fish, Zsh, Powershell
- Automatic pagination of resource collections via [RFC 5988](https://tools.ietf.org/html/rfc5988) `prev` and `next` hypermedia links
- API endpoint-based auth built-in with support for profiles:
  - HTTP Basic
  - API key via header or query param
  - OAuth2 client credentials flow (machine-to-machine, [RFC 6749](https://tools.ietf.org/html/rfc6749))
  - OAuth2 authorization code (with PKCE [RFC 7636](https://tools.ietf.org/html/rfc7636)) flow
  - On the fly authorization through external tools for custom API signature mechanisms
- Content negotiation, decoding & unmarshalling built-in:
  - JSON ([RFC 8259](https://tools.ietf.org/html/rfc8259), <https://www.json.org/>)
  - YAML (<https://yaml.org/>)
  - CBOR ([RFC 7049](https://tools.ietf.org/html/rfc7049), <http://cbor.io/>)
  - MessagePack (<https://msgpack.org/>)
  - Amazon Ion (<http://amzn.github.io/ion-docs/>)
  - Gzip ([RFC 1952](https://tools.ietf.org/html/rfc1952)), Deflate ([RFC 1951](https://datatracker.ietf.org/doc/html/rfc1951)), and Brotli ([RFC 7932](https://tools.ietf.org/html/rfc7932)) content encoding
- Automatic retries with support for [`Retry-After`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After) and `X-Retry-In` headers when APIs are rate-limited.
- Standardized [hypermedia](https://smartbear.com/learn/api-design/what-is-hypermedia/) parsing into queryable/followable response links:
  - HTTP Link relation headers ([RFC 5988](https://tools.ietf.org/html/rfc5988#section-6.2.2))
  - [HAL](http://stateless.co/hal_specification.html)
  - [Siren](https://github.com/kevinswiber/siren)
  - [Terrifically Simple JSON](https://github.com/mpnally/Terrifically-Simple-JSON)
  - [JSON:API](https://jsonapi.org/)
- Local caching that respects [RFC 7234](https://tools.ietf.org/html/rfc7234) `Cache-Control` and `Expires` headers
- CLI [shorthand](https://github.com/danielgtaylor/openapi-cli-generator/tree/master/shorthand#cli-shorthand-syntax) for structured data input (e.g. for JSON)
- [Shorthand query](https://github.com/danielgtaylor/shorthand#querying) response filtering & projection
- Colorized prettified readable output
- Fast native zero-dependency binary

Articles:

- [A CLI for REST APIs](https://dev.to/danielgtaylor/a-cli-for-rest-apis-part-1-104b)
- [Mapping OpenAPI to the CLI](https://dev.to/danielgtaylor/mapping-openapi-to-the-cli-37pb)

This project started life as a fork of [OpenAPI CLI Generator](https://github.com/danielgtaylor/openapi-cli-generator).

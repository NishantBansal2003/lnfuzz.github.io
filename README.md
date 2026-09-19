# lnfuzz.org

The website of the lnfuzz org: security advisories, the bug list, and posts
about fuzzing the Lightning Network.

Built with [Hugo](https://gohugo.io/). The site ships no JavaScript, loads no
webfonts, and makes no third-party requests.

## Running it

```sh
./serve.sh        # http://localhost:1313, live reload, drafts visible
hugo --minify     # production build into public/
```

The only dependency is [Hugo](https://gohugo.io/). Deployment is automatic:
pushing to `master` runs `.github/workflows/deploy.yml` which builds with a
checksum-verified Hugo tarball and publishes.

## Layout

```
content/           the pages: advisories/, posts/, projects/, and the standalone ones
data/bugs.yaml     the bug list, rendered by layouts/bugs.html
data/authors.yaml  author list used by front matter
layouts/           templates
assets/css/        CSS files concatenated and fingerprinted into one request
assets/logo/       the lnfuzz mark
static/            favicons; static/images/ for page images
```

## Adding things

New post or advisory:

```sh
hugo new content posts/my-post.md
hugo new content advisories/cln-something-specific.md
```

Both are created as drafts.

New bugs go at the end of `data/bugs.yaml`.

See [CONTRIBUTING.md](CONTRIBUTING.md) before writing an advisory.

## Licensing

Site code is MIT ([LICENSE](LICENSE)). Pages and their images are CC BY 4.0,
copyright their authors ([LICENSE-CONTENT](LICENSE-CONTENT)).

# Contributing

## Embargoed material must never enter this repository

**This repository is public. Pushing a branch publishes it.** A file is readable
on GitHub from the moment it is pushed, whether or not it is merged, and whether
or not it is marked `draft`.

Advisories for embargoed vulnerabilities must be written somewhere else and only
opened as PRs once the embargo has ended.

## Findings made with smite

smite is open source. Anyone can run it, extend it, find bugs and report them
upstream without involving us or mentioning smite, and a finding made that way
belongs to whoever made it.

If you find something with it, we would like to host the advisory here once it
is safe to publish. Open a pull request. You keep your copyright and your name
goes on the page.

## Licensing, and who is named

Submitting a page publishes it under CC BY 4.0 with you named as its author. You
keep your copyright; there is no CLA. The final merger acts as editor, not as
copyright holder. See [LICENSE-CONTENT](LICENSE-CONTENT).

Add yourself to `data/authors.yaml` if you want your byline linked. An unknown
key renders as a plain name, so you do not have to.

## House style

Preferences, not hard rules:

- **ASCII in `content/` and `data/`.** ASCII source is easily greppable and
  produces readable diffs. The rendered text can still contain common special
  characters (e.g., Goldmark turns `--` into an en dash and `"` into curly
  quotes at build time).
- Org-level prose is first person plural.
- Page images go in `static/images/`, referenced root-absolute
  (`/images/foo.png`). Resize before committing.

## Adding a bug

Append to the end of `data/bugs.yaml`. The header comment documents every field
and the allowed values, and the build fails on anything outside them.

Two things you cannot copy straight off the upstream page:

- **The title should describe the bug, not the fix.** A PR is titled for the
  change it makes, so "funding: require explicit channel type in all
  negotiations" becomes "Absent `channel_type` TLV negotiates a legacy channel".
  Where an issue title already describes the defect, keep its wording.
- **`fixed` is the date the fix landed**, which is often not the date the issue
  was closed.

Entries are added when a bug is reported, not when it is fixed.

## Writing an advisory

```sh
hugo new content advisories/short-description-of-the-bug.md
```

The filename is the URL and should describe the bug; `id` is a separate citation
handle. Follow the format of existing advisories.

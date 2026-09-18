---
title: "{{ replace .File.ContentBaseName "-" " " | title }}"
# Citation handle, allocated in sequence: LNF-<year>-<4 digits>. It is not the
# URL. The filename is the URL, and it should read as a description of the bug.
id: "LNF-{{ now.Format "2006" }}-0000"
# Makes the id resolve as a URL too, so a citation carrying only the id reaches
# the page. Keep in sync with `id`; the build fails if it drifts.
aliases: ["/advisories/lnf-{{ now.Format "2006" }}-0000/"]
description: ""
date: {{ .Date }}
draft: true
# How it was found: a project name like `smite`, or a method such as
# `variant-analysis`. Omit when neither fits.
found_with: smite
# critical | high | medium | low. The headline severity: where it differs by
# implementation, this is the worst case and the body explains the difference.
severity: ""
# Always a list, even for one implementation. A single spec ambiguity often
# lands the same bug in several codebases, and each carries its own versions,
# its own upstream links, its own report date and its own CVE.
targets:
  - impl: ""          # lnd | cln | ldk | eclair
    affected: ""
    fixed_in: ""
    reported:
    upstream: ""
    fix: ""
    cve: ""
authors: []
tags: []
---

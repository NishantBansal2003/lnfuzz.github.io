---
title: "{{ replace .File.ContentBaseName "-" " " | title }}"
# One sentence. It is the meta description, the social card text, the Atom
# summary, and the line shown under the title on list pages.
description: ""
date: {{ .Date }}
draft: true
# Keys from data/authors.yaml, in the order they should be credited. An unknown
# key renders as a plain name, so a guest author needs no entry there.
authors: []
tags: []
---

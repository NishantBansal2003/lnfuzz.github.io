#!/bin/sh
# Local preview at http://localhost:1313.
#
# -D renders drafts; --navigateToChanged jumps the browser to the page you just
# saved.
exec hugo server -D --navigateToChanged "$@"

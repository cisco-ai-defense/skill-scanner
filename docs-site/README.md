# Website MDX source

This directory is the canonical MDX source for the Skill Scanner section of
the Cisco AI Defense website. The website repository fetches this directory at
build time; do not copy these pages back into that repository.

Keep the detailed Markdown documentation under `docs/` and these website pages
in sync when features, CLI flags, API fields, policies, or installation steps
change.

Pull requests that modify this directory run `scripts/validate_docs_site.py`.
After merge, the Cisco AI Defense website's scheduled deployment checks out
`skill-scanner@main`, validates these pages in the website renderer, and
publishes the refreshed static site. The sync runs daily, so documentation
changes appear within 24 hours without copying MDX between repositories.

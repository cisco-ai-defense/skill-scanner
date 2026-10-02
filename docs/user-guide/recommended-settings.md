# Recommended Settings

This guide now lives on the website, so there is one copy to keep current:

**[Recommended Settings](https://cisco-ai-defense.github.io/docs/skill-scanner/recommended-settings)**
([source in this repository](../../docs-site/recommended-settings.mdx))

It picks a setup by goal, with measured recall, false-positive rate and F1 for each preset, and
copy-paste configs for the CLI, pre-commit, GitHub Actions, Python and the REST API. Every
recommended setup runs the LLM judge: rules alone catch only about 8% of held-out malicious skills.
In short:

- **Highest F1:** `--use-llm --policy balanced`. Block at HIGH and review everything at MEDIUM+.
- **Smaller review queue, and your own skills:** `--use-llm --policy low-noise`.
- **Lowest false-positive rate:** `--use-llm --policy quiet`, blocking at HIGH. Never use `quiet`
  without the judge.
- **Nothing leaves the machine:** any of the above with the judge on a local model.

The measurements behind it are in [Measured results](../reference/measured-results.md).

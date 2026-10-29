# APAC Cyber Insight

A daily dashboard of cybersecurity signals across Asia Pacific, seen through four lenses:

1. **Compliance**: laws, regulator actions and consultations, from [apac-cyber-policy-tracker](https://github.com/djrufio21/apac-cyber-policy-tracker)
2. **Threat**: exploited vulnerabilities, incidents, research and advisories, from [cyber-threat-brief](https://github.com/djrufio21/cyber-threat-brief)
3. **Industry**: sector news for telecom, financial services, government, critical infrastructure, and cloud and AI
4. **Customer**: security, outage and data stories about the operators on your watchlist

Every run also scores 12 countries on an **Attention Index** and plots them on a regulation vs threat matrix. Click any country on the page to filter every section to it.

Live page: https://djrufio21.github.io/apac-cyber-insight/

## How it works

`build.py` runs on GitHub Actions at 7:37 AM and 5:37 PM Malaysia time. It reads the latest editions of the two sibling repos, pulls the industry and customer news, scores each country, and writes `docs/data.json`. The page in `docs/index.html` renders everything from that file. A small file per day in `docs/history/` lets the index look back 7 days and show week on week change.

## The Attention Index

For each country, the build counts unique stories naming it in each lens over the last 7 days. Each lens is scaled so the busiest country scores 1, then the four lenses are combined with these weights:

| Lens | Weight |
|---|---|
| Threat | 40% |
| Compliance | 35% |
| Industry | 15% |
| Customer | 10% |

The result runs from 0 to 100. It shows where the activity is, relative to the other countries. It is not a risk rating.

## Changing what it covers

Everything lives in `sources.yml`:

1. **countries**: the matrix countries and the headline patterns that tag a story to each one
2. **index_weights**: the four lens weights
3. **industry.sectors**: one Google News search per sector
4. **customer.watchlist**: the operators you follow, each tied to a country

Commit the change and use **Actions → Build APAC Cyber Insight → Run workflow** to rebuild straight away.

## One time setup

1. **Settings → Pages**: Source "Deploy from a branch", branch `main`, folder `/docs`
2. **Settings → Actions → General → Workflow permissions**: "Read and write permissions"
3. **Actions** tab: run the workflow once by hand

## Run it locally

```bash
pip install -r requirements.txt
python build.py
cd docs && python -m http.server 8000
```

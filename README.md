# AI Breakpoint collector

Runs once a day on GitHub Actions for Security Point Break's AI Breakpoint Report.
It reads every advisory GitHub added to its Advisory Database the previous day,
keeps those rated CVSS 8.0 or higher, flags the likely AI ones using the AI product
registry (`registry.csv`), removes duplicates, and writes `daily/<date>.json`.
A Make scenario picks up that file, has Claude confirm each candidate under
methodology v1.0, and writes the results to the AI Breakpoint Data sheet.

To collect a specific day by hand: Actions tab -> "Daily AI Breakpoint collector"
-> Run workflow -> enter the date.

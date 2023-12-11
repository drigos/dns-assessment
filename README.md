# DNS Assessment

## Project purpose

The DNS Assessment project aims to perform a DNS evaluation.

## Running the project with Poetry

To run the project with Poetry, follow the steps below:

1. Create a `.env` file at the root of the project based on `.env.example`.
2. Install project dependencies by running the command `poetry install`.
3. Activate pre-commit by running the command `poetry run pre-commit install`.
4. Run the project with the command `poetry run python dns_assessment/app.py input/domains.txt` with the necessary parameters.

Make sure you have Poetry installed in your environment before proceeding with the above steps.

## Parameters

The project accepts the following parameters:

- `file_path`: input file with the domains to be evaluated (one domain per line; accept `#` as comment)
- `--output`: output format of the results. Can be `json` or `csv`. The default is `json`

Usage example:

```bash
poetry run python dns_assessment/app.py --output csv input/domains.txt > output/domains.csv
```

## Collected information

The project collects the following information:

- `domain`: evaluated domain
- `is_subdomain`: indicates if the domain is a subdomain
- `is_authoritative`: indicates if the domain is authoritative (i.e. if it has NS records)
- `has_dnssec`: indicates if the domain has DNSSEC
- `registrar`: domain registrar
- `zone_provider`: domain zone provider
- `dmarc_record`: domain's DMARC record (e.g. `v=DMARC1; p=reject; rua=...`)
- `dmarc_policy`: domain's DMARC policy (e.g. `none`, `quarantine`, `reject`)
- `spf_record`: domain's SPF record (e.g. `v=spf1 include:spf.protection.outlook.com -all`)
- `spf_action`: domain's SPF action (e.g. `~all`, `-all`)
- `bimi_record`: domain's BIMI record (e.g. `v=BIMI1; l=https://example.com/logo.svg`)
- `bimi_location`: location of the domain's BIMI logo (e.g. `https://example.com/logo.svg`)
- `bimi_logo_valid`: indicates if the domain's BIMI logo is valid

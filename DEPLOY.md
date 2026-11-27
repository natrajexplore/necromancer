# Deploy to AWS

`template.yaml` (AWS SAM) creates:

- One Lambda (Python 3.12, 1769 MB, 28 s timeout) running `backend/api/main.py` through `mangum`.
- An API Gateway HTTP API in front of it (`GET /healthz`, `GET|POST /v1/{proxy+}`), throttled to 2 requests/s with a burst of 10.
- A private S3 bucket for the built UI, read through CloudFront origin access control.
- A CloudFront distribution. `/` is the UI. `/v1/*` and `/healthz` go to the API on the same host, so the UI needs no API URL and no CORS.
- CSP, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` on every CloudFront response.
- An AWS Budgets alarm at USD 1 per month (actual and forecasted), e-mailed to `AlertEmail`.

Nothing in the repository holds an account ID, region, key or e-mail address.

## Prerequisites

Windows PowerShell, with `aws`, `sam`, `uv`, `git` and Node on `PATH`, and the signed python.org Python 3.12 (see `tech.md`).
Configure credentials once with `aws configure` (or `aws configure sso`), and set a default region there or pass `-Region`.
Use an IAM user or role that can manage CloudFormation, Lambda, API Gateway, S3, CloudFront, IAM roles, CloudWatch Logs and Budgets.

## Deploy

```powershell
.\deploy.ps1 -AlertEmail <your-address>
```

Optional: `-StackName`, `-Region`, `-Profile`, `-Yes` (skip the change-set prompt), `-SkipTests`, `-NoCdn` (see below).

The script runs these steps and stops at the first failure:

1. Checks the credentials (`aws sts get-caller-identity`) and runs `tests/test_api.py` through `uv run python -m pytest`.
2. Copies `api/`, `necro/` and `samples/` to `build/lambda-src/` and writes `requirements.txt` from `uv.lock` (without the MCP server and uvicorn).
3. `sam build`, then `sam deploy`. You review the change set and confirm it.
4. `npm.cmd --prefix frontend run build`.
5. `aws s3 cp` and `aws s3 sync` of `frontend/dist` to the bucket, with explicit content types, then a CloudFront invalidation.

The first CloudFront deployment takes a few minutes. The script prints the UI URL and `/healthz` URL at the end.
AWS sends a confirmation e-mail for the budget alert. Confirm it, or no alerts arrive.

Check the result:

```powershell
curl.exe https://<distribution-domain>/healthz
```

It returns the version and commit.

## Fallback without CloudFront (`-NoCdn`)

A new AWS account can be blocked from creating CloudFront distributions until AWS verifies it. Use this mode meanwhile:

```powershell
.\deploy.ps1 -AlertEmail <your-address> -NoCdn
```

It sets the template parameter `EnableCdn=false`. Then:

- The UI bucket, its policy, the origin access control, the distribution and both response headers policies are **not created**.
  The budget alarm, Lambda and HTTP API are unchanged.
- The script builds the UI first and copies `frontend/dist` to `build/lambda-src/static`, which ships inside the Lambda package.
  It skips the S3 sync and the CloudFront invalidation.
- The stack sets `NECRO_STATIC_DIR=/var/task/static` and adds the routes `GET /` and `GET /{proxy+}` to the HTTP API.
  `api/static.py` serves the files after every `/v1` and `/healthz` route. Unknown GET paths return `index.html`
  (SPA fallback). A missing `/assets/*` file, an unknown `/v1/*` path and `/healthz/*` stay JSON 404s.
- The app adds the CloudFront policy headers itself on every response: CSP, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer` and `X-Frame-Options: DENY`. The UI gets the same CSP as the CloudFront UI policy; API responses get the strict one.
- `SiteUrl` and `HealthUrl` point at the HTTP API endpoint. `UiBucketName` and `DistributionId` are not output.

The UI and the API share one origin in this mode too, so the UI needs no API URL and no CORS.
Differences from the CDN mode: no edge caching, and every UI request invokes the Lambda (a cold start can add a second or two to the first page load).
The 2 requests/s API throttle also applies to UI requests, so a page load with many assets can briefly return 429.

To move to CloudFront later, deploy again without `-NoCdn`. CloudFormation creates the CDN resources and removes the static routes.
The `static` directory is no longer staged, so `NECRO_STATIC_DIR` is unset.
To try it locally, set `NECRO_STATIC_DIR` to the path of `frontend/dist` and run `uv run python -m uvicorn api.main:app` from `backend/`.

## Validate the template without AWS

```powershell
$env:AWS_DEFAULT_REGION = '<any-region>'; sam validate --lint
```

## Limits and known gaps

- **Per-IP rate limit (CDN mode).** HTTP APIs cannot throttle per client. API Gateway throttles the whole API; the 10 POSTs/minute/IP limit
  is enforced by `api/middleware.py` in each warm Lambda instance. Behind CloudFront that limiter sees CloudFront edge addresses, not
  visitors, because it reads the socket peer. Reading `X-Forwarded-For` in the backend would fix that and needs a code change.
- **Timeout.** A request that needs more than 28 s (for example a proof at a very large example budget) fails with a gateway error.
- **Direct API URL.** With CloudFront, the `ApiEndpoint` output bypasses it. It has the same throttling and the app's own security headers.
- **CSP.** The UI policy allows inline styles because the print-ready report opens as a `blob:` page that inherits it.
- **Cost.** All services used are in the free tier at demo traffic. CloudFront uses `PriceClass_100`. The budget alarm warns; it does not stop spending.

## Tear down

```powershell
aws s3 rm s3://<UiBucketName output> --recursive
sam delete --stack-name necromancer
```

The bucket must be empty before CloudFormation can delete it. `sam deploy --resolve-s3` also created a
`aws-sam-cli-managed-default` stack for build artifacts. Delete it only if no other SAM project uses it.

# Website hosting

The canonical public URL is https://sail-gpl.org/. Vercel hosts the static
presentation site from the repository's web directory. The source and toolkit
remain in GitHub. The legacy GitHub Pages workflow is manual only.

## Vercel project

- Team: Sarunas projects, slug sarunas.
- Project: sail-gpl.
- Project ID: prj_aj5Ras8sp3LKUVWynt1LIotL2TAP.
- Dashboard: https://vercel.com/sarunas/sail-gpl.
- The site has no build command, package installation or server runtime.
- web/vercel.json selects the static output directory.
- www.sail-gpl.org redirects to sail-gpl.org with HTTP 308.

GitHub integration could not be connected with the currently installed Vercel
GitHub app permissions. Deployments use the authenticated Vercel CLI. A GitHub
push alone does not currently deploy the Vercel site. To enable that later,
grant the Vercel GitHub app access to this repository, connect the project, and
set its Git root directory to web. Do not upload the repository root manually.

## Interneto vizija DNS

The domain retains its existing Interneto vizija nameservers. Do not transfer
the registration or replace the nameservers for this setup. In the IV client
panel, open the sail-gpl.org service and choose Redaguoti zoną (Edit zone).

Vercel returned the following preferred records for this project on 2026-10-24:

| Name | Type | Value |
|---|---|---|
| @ | A | 216.150.1.1 |
| @ | A | 216.150.16.1 |
| www | CNAME | 2c81ec7e2a3870f0.vercel-dns-016.com. |

Replace the old apex A value 79.98.28.26. Remove any explicit www A record
before creating the www CNAME. Keep the final dot on the CNAME value because
the IV editor otherwise appends the zone name. These values are specific to
the current Vercel project configuration, not universal deployment defaults.

Preserve mail and verification records, including MX, SPF, DKIM and DMARC.
At inspection, MX pointed to garnys.serveriai.lt and mx-backup.serveriai.lt.
Those records do not need to change for the website migration.

The project-domain ownership checks passed, so no extra ownership TXT record
was requested. DNS routing was still pending at handoff. The custom domain's
new content and HTTPS must be checked after DNS propagation. Vercel provisions
the certificate when the domain routes correctly. IV documents up to one or
two hours for a zone edit to take full effect.

Official IV guide: https://pagalba.iv.lt/lt/articles/380773-zonos-redagavimas.

## Manual deployment

Run from the repository root after tests and source changes have been committed:

```bash
cd web
vercel link --scope sarunas --project sail-gpl --yes
vercel project inspect --scope sarunas --non-interactive
vercel deploy . --scope sarunas --project sail-gpl --prod --skip-domain
vercel curl / --deployment DEPLOYMENT_URL
vercel promote DEPLOYMENT_URL --scope sarunas --yes
```

Use the actual returned deployment URL. Keep the project's existing deployment
protection. Authenticated vercel curl can test protected preview or deployment
URLs without making those URLs public. The custom production domains are the
public website addresses.

The CLI may create a local environment file during linking. Such files and
local project state are ignored by Git and excluded from deployment inputs.
Never commit, print or publish their contents.

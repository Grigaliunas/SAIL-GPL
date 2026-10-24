# Website hosting

The canonical public URL is https://sail-gpl.org/. Vercel hosts the static
presentation site from the repository's web directory. The source and toolkit
remain in GitHub. The legacy GitHub Pages workflow is manual only.

## Vercel project

- Team: Sarunas projects, slug sarunas.
- Project: sail-gpl.
- Project ID: prj_aj5Ras8sp3LKUVWynt1LIotL2TAP.
- Dashboard: https://vercel.com/sarunas/sail-gpl.
- Git repository: Grigaliunas/SAIL-GPL, connected through the Vercel GitHub app.
- Production branch: main.
- Root Directory project setting: web.
- Framework preset: Other (no framework).
- Build and install commands: empty. No server runtime is required.
- Output directory: a dot (.), relative to web.
- web/vercel.json records the static framework, command and output settings.
- Automatic custom-domain assignment is enabled for production deployments.
- www.sail-gpl.org redirects to sail-gpl.org with HTTP 308.

The native Git connection was established on 2026-10-24 after repository access
was granted to the existing Vercel GitHub app. Push committed changes to main
to trigger the project's native Vercel production deployment. Successful
production deployments are assigned to the configured custom domains
automatically. The repository's GitHub Actions CI remains a separate check;
this connection does not itself make those checks a Vercel release gate.

Root Directory is a Vercel project setting, not a rootDirectory field in
vercel.json. The static output is web, so repository documentation, toolkit
source and local-only documents are not part of the public website output.

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

The previous apex A value was 79.98.28.26. For future DNS repairs, replace
conflicting apex A values and remove any explicit www A or AAAA record before
using the www CNAME. Keep the final dot on its value because the IV editor
otherwise appends the zone name. These records are specific to this Vercel
project configuration, not universal deployment defaults.

Preserve mail and verification records, including MX, SPF, DKIM and DMARC.
At inspection, MX pointed to garnys.serveriai.lt and mx-backup.serveriai.lt.
Those records do not need to change for the website migration.

Project-domain ownership checks passed without an extra ownership TXT record.
DNS routing and HTTPS for sail-gpl.org were verified on 2026-10-24. The www
host was also verified to redirect to the HTTPS apex URL with HTTP 308.
These are dated observations, not a substitute for checking a later DNS
change. IV documents up to one or two hours for a zone edit to take full effect.

Official IV guide: https://pagalba.iv.lt/lt/articles/380773-zonos-redagavimas.

## Manual deployment fallback

Native Git deployment is the normal release path. Use this fallback only when
an intentional manual release is needed. Run from the repository root, after
tests and source changes have been committed. Do not cd into web: the remote
Root Directory setting already selects that folder for this project.

The following workflow builds locally and uploads only the generated Build
Output API artifacts. It avoids a manual upload of the full repository source.

```bash
vercel link --scope sarunas --project sail-gpl --yes
vercel project inspect --scope sarunas --non-interactive
vercel pull --scope sarunas --environment=production --yes
vercel build --prod --scope sarunas
vercel deploy --prebuilt --prod --skip-domain --scope sarunas
vercel curl / --deployment DEPLOYMENT_URL
vercel promote DEPLOYMENT_URL --scope sarunas --yes
```

Before building, confirm that project inspection identifies team sarunas,
project sail-gpl and Root Directory web. Review .vercel/output after the build
and confirm that it contains only the intended public site assets. Use the
actual URL returned by the staged production deployment for both curl and
promote. The --skip-domain flag leaves the current public production release
in place until the tested production deployment is promoted.

Keep the project's existing deployment protection. Authenticated vercel curl
can test protected deployment URLs without making them public. The custom
production domains are the public website addresses.

Linking and pulling may create local project state and download environment
configuration into .vercel/. These files are ignored by Git and are not the
prebuilt public output. Never commit, print or publish their contents.

Official Vercel references:

- Root Directory and static output: https://vercel.com/docs/builds/configure-a-build.
- Local Build Output API artifacts: https://vercel.com/docs/cli/build.
- Prebuilt deployment: https://vercel.com/docs/cli/deploy.

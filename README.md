# HELLBOY MOB BEATS

Cloudflare Pages website with an R2-backed free WAV library and private upload studio.

## Owner dashboard
Visit `/admin` after Cloudflare Access configuration. Upload a WAV (up to 90 MB), optional artwork (JPG/PNG/WebP, up to 5 MB), title, BPM, and key. Save a private draft or publish it. The dashboard also supports unpublishing.

## Public library
Published beats appear on Free Beats with audio controls and WAV downloads. Draft metadata and files are inaccessible to public visitors. Free beats allow unlimited use, commercial releases, and monetization. Custom production inquiries go to @hellboymob for Zoom consultations.

## Runtime configuration
- R2 binding `BEATS`: private bucket `hellboy-mob-beats-library`.
- `ADMIN_EMAIL`: allowed owner email.
- `ACCESS_TEAM_DOMAIN`: Cloudflare Access team hostname, without https://.
- `ACCESS_AUD`: Access application audience.
- Protect `hellboymob.com/admin*` and `hellboymob.com/api/admin*` with the same Access application. Only the owner email should be allowed. One-time PIN login is sufficient.
- Production and alternate Pages hosts independently verify Access JWT signatures, issuer, audience, expiry, and owner email. Missing configuration fails closed.
- Set Pages Functions to fail closed on usage limits.

## Deployment
Commits to main deploy through Cloudflare Pages to hellboymob.com. There is no build command; output directory is `.`. `_worker.js` is the server entrypoint; `admin.html` is served only through the authenticated `/admin` route. The original private Sites draft is separate and is not synchronized by this repository.

## Limitations
No payments; custom fees are negotiated over Zoom. Files remain in storage after unpublishing. Failed or abandoned uploads may leave unused file objects. Downloaded copies cannot be revoked by unpublishing.


## Library organization and community
- Artist filters: Future, Travis Scott, Juice WRLD, XXXTentacion, Lil Peep, and Other. Untagged existing beats appear in Other. Multiple tags are supported; edit them in `/admin`.
- Search combines with key root (enharmonic equivalents supported), Major/Minor, and inclusive BPM range. Popularity sorts by likes, then views, then newest.
- Likes and first-play views are stored in the existing BEATS R2 bucket under `community/`. One like and one view per browser identifier per beat; clearing browser storage resets that identity. These are approximate engagement counts, not verified unique people.
- Comments use nicknames without accounts. Pending comments are private until approved in `/admin`; hiding a comment is reversible. Plain text rendering, field limits, a honeypot, link rejection, origin checks, and an atomic five-minute cooldown per hashed network address reduce spam. No raw IP address is stored.
- Comment retrieval returns the latest 100 approved comments. Counts scan paginated R2 object listings, suitable for the current small catalog; migrate counters to a database before high-volume growth.
- No additional cloud bindings are required. Existing private upload authorization remains in place.

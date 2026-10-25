# Routing editor

Approved in chat: four lists for RU/EXIT domains and IPv4/CIDR, one entry per
line, manual rules before GeoIP, reject contradictions, validate before applying
and restore previous settings on failure. Keep Basic Auth, CSRF and loopback.

Approaches: a sortable rule table permits arbitrary priorities but adds complexity;
four lists fit existing rule-set files and were selected by the user.

Implementation decisions: retain the four existing JSON files; reject overlapping
RU/EXIT networks and overlapping domain patterns. Domain rules take precedence
over IP rules, allowing a named site to override its network. Cannot infer a
domain/IP conflict without DNS, so do not resolve DNS during validation.
Use a revision hash to reject stale browser saves. Validate staged files using
sing-box before writing live files; restore files/config and restart on failure.
Application briefly interrupts sessions. No VPS deployment by the agent.

Add a non-destructive update command for existing installs: preserve secrets,
profiles, rule files, state and TProxy; replace application code and restart panel.
No new third-party runtime dependencies.

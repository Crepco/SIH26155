# Frontend build checks

## assert-no-external-assets

Scans the production build output for any reference to an external host: fonts, scripts,
stylesheets, images, preconnect hints, source map URLs.

The whole system claims to run with the network cable unplugged. A single Google Fonts link in a
layout file makes that claim false in front of an evaluator, and it is the kind of thing that
arrives silently with a copied component. So it is checked in CI rather than remembered.

Fails the build on any match. Allowed hosts: none. Not a warning.

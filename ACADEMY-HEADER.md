# Hifz V5.1 — Academy banners

Requested on 17 October 2026: copy Academy’s top two banners, replace its role tabs with Hifz navigation, and omit Surahs in My Heart and Kaaba Puzzle.

The authenticated shell keeps Academy’s logo, typography, colours, date box, greeting, profile and Home/Refresh/Sign out controls. Navigation comes from the existing Hifz role rules, so students keep their personal journal tools and staff keep their authorised Maktab tools. The class Zoom action remains visible. Timer and Switch account remain available. Colouring/puzzle entries are removed from the header and Home tiles, without deleting their saved data or direct screen handlers.

The header date uses the same Jamiat source and Johannesburg day as Academy. Hifz serves and caches it independently, with bounded reads and a timeout. It never reads D1, sends credentials to the date source, or requires the Academy API to be available.

Navigation is always visible on desktop and scrolls horizontally on phones. Header height is measured so sticky journal headings stay below both banners.

Production uses `hifz.maktab4life.org` and the production Worker/D1. Development uses `hifzhelper-dev.pages.dev` with its separate Worker/D1. Both can receive an Academy sign-in pass through distinct fixed endpoints; automatic profile/PIN changes are delivered to production.

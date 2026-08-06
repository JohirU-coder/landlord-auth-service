// Frontend runtime configuration for local development (start-server.bat).
// In production this file is regenerated at container startup from environment
// variables — see server.js. Do not rely on this file's contents in prod.
//
// Points at the deployed backend rather than localhost because property-service
// and review-service aren't set up to run locally on this machine (no .env, no
// local Postgres). Switch back to localhost URLs once you have a local stack.
//
// GOOGLE_STREETVIEW_API_KEY is intentionally left blank here — this file is
// git-tracked, and the key must never be committed (rotate via Railway env
// vars only). To test Street View fallback locally, paste a key below
// temporarily and don't commit the change.
window.APP_CONFIG = window.APP_CONFIG || {
  API_BASE_URL: 'https://api.rentreviews.net',
  AUTH_API_BASE_URL: 'https://api.rentreviews.net',
  PROPERTY_API_BASE_URL: 'https://property.rentreviews.net',
  REVIEW_API_BASE_URL: 'https://review.rentreviews.net',
  GOOGLE_STREETVIEW_API_KEY: ''
};

// Frontend runtime configuration.
// For local dev this points to the deployed Railway auth service.
// During CI/CD deployment, replace the URL with your production API URL if it ever changes.
window.APP_CONFIG = window.APP_CONFIG || {
  API_BASE_URL: 'https://landlord-auth-service-production.up.railway.app'
};

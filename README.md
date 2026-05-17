# landlord-auth-service
Authentication microservice for landlord review platform

## Test and deploy

- Run the full test suite locally with `npm test`
- Run CI-style coverage locally with `npm run test:ci`
- A deployment workflow is available at `.github/workflows/deploy.yml`
- The deploy workflow generates `frontend/landlord-frontend/config.js` at deploy time from `FRONTEND_API_BASE_URL`

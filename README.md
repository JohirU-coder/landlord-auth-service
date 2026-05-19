# landlord-auth-service
Authentication microservice for landlord review platform

## Test and deploy

- Run the full test suite locally with `npm test`
- Run CI-style coverage locally with `npm run test:ci`
- A deployment workflow is available at `.github/workflows/deploy.yml`
- The deploy workflow generates `frontend/landlord-frontend/config.js` at deploy time from `FRONTEND_API_BASE_URL`

CI trigger note: This repository had a CI trigger commit created on 2026-05-18 to validate the updated workflows and tests.

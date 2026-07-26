// Address geocoding via OpenStreetMap's Nominatim (free, no API key).
// Nominatim's usage policy caps anonymous use at 1 request/second and requires
// a descriptive User-Agent, so all requests go through a single serialized
// queue rather than firing in parallel.

const NOMINATIM_URL = 'https://nominatim.openstreetmap.org/search';
const USER_AGENT = 'RentReviews/1.0 (https://github.com/JohirU-coder/landlord-property-service)';
const MIN_REQUEST_INTERVAL_MS = 1100;
const REQUEST_TIMEOUT_MS = 8000;

let queue = Promise.resolve();

function throttled(fn) {
  const run = queue.then(async () => {
    const result = await fn();
    await new Promise((resolve) => setTimeout(resolve, MIN_REQUEST_INTERVAL_MS));
    return result;
  });
  // Keep the chain alive even if this call fails, so later calls still run.
  queue = run.catch(() => {});
  return run;
}

// Returns { latitude, longitude } or null if the address couldn't be geocoded.
async function geocodeAddress(address, city, state, zip_code) {
  const query = [address, city, state, zip_code].filter(Boolean).join(', ');
  if (!query) return null;

  return throttled(async () => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const url = `${NOMINATIM_URL}?format=json&limit=1&q=${encodeURIComponent(query)}`;
      const response = await fetch(url, {
        headers: { 'User-Agent': USER_AGENT },
        signal: controller.signal
      });

      if (!response.ok) {
        console.warn(`⚠️ Geocoding failed (${response.status}) for: ${query}`);
        return null;
      }

      const results = await response.json();
      if (!Array.isArray(results) || results.length === 0) {
        console.warn(`⚠️ No geocoding match for: ${query}`);
        return null;
      }

      const latitude = parseFloat(results[0].lat);
      const longitude = parseFloat(results[0].lon);
      if (Number.isNaN(latitude) || Number.isNaN(longitude)) return null;

      return { latitude, longitude };
    } catch (error) {
      console.warn(`⚠️ Geocoding error for "${query}": ${error.message}`);
      return null;
    } finally {
      clearTimeout(timeout);
    }
  });
}

module.exports = { geocodeAddress };

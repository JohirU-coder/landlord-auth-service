// Shared session-expiry guard, included early (right after config.js, before
// any page-specific auth-check script) on every page that reads the login
// session. Auto-logout after 12 hours of inactivity -- login state itself
// lives in localStorage (shared across tabs, survives a mobile browser
// reclaiming a backgrounded tab), so it needs its own timeout or a token
// left signed in on a shared/public computer would stay valid indefinitely.
(function () {
    const TOKEN_KEY = 'rentreviews_token';
    const USER_KEY = 'rentreviews_user';
    const ACTIVITY_KEY = 'rentreviews_last_activity';
    const INACTIVITY_LIMIT_MS = 12 * 60 * 60 * 1000; // 12 hours

    const lastActivity = parseInt(localStorage.getItem(ACTIVITY_KEY) || '0', 10);
    const now = Date.now();

    if (localStorage.getItem(TOKEN_KEY) && lastActivity && (now - lastActivity > INACTIVITY_LIMIT_MS)) {
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(USER_KEY);
    }

    localStorage.setItem(ACTIVITY_KEY, String(now));

    // Keep the timestamp fresh while the tab is actually being used --
    // otherwise someone actively browsing for 12+ hours straight would get
    // logged out mid-session, which isn't the intent ("inactivity", not
    // "session age"). Passive + throttled so this doesn't run on every
    // single mousemove/scroll event.
    let lastRecorded = now;
    const recordActivity = () => {
        const t = Date.now();
        if (t - lastRecorded < 60000) return; // at most once/minute
        lastRecorded = t;
        localStorage.setItem(ACTIVITY_KEY, String(t));
    };
    ['click', 'keydown', 'scroll', 'mousemove'].forEach(evt => {
        document.addEventListener(evt, recordActivity, { passive: true });
    });
})();

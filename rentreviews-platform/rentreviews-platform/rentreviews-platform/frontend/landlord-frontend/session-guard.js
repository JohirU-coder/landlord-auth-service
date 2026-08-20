// Shared session-expiry guard, included early (right after config.js, before
// any page-specific auth-check script) on every page that reads the login
// session. Two things happen here, both before the page's own auth logic
// runs, so an expired session is already gone by the time that logic checks
// for a token -- no changes needed to each page's existing "no token ->
// redirect to login" handling.
//
// 1. Auto-logout after 12 hours of inactivity. Session storage alone doesn't
//    time out on its own -- a tab left open (or put to sleep and resumed)
//    would otherwise stay logged in indefinitely.
// 2. Nothing to do here for "closed tab/window -> logged out" specifically --
//    that's handled by auth.html and every other page storing the token in
//    sessionStorage instead of localStorage. sessionStorage is cleared when
//    its tab closes and, unlike localStorage, isn't shared with other tabs
//    of the same site -- opening a second tab starts a separate session,
//    which also means testing multiple accounts side by side in different
//    tabs no longer bleeds into each other.
(function () {
    const TOKEN_KEY = 'rentreviews_token';
    const USER_KEY = 'rentreviews_user';
    const ACTIVITY_KEY = 'rentreviews_last_activity';
    const INACTIVITY_LIMIT_MS = 12 * 60 * 60 * 1000; // 12 hours

    const lastActivity = parseInt(sessionStorage.getItem(ACTIVITY_KEY) || '0', 10);
    const now = Date.now();

    if (sessionStorage.getItem(TOKEN_KEY) && lastActivity && (now - lastActivity > INACTIVITY_LIMIT_MS)) {
        sessionStorage.removeItem(TOKEN_KEY);
        sessionStorage.removeItem(USER_KEY);
    }

    sessionStorage.setItem(ACTIVITY_KEY, String(now));

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
        sessionStorage.setItem(ACTIVITY_KEY, String(t));
    };
    ['click', 'keydown', 'scroll', 'mousemove'].forEach(evt => {
        document.addEventListener(evt, recordActivity, { passive: true });
    });
})();
